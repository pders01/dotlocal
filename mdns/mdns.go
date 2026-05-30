// Package mdns advertises a service on the local network over multicast DNS,
// so it is reachable at a stable <name>.local address without DNS, a hosts
// entry, or a static IP. It is a thin wrapper over hashicorp/mdns.
//
// mDNS is link-local: it only works on the same LAN segment, and the
// advertised A records point at the host's LAN interface addresses, not
// loopback. On a multi-homed host, Advertise runs one responder per interface
// (bound to that interface), so a query is answered with the address reachable
// on the subnet it arrived from — <name>.local then resolves correctly on
// every LAN the host is on, rather than handing a client an address on a
// subnet it cannot route to.
package mdns

import (
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/hashicorp/mdns"
)

// Options tunes advertising. The zero value is valid.
type Options struct {
	// Info is the TXT record text. Defaults to "<name> (dotlocal)".
	Info string
	// Interfaces, if non-empty, restricts advertising to exactly these
	// interface names (bypassing the virtual/tunnel filter). Empty means every
	// LAN-candidate interface (see isLANCandidate).
	Interfaces []string
}

func (o Options) info(name string) string {
	if o.Info != "" {
		return o.Info
	}
	return name + " (dotlocal)"
}

// Advertiser publishes an mDNS A record for <name>.local plus an _http._tcp
// service record on a port, until Close is called. It may run more than one
// underlying responder (one per interface).
type Advertiser struct {
	servers []*mdns.Server
	// Host is the resolved fully-qualified name, e.g. "fwrd.local.".
	Host string
	// Targets lists the advertised addresses (e.g. "en0=192.168.1.5") for
	// logging.
	Targets []string
}

// Advertise runs one responder per usable interface, each bound to its
// interface and advertising only that interface's IPv4 address(es), so
// <name>.local resolves to the reachable address on whichever LAN a client
// sits on. name is the bare label (e.g. "fwrd"); the advertised name is
// "<name>.local".
//
// It coexists with the OS responder (Bonjour/Avahi): the multicast socket sets
// SO_REUSEADDR, and the two answer for different names.
func Advertise(name string, port int, opts Options) (*Advertiser, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerating interfaces: %w", err)
	}
	host := name + ".local."
	adv := &Advertiser{Host: host}
	for i := range ifaces {
		ifi := ifaces[i]
		if len(opts.Interfaces) > 0 {
			if !slices.Contains(opts.Interfaces, ifi.Name) {
				continue
			}
		} else if !isLANCandidate(&ifi) {
			continue
		}
		ips := ifaceIPv4s(&ifi)
		if len(ips) == 0 {
			continue
		}
		if err := adv.addResponder(name, host, port, opts.info(name), ips, &ifi); err != nil {
			_ = adv.Close()
			return nil, err
		}
	}
	if len(adv.servers) == 0 {
		if len(opts.Interfaces) > 0 {
			return nil, fmt.Errorf("none of the requested interfaces %v are up with an IPv4 address", opts.Interfaces)
		}
		return nil, fmt.Errorf("no up, non-loopback IPv4 interface to advertise on")
	}
	return adv, nil
}

// AdvertiseScoped advertises each given IP on the interface whose subnet
// contains it, one scoped responder per interface. Use it to publish dedicated
// alias IPs (e.g. from a port-80 redirect), so on a multi-homed host
// <name>.local resolves to the alias reachable on whichever LAN a client is on.
func AdvertiseScoped(name string, port int, ips []net.IP, opts Options) (*Advertiser, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerating interfaces: %w", err)
	}
	byIface := map[string][]net.IP{}
	var order []string
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		ifn := ifaceForIP(ifaces, ip4)
		if ifn == "" {
			return nil, fmt.Errorf("no active interface has a subnet containing %s", ip4)
		}
		if _, ok := byIface[ifn]; !ok {
			order = append(order, ifn)
		}
		byIface[ifn] = append(byIface[ifn], ip4)
	}
	if len(byIface) == 0 {
		return nil, fmt.Errorf("no usable IPv4 address to advertise on")
	}
	host := name + ".local."
	adv := &Advertiser{Host: host}
	for _, ifn := range order {
		ifi, err := net.InterfaceByName(ifn)
		if err != nil {
			_ = adv.Close()
			return nil, fmt.Errorf("looking up interface %s: %w", ifn, err)
		}
		if err := adv.addResponder(name, host, port, opts.info(name), byIface[ifn], ifi); err != nil {
			_ = adv.Close()
			return nil, err
		}
	}
	return adv, nil
}

func (a *Advertiser) addResponder(name, host string, port int, info string, ips []net.IP, ifi *net.Interface) error {
	svc, err := mdns.NewMDNSService(name, "_http._tcp", "local.", host, port, ips, []string{info})
	if err != nil {
		return fmt.Errorf("building mDNS service for %s: %w", ifi.Name, err)
	}
	srv, err := mdns.NewServer(&mdns.Config{Zone: svc, Iface: ifi})
	if err != nil {
		return fmt.Errorf("starting mDNS responder on %s: %w", ifi.Name, err)
	}
	a.servers = append(a.servers, srv)
	for _, ip := range ips {
		a.Targets = append(a.Targets, ifi.Name+"="+ip.String())
	}
	return nil
}

// Close stops every underlying responder. Safe to call on a nil Advertiser.
func (a *Advertiser) Close() error {
	if a == nil {
		return nil
	}
	var firstErr error
	for _, s := range a.servers {
		if s == nil {
			continue
		}
		if err := s.Shutdown(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// virtualPrefixes are interface-name prefixes for tunnels, VM/container
// bridges, and Apple internal links that are not real LANs we want to publish
// <name>.local on. An explicit Options.Interfaces list bypasses this.
var virtualPrefixes = []string{
	"awdl", "llw", "utun", "gif", "stf", "anpi", "ap", // darwin internal / tunnels
	"bridge", "vmnet", "vnic", // darwin VM bridges
	"docker", "veth", "virbr", "br-", "vnet", "wg", "tailscale", // linux container/VPN
}

// isLANCandidate reports whether an interface should be auto-advertised on:
// up, multicast-capable, not loopback or point-to-point, and not a known
// virtual/tunnel device.
func isLANCandidate(ifi *net.Interface) bool {
	if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
		return false
	}
	if ifi.Flags&net.FlagPointToPoint != 0 || ifi.Flags&net.FlagMulticast == 0 {
		return false
	}
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(ifi.Name, p) {
			return false
		}
	}
	return true
}

// ifaceForIP returns the name of the up, non-loopback interface whose subnet
// contains ip, or "" if none does.
func ifaceForIP(ifaces []net.Interface, ip net.IP) string {
	for i := range ifaces {
		ifi := ifaces[i]
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.Contains(ip) {
				return ifi.Name
			}
		}
	}
	return ""
}

// ifaceIPv4s returns the global-unicast IPv4 addresses of a single interface.
// mDNS is link-local, so we stay IPv4-only to avoid publishing link-local
// IPv6 (fe80::) records that many clients can't route to without a scope id.
func ifaceIPv4s(ifi *net.Interface) []net.IP {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil
	}
	var ips []net.IP
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil || !ip4.IsGlobalUnicast() {
			continue
		}
		ips = append(ips, ip4)
	}
	return ips
}
