// Package mdns advertises a service on the local network over multicast DNS,
// so it is reachable at a stable <name>.local address without DNS, a hosts
// entry, or a static IP.
//
// The responder backend is platform-specific (see startResponder):
//
//   - Linux/other: a self-hosted responder (hashicorp/mdns), one per
//     interface, which coexists with Avahi over the shared multicast socket.
//   - macOS: the system mDNSResponder (Bonjour) is driven via `dns-sd`,
//     because a second self-hosted responder on the box does not interoperate
//     with Bonjour — its records never become resolvable.
//
// On a multi-homed host, advertising is scoped per interface so <name>.local
// resolves to the address reachable on whichever LAN a client sits on.
package mdns

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/pders01/dotlocal/internal/lan"
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

// Advertiser publishes <name>.local until Close is called. It may own several
// underlying responders/registrations (one per interface).
type Advertiser struct {
	// Host is the resolved fully-qualified name, e.g. "fwrd.local.".
	Host string
	// Targets lists the advertised addresses (e.g. "en0=192.168.1.5") for
	// logging.
	Targets []string
	closers []func() error
}

// Advertise advertises <name>.local on every LAN-candidate interface (or the
// ones named in opts.Interfaces), scoped per interface.
func Advertise(name string, port int, opts Options) (*Advertiser, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerating interfaces: %w", err)
	}
	byIface := map[string][]net.IP{}
	var order []string
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
		byIface[ifi.Name] = ips
		order = append(order, ifi.Name)
	}
	if len(order) == 0 {
		if len(opts.Interfaces) > 0 {
			return nil, fmt.Errorf("none of the requested interfaces %v are up with an IPv4 address", opts.Interfaces)
		}
		return nil, fmt.Errorf("no up, non-loopback IPv4 interface to advertise on")
	}
	return build(name, port, opts.info(name), byIface, order)
}

// AdvertiseScoped advertises <name>.local for exactly the given IPs, each on
// the interface whose subnet contains it. Use it to publish dedicated alias
// IPs (e.g. from a port-80 redirect).
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
		ifn := lan.InterfaceForIP(ifaces, ip4)
		if ifn == "" {
			return nil, fmt.Errorf("no active interface has a subnet containing %s", ip4)
		}
		if _, ok := byIface[ifn]; !ok {
			order = append(order, ifn)
		}
		byIface[ifn] = append(byIface[ifn], ip4)
	}
	if len(order) == 0 {
		return nil, fmt.Errorf("no usable IPv4 address to advertise on")
	}
	return build(name, port, opts.info(name), byIface, order)
}

// build creates one responder per interface via the platform's startResponder
// and assembles the Advertiser.
func build(name string, port int, info string, byIface map[string][]net.IP, order []string) (*Advertiser, error) {
	host := name + ".local."
	adv := &Advertiser{Host: host}
	for _, ifn := range order {
		closer, err := startResponder(name, host, port, info, ifn, byIface[ifn])
		if err != nil {
			_ = adv.Close()
			return nil, err
		}
		adv.closers = append(adv.closers, closer)
		for _, ip := range byIface[ifn] {
			adv.Targets = append(adv.Targets, ifn+"="+ip.String())
		}
	}
	return adv, nil
}

// Close stops every responder/registration. Safe to call on a nil Advertiser.
func (a *Advertiser) Close() error {
	if a == nil {
		return nil
	}
	var errs []error
	for _, c := range a.closers {
		if c == nil {
			continue
		}
		if err := c(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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

// ifaceIPv4s returns the global-unicast IPv4 addresses of a single interface.
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
