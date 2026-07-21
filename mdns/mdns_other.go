//go:build !darwin

package mdns

import (
	"fmt"
	"net"

	"github.com/hashicorp/mdns"
)

// startResponder runs a self-hosted mDNS responder bound to one interface. It
// coexists with Avahi over the shared multicast socket (SO_REUSEADDR). Returns
// a closer that shuts the responder down.
func startResponder(name, host string, port int, info, ifaceName string, ips []net.IP) (func() error, error) {
	ifi, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("looking up interface %s: %w", ifaceName, err)
	}
	svc, err := mdns.NewMDNSService(name, "_http._tcp", "local.", host, port, ips, []string{info})
	if err != nil {
		return nil, fmt.Errorf("building mDNS service for %s: %w", ifaceName, err)
	}
	srv, err := mdns.NewServer(&mdns.Config{Zone: svc, Iface: ifi})
	if err != nil {
		return nil, fmt.Errorf("starting mDNS responder on %s: %w", ifaceName, err)
	}
	return srv.Shutdown, nil
}

// startLocalResponder has no backend here: host-local registrations need a
// system resolver that serves them to local clients (macOS mDNSResponder's
// LocalOnly interface). A self-hosted multicast responder is inherently
// network-visible, which is the opposite of what local-only promises.
func startLocalResponder(_, _ string, _ int, _ string, _, _ []net.IP) (func() error, error) {
	return nil, fmt.Errorf("mdns: local-only advertising is only supported on macOS")
}
