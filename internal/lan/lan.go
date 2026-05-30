// Package lan holds the small LAN/DNS primitives shared by the public
// packages, so there is one definition of each rather than a copy drifting in
// every package. It is internal: these are implementation details, not API.
package lan

import "net"

// ValidLabel reports whether s is a valid single DNS label: 1–63 characters of
// letters, digits, or hyphens, not starting or ending with a hyphen. Every name
// in this module becomes the <name>.local host, so this is the one rule that
// keeps malformed input out of the mDNS records — and, being a strict subset of
// shell/path-safe characters, it doubles as the guard for names that become a
// firewall anchor, an nftables table, or a state-file path.
func ValidLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// InterfaceForIP returns the name of the up, non-loopback interface whose
// subnet contains ip, or "" if none does. The caller passes a pre-enumerated
// interface list so a single net.Interfaces() call can back several lookups.
func InterfaceForIP(ifaces []net.Interface, ip net.IP) string {
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
