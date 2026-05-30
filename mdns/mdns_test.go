package mdns

import (
	"net"
	"testing"
)

func TestIsLANCandidate(t *testing.T) {
	const lan = net.FlagUp | net.FlagBroadcast | net.FlagMulticast
	cases := []struct {
		name  string
		flags net.Flags
		want  bool
	}{
		{"en0", lan, true},
		{"eth0", lan, true},
		{"bridge100", lan, false},
		{"utun8", lan | net.FlagPointToPoint, false},
		{"docker0", lan, false},
		{"tailscale0", lan | net.FlagPointToPoint, false},
		{"awdl0", lan, false},
		{"lo0", net.FlagUp | net.FlagLoopback, false},
		{"en1", net.FlagBroadcast | net.FlagMulticast, false}, // down
	}
	for _, c := range cases {
		ifi := net.Interface{Name: c.name, Flags: c.flags}
		if got := isLANCandidate(&ifi); got != c.want {
			t.Errorf("isLANCandidate(%s, %v) = %v, want %v", c.name, c.flags, got, c.want)
		}
	}
}

func TestOptionsInfo(t *testing.T) {
	if got := (Options{}).info("fwrd"); got != "fwrd (dotlocal)" {
		t.Fatalf("default info = %q", got)
	}
	if got := (Options{Info: "custom"}).info("fwrd"); got != "custom" {
		t.Fatalf("explicit info = %q", got)
	}
}
