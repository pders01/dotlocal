package main

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pders01/dotlocal/port80"
)

func TestOptionsLocalDefaultsLoopbackIface(t *testing.T) {
	bf := &bindingFlags{name: "app", ips: "127.0.0.2", ports: "80", toPort: 8080, local: true}
	o, ips, err := bf.options()
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Aliases) != 1 || o.Aliases[0].Iface != loopbackIface() || o.Aliases[0].AliasIP != "127.0.0.2" {
		t.Fatalf("aliases: %+v", o.Aliases)
	}
	if len(ips) != 1 || ips[0].String() != "127.0.0.2" {
		t.Fatalf("ips: %v", ips)
	}
}

func TestOptionsRejectsLoopbackWithoutLocal(t *testing.T) {
	// A loopback IP without --local would put a 127.x alias on a LAN
	// interface and multicast it — reject rather than half-work.
	bf := &bindingFlags{name: "app", ips: "127.0.0.2", ports: "80", toPort: 8080}
	if _, _, err := bf.options(); err == nil || !strings.Contains(err.Error(), "--local") {
		t.Fatalf("expected a hint to add --local, got %v", err)
	}
}

func TestOptionsRejectsNonLoopbackWithLocal(t *testing.T) {
	bf := &bindingFlags{name: "app", ips: "192.168.1.240", ports: "80", toPort: 8080, local: true}
	if _, _, err := bf.options(); err == nil {
		t.Fatal("expected rejection of a LAN IP under --local")
	}
}

func TestSameBindingIgnoresOrder(t *testing.T) {
	a := port80.Options{ToPort: 8080, Ports: []int{80, 443}, Aliases: []port80.Alias{
		{Iface: "lo0", AliasIP: "127.0.0.2"}, {Iface: "lo0", AliasIP: "127.0.0.3"}}}
	b := port80.Options{ToPort: 8080, Ports: []int{443, 80}, Aliases: []port80.Alias{
		{Iface: "lo0", AliasIP: "127.0.0.3"}, {Iface: "lo0", AliasIP: "127.0.0.2"}}}
	if !sameBinding(&a, &b) {
		t.Fatal("order-only differences should compare equal")
	}
}

func TestSameBindingSeesPortFallback(t *testing.T) {
	// A state written by an older version may carry only the scalar Port.
	a := port80.Options{ToPort: 8080, Port: 80, Aliases: []port80.Alias{{Iface: "lo0", AliasIP: "127.0.0.2"}}}
	b := port80.Options{ToPort: 8080, Ports: []int{80}, Aliases: []port80.Alias{{Iface: "lo0", AliasIP: "127.0.0.2"}}}
	if !sameBinding(&a, &b) {
		t.Fatal("scalar Port and Ports[80] should compare equal")
	}
}

func TestSameBindingDetectsChange(t *testing.T) {
	a := port80.Options{ToPort: 8080, Ports: []int{80}, Aliases: []port80.Alias{{Iface: "lo0", AliasIP: "127.0.0.2"}}}
	b := port80.Options{ToPort: 9090, Ports: []int{80}, Aliases: []port80.Alias{{Iface: "lo0", AliasIP: "127.0.0.2"}}}
	if sameBinding(&a, &b) {
		t.Fatal("a changed to-port must not compare equal")
	}
}

func TestKeepArgsRoundTrip(t *testing.T) {
	bf := &bindingFlags{name: "app", ips: "127.0.0.2", ports: "80,443", toPort: 8080, local: true, info: "my app"}
	args := keepArgs(bf, 10*time.Minute)
	if args[0] != "keep" {
		t.Fatalf("first arg: %v", args)
	}
	for _, want := range [][]string{
		{"--name", "app"}, {"--ip", "127.0.0.2"}, {"--ports", "80,443"},
		{"--to-port", "8080"}, {"--interval", "10m0s"}, {"--info", "my app"},
	} {
		i := slices.Index(args, want[0])
		if i < 0 || i+1 >= len(args) || args[i+1] != want[1] {
			t.Fatalf("missing %v in %v", want, args)
		}
	}
	if !slices.Contains(args, "--local") {
		t.Fatalf("missing --local in %v", args)
	}
}
