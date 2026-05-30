package port80

import (
	"errors"
	"testing"
)

func TestApplyDefaults(t *testing.T) {
	o := Options{Aliases: []Alias{{}}}
	o.applyDefaults()
	if o.Port != 80 || o.ToPort != 8080 {
		t.Fatalf("port defaults: %+v", o)
	}
	if o.Aliases[0].Prefix != 24 || o.Aliases[0].Mask != "255.255.255.0" {
		t.Fatalf("alias defaults: %+v", o.Aliases[0])
	}
}

func TestValidate(t *testing.T) {
	good := Options{Name: "fwrd", Port: 80, ToPort: 8080,
		Aliases: []Alias{{Iface: "en0", AliasIP: "192.168.1.240"}}}
	good.applyDefaults() // Up applies defaults (prefix/mask) before validate
	if err := good.validate(); err != nil {
		t.Fatalf("good.validate: %v", err)
	}
	full := []Alias{{Iface: "en0", AliasIP: "192.168.1.240", Prefix: 24, Mask: "255.255.255.0"}}
	bad := []Options{
		{Port: 80, ToPort: 8080, Aliases: full}, // no name
		{Name: "x", Port: 80, ToPort: 8080},     // no aliases
		{Name: "x", Port: 80, ToPort: 8080, Aliases: []Alias{{AliasIP: "192.168.1.240", Prefix: 24, Mask: "255.255.255.0"}}}, // no iface
		{Name: "x", Port: 80, ToPort: 8080, Aliases: []Alias{{Iface: "en0", AliasIP: "nope", Prefix: 24, Mask: "255.255.255.0"}}},
		{Name: "x", Port: 0, ToPort: 8080, Aliases: full},                                                                                             // bad port
		{Name: "../etc", Port: 80, ToPort: 8080, Aliases: full},                                                                                       // path-traversal name
		{Name: "x", Port: 80, ToPort: 8080, Aliases: []Alias{{Iface: "en0\nblock all", AliasIP: "192.168.1.240", Prefix: 24, Mask: "255.255.255.0"}}}, // pf injection
	}
	for i, o := range bad {
		if err := o.validate(); err == nil {
			t.Errorf("bad[%d] validate: expected error", i)
		}
	}
}

func TestStatePathRejectsUnsafeName(t *testing.T) {
	for _, bad := range []string{"", "../etc", "a/b", "x.y", "name with space", ".hidden"} {
		if _, err := statePath(bad); err == nil {
			t.Errorf("statePath(%q): expected rejection", bad)
		}
	}
	if _, err := statePath("fwrd"); err != nil {
		t.Errorf("statePath(%q): unexpected error %v", "fwrd", err)
	}
}

func TestValidateRejectsNonContiguousMask(t *testing.T) {
	o := Options{Name: "x", Port: 80, ToPort: 8080,
		Aliases: []Alias{{Iface: "en0", AliasIP: "192.168.1.240", Prefix: 24, Mask: "255.0.255.0"}}}
	if err := o.validate(); err == nil {
		t.Fatal("expected rejection of non-contiguous netmask 255.0.255.0")
	}
}

func TestDetectIfaceErrors(t *testing.T) {
	if _, err := DetectIface("not-an-ip"); err == nil {
		t.Fatal("expected error for invalid IP")
	}
	if _, err := DetectIface("203.0.113.7"); err == nil { // TEST-NET-3, on no local subnet
		t.Fatal("expected error for IP on no local subnet")
	}
}

func TestStateRoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if _, err := loadState("fwrd"); !errors.Is(err, ErrNoBinding) {
		t.Fatalf("loadState empty: %v", err)
	}
	want := &State{
		Options: Options{Name: "fwrd", Port: 80, ToPort: 8080,
			Aliases: []Alias{{Iface: "en0", AliasIP: "192.168.1.240", Prefix: 24, Mask: "255.255.255.0"}}},
		Backend: "pf", PFToken: "123",
	}
	if err := saveState(want); err != nil {
		t.Fatalf("saveState: %v", err)
	}
	got, err := loadState("fwrd")
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	if got.Name != "fwrd" || len(got.Aliases) != 1 || got.Aliases[0].AliasIP != "192.168.1.240" || got.PFToken != "123" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if err := clearState("fwrd"); err != nil {
		t.Fatalf("clearState: %v", err)
	}
	if _, err := loadState("fwrd"); !errors.Is(err, ErrNoBinding) {
		t.Fatalf("loadState after clear: %v", err)
	}
}
