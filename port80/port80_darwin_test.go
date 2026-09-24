//go:build darwin

package port80

import (
	"strings"
	"testing"
)

func TestRenderPFAnchorMultiAlias(t *testing.T) {
	o := &Options{Name: "fwrd", Port: 80, Ports: []int{80}, ToPort: 5336, Aliases: []Alias{
		{Iface: "en0", AliasIP: "192.168.1.240"},
		{Iface: "en9", AliasIP: "192.168.178.240"},
	}}
	got := renderPFAnchor(o)
	want := "rdr pass on en0 inet proto tcp from any to 192.168.1.240 port 80 -> 192.168.1.240 port 5336\n" +
		"rdr pass on lo0 inet proto tcp from any to 192.168.1.240 port 80 -> 127.0.0.1 port 5336\n" +
		"rdr pass on en9 inet proto tcp from any to 192.168.178.240 port 80 -> 192.168.178.240 port 5336\n" +
		"rdr pass on lo0 inet proto tcp from any to 192.168.178.240 port 80 -> 127.0.0.1 port 5336\n"
	if got != want {
		t.Fatalf("renderPFAnchor:\n got %q\nwant %q", got, want)
	}
}

func TestRenderPFAnchorMultiPort(t *testing.T) {
	// One LAN and one loopback rdr line per (alias × port), emitted
	// aliases-outer, ports-inner.
	o := &Options{Name: "fwrd", ToPort: 5336, Ports: []int{80, 443}, Aliases: []Alias{
		{Iface: "en0", AliasIP: "192.168.1.240"},
		{Iface: "en9", AliasIP: "192.168.178.240"},
	}}
	got := renderPFAnchor(o)
	want := "rdr pass on en0 inet proto tcp from any to 192.168.1.240 port 80 -> 192.168.1.240 port 5336\n" +
		"rdr pass on lo0 inet proto tcp from any to 192.168.1.240 port 80 -> 127.0.0.1 port 5336\n" +
		"rdr pass on en0 inet proto tcp from any to 192.168.1.240 port 443 -> 192.168.1.240 port 5336\n" +
		"rdr pass on lo0 inet proto tcp from any to 192.168.1.240 port 443 -> 127.0.0.1 port 5336\n" +
		"rdr pass on en9 inet proto tcp from any to 192.168.178.240 port 80 -> 192.168.178.240 port 5336\n" +
		"rdr pass on lo0 inet proto tcp from any to 192.168.178.240 port 80 -> 127.0.0.1 port 5336\n" +
		"rdr pass on en9 inet proto tcp from any to 192.168.178.240 port 443 -> 192.168.178.240 port 5336\n" +
		"rdr pass on lo0 inet proto tcp from any to 192.168.178.240 port 443 -> 127.0.0.1 port 5336\n"
	if got != want {
		t.Fatalf("renderPFAnchor multi-port:\n got %q\nwant %q", got, want)
	}
	wantLines := 2 * len(o.Aliases) * len(o.Ports)
	if n := strings.Count(got, "rdr pass"); n != wantLines {
		t.Fatalf("expected %d rdr lines, got %d", wantLines, n)
	}
}

func TestAliasAddArgsUsesHostMask(t *testing.T) {
	// A /32 host alias avoids the same-subnet REJECT route on macOS; the
	// caller's Mask is intentionally not used for the alias.
	got := strings.Join(aliasAddArgs(Alias{Iface: "en0", AliasIP: "192.168.1.240", Mask: "255.255.255.0"}), " ")
	want := "en0 alias 192.168.1.240 netmask 255.255.255.255"
	if got != want {
		t.Fatalf("aliasAddArgs = %q, want %q", got, want)
	}
}

func TestPFSubAnchor(t *testing.T) {
	if got := pfSubAnchor("fwrd"); got != "com.apple/fwrd" {
		t.Fatalf("pfSubAnchor = %q", got)
	}
}

func TestParsePFToken(t *testing.T) {
	if got := parsePFToken("pf enabled\nToken : 12345\n"); got != "12345" {
		t.Fatalf("parsePFToken = %q", got)
	}
	if got := parsePFToken("pf enabled\n"); got != "" {
		t.Fatalf("parsePFToken empty = %q", got)
	}
	// Non-numeric content after the colon must be rejected (it would otherwise
	// become a `pfctl -X <token>` argument).
	if got := parsePFToken("Token : 999 ; rm -rf /\n"); got != "" {
		t.Fatalf("parsePFToken garbage = %q, want empty", got)
	}
}

// The skip/ruleset fixtures below are verbatim pfctl output captured from a
// real incident (2026-07-23): vmnet/Internet Sharing had set `skip on lo0`,
// leaving perfectly loaded loopback redirects that were never evaluated.

func TestParseSkippedIfaces(t *testing.T) {
	out := "No ALTQ support in kernel\nALTQ related functions disabled\n" +
		"ALL\nanpi0\nap1\nbridge100\nen0\nlo0 (skip)\nstf0\nutun0\nvmenet0\n"
	skipped := parseSkippedIfaces(out)
	if !skipped["lo0"] {
		t.Fatal("lo0 should be flagged as skipped")
	}
	if len(skipped) != 1 {
		t.Fatalf("only lo0 should be skipped, got %v", skipped)
	}
}

func TestParseSkippedIfacesNone(t *testing.T) {
	if got := parseSkippedIfaces("ALL\nen0\nlo0\n"); len(got) != 0 {
		t.Fatalf("no interface is skipped, got %v", got)
	}
}

func TestRenderMainRuleset(t *testing.T) {
	filterDump := "No ALTQ support in kernel\nALTQ related functions disabled\n" +
		"scrub-anchor \"com.apple/*\" all fragment reassemble\n" +
		"scrub-anchor \"com.apple.internet-sharing\" all fragment reassemble\n" +
		"anchor \"com.apple/*\" all\n" +
		"anchor \"com.apple.internet-sharing\" all\n"
	natDump := "No ALTQ support in kernel\nALTQ related functions disabled\n" +
		"nat-anchor \"com.apple/*\" all\n" +
		"nat-anchor \"com.apple.internet-sharing\" all\n" +
		"rdr-anchor \"com.apple/*\" all\n" +
		"rdr-anchor \"com.apple.internet-sharing\" all\n"
	dummynetDump := "dummynet-anchor \"com.apple/*\" all\n"
	want := "scrub-anchor \"com.apple/*\" all fragment reassemble\n" +
		"scrub-anchor \"com.apple.internet-sharing\" all fragment reassemble\n" +
		"nat-anchor \"com.apple/*\" all\n" +
		"nat-anchor \"com.apple.internet-sharing\" all\n" +
		"rdr-anchor \"com.apple/*\" all\n" +
		"rdr-anchor \"com.apple.internet-sharing\" all\n" +
		"dummynet-anchor \"com.apple/*\" all\n" +
		"anchor \"com.apple/*\" all\n" +
		"anchor \"com.apple.internet-sharing\" all\n"
	if got := renderMainRuleset(filterDump, natDump, dummynetDump); got != want {
		t.Fatalf("renderMainRuleset:\n got %q\nwant %q", got, want)
	}
}

func TestRenderMainRulesetEmpty(t *testing.T) {
	// Empty dumps must render empty (not "\n"), so clearPFSkip's com.apple/*
	// guard is the only thing standing between a truncated dump and a wipe.
	if got := renderMainRuleset("", "No ALTQ support in kernel\n", ""); got != "" {
		t.Fatalf("empty dumps should render empty, got %q", got)
	}
}

func TestRenderPFAnchorContains(t *testing.T) {
	o := &Options{Name: "x", Port: 80, Ports: []int{80}, ToPort: 8080, Aliases: []Alias{{Iface: "en0", AliasIP: "10.0.0.5"}}}
	got := renderPFAnchor(o)
	if !strings.Contains(got, "to 10.0.0.5 port 80 -> 10.0.0.5 port 8080") {
		t.Fatal("rdr rule missing expected LAN redirect")
	}
	if !strings.Contains(got, "on lo0 inet proto tcp from any to 10.0.0.5 port 80 -> 127.0.0.1 port 8080") {
		t.Fatal("rdr rule missing expected host-local redirect")
	}
}
