//go:build darwin

package port80

import (
	"strings"
	"testing"
)

func TestRenderPFAnchorMultiAlias(t *testing.T) {
	o := &Options{Name: "fwrd", Port: 80, ToPort: 5336, Aliases: []Alias{
		{Iface: "en0", AliasIP: "192.168.1.240"},
		{Iface: "en9", AliasIP: "192.168.178.240"},
	}}
	got := renderPFAnchor(o)
	want := "rdr pass on en0 inet proto tcp from any to 192.168.1.240 port 80 -> 127.0.0.1 port 5336\n" +
		"rdr pass on en9 inet proto tcp from any to 192.168.178.240 port 80 -> 127.0.0.1 port 5336\n"
	if got != want {
		t.Fatalf("renderPFAnchor:\n got %q\nwant %q", got, want)
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
}

func TestRenderPFAnchorContains(t *testing.T) {
	o := &Options{Name: "x", Port: 80, ToPort: 8080, Aliases: []Alias{{Iface: "en0", AliasIP: "10.0.0.5"}}}
	if !strings.Contains(renderPFAnchor(o), "to 10.0.0.5 port 80 -> 127.0.0.1 port 8080") {
		t.Fatal("rdr rule missing expected redirect")
	}
}
