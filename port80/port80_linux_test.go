//go:build linux

package port80

import (
	"strings"
	"testing"
)

func TestAliasArgs(t *testing.T) {
	a := Alias{Iface: "eth0", AliasIP: "192.168.1.240", Prefix: 24}
	if got := strings.Join(aliasAddArgs(a), " "); got != "addr add 192.168.1.240/24 dev eth0" {
		t.Fatalf("aliasAddArgs = %q", got)
	}
	if got := strings.Join(aliasDelArgs(a), " "); got != "addr del 192.168.1.240/24 dev eth0" {
		t.Fatalf("aliasDelArgs = %q", got)
	}
}

func TestNftArgs(t *testing.T) {
	a := Alias{Iface: "eth0", AliasIP: "192.168.1.240"}
	if got := strings.Join(nftAddTableArgs("fwrd"), " "); got != "add table ip fwrd" {
		t.Fatalf("table = %q", got)
	}
	if got := strings.Join(nftAddChainArgs("fwrd"), " "); got != "add chain ip fwrd prerouting { type nat hook prerouting priority dstnat ; }" {
		t.Fatalf("chain = %q", got)
	}
	if got := strings.Join(nftAddRuleArgs("fwrd", a, 80, 5336), " "); got != "add rule ip fwrd prerouting ip daddr 192.168.1.240 tcp dport 80 redirect to :5336" {
		t.Fatalf("rule = %q", got)
	}
	if got := strings.Join(nftDelTableArgs("fwrd"), " "); got != "delete table ip fwrd" {
		t.Fatalf("del = %q", got)
	}
}

func TestNftRuleStepsMultiPort(t *testing.T) {
	// One rule per (alias × port): len(aliases)*len(ports) rules, emitted
	// aliases-outer, ports-inner.
	o := &Options{Name: "fwrd", ToPort: 5336, Ports: []int{80, 443}, Aliases: []Alias{
		{Iface: "eth0", AliasIP: "192.168.1.240"},
		{Iface: "eth1", AliasIP: "192.168.178.240"},
	}}
	steps := nftRuleSteps("fwrd", o)
	want := []string{
		"add rule ip fwrd prerouting ip daddr 192.168.1.240 tcp dport 80 redirect to :5336",
		"add rule ip fwrd prerouting ip daddr 192.168.1.240 tcp dport 443 redirect to :5336",
		"add rule ip fwrd prerouting ip daddr 192.168.178.240 tcp dport 80 redirect to :5336",
		"add rule ip fwrd prerouting ip daddr 192.168.178.240 tcp dport 443 redirect to :5336",
	}
	if len(steps) != len(o.Aliases)*len(o.Ports) {
		t.Fatalf("expected %d rules, got %d", len(o.Aliases)*len(o.Ports), len(steps))
	}
	for i, args := range steps {
		if got := strings.Join(args, " "); got != want[i] {
			t.Fatalf("rule[%d] = %q, want %q", i, got, want[i])
		}
	}
}

func TestNftRuleStepsSinglePort(t *testing.T) {
	// Back-compat: a single port yields one rule per alias.
	o := &Options{Name: "fwrd", ToPort: 8080, Ports: []int{80}, Aliases: []Alias{
		{Iface: "eth0", AliasIP: "192.168.1.240"},
	}}
	steps := nftRuleSteps("fwrd", o)
	if len(steps) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(steps))
	}
	if got := strings.Join(steps[0], " "); got != "add rule ip fwrd prerouting ip daddr 192.168.1.240 tcp dport 80 redirect to :8080" {
		t.Fatalf("rule = %q", got)
	}
}
