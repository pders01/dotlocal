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
