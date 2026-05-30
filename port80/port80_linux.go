//go:build linux

package port80

import (
	"fmt"
	"strconv"
)

// Linux uses iproute2 for the alias IPs and nftables for the redirect. The
// redirect lives in its own table (named after Options.Name) so teardown is a
// single `nft delete table` that never touches other firewall rules.

const supported = true

func aliasAddArgs(a Alias) []string {
	return []string{"addr", "add", a.AliasIP + "/" + strconv.Itoa(a.Prefix), "dev", a.Iface}
}

func aliasDelArgs(a Alias) []string {
	return []string{"addr", "del", a.AliasIP + "/" + strconv.Itoa(a.Prefix), "dev", a.Iface}
}

func nftAddTableArgs(table string) []string {
	return []string{"add", "table", "ip", table}
}

func nftAddChainArgs(table string) []string {
	// A nat prerouting chain at dstnat priority: redirect happens before the
	// socket lookup, so it intercepts the alias IP's :80 even when the host
	// already listens on 0.0.0.0:80.
	return []string{"add", "chain", "ip", table, "prerouting",
		"{", "type", "nat", "hook", "prerouting", "priority", "dstnat", ";", "}"}
}

func nftAddRuleArgs(table string, a Alias, port, toPort int) []string {
	return []string{"add", "rule", "ip", table, "prerouting",
		"ip", "daddr", a.AliasIP, "tcp", "dport", strconv.Itoa(port),
		"redirect", "to", ":" + strconv.Itoa(toPort)}
}

func nftDelTableArgs(table string) []string {
	return []string{"delete", "table", "ip", table}
}

func applyUp(o *Options) (*State, error) {
	st := &State{Options: *o, Backend: "nftables"}
	table := o.Name
	added := make([]Alias, 0, len(o.Aliases))
	rollback := func() {
		_ = run("nft", nftDelTableArgs(table)...)
		for _, a := range added {
			_ = run("ip", aliasDelArgs(a)...)
		}
	}
	for _, a := range o.Aliases {
		if err := run("ip", aliasAddArgs(a)...); err != nil {
			rollback()
			return nil, fmt.Errorf("adding alias IP %s: %w", a.AliasIP, err)
		}
		added = append(added, a)
	}

	steps := [][]string{nftAddTableArgs(table), nftAddChainArgs(table)}
	for _, a := range o.Aliases {
		steps = append(steps, nftAddRuleArgs(table, a, o.Port, o.ToPort))
	}
	for _, args := range steps {
		if err := run("nft", args...); err != nil {
			rollback()
			return nil, fmt.Errorf("installing nftables redirect: %w", err)
		}
	}
	return st, nil
}

func applyDown(s *State) error {
	var firstErr error
	note := func(e error) {
		if e != nil && firstErr == nil {
			firstErr = e
		}
	}
	if err := run("nft", nftDelTableArgs(s.Name)...); err != nil {
		note(fmt.Errorf("removing nftables table: %w", err))
	}
	for _, a := range s.Aliases {
		if err := run("ip", aliasDelArgs(a)...); err != nil {
			note(fmt.Errorf("removing alias IP %s: %w", a.AliasIP, err))
		}
	}
	return firstErr
}
