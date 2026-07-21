//go:build linux

package port80

import (
	"fmt"
	"strconv"
	"strings"
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

// nftRuleSteps builds one nft add-rule invocation per (alias × public port),
// redirecting each alias IP's public ports to the single ToPort. Aliases-outer,
// ports-inner for a stable order. Pure for testing.
func nftRuleSteps(table string, o *Options) [][]string {
	steps := make([][]string, 0, len(o.Aliases)*len(o.Ports))
	for _, a := range o.Aliases {
		for _, p := range o.Ports {
			steps = append(steps, nftAddRuleArgs(table, a, p, o.ToPort))
		}
	}
	return steps
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
	steps = append(steps, nftRuleSteps(table, o)...)
	for _, args := range steps {
		if err := run("nft", args...); err != nil {
			rollback()
			return nil, fmt.Errorf("installing nftables redirect: %w", err)
		}
	}
	return st, nil
}

// hasAlias reports whether the interface currently carries the alias IP.
// `ip -4 addr show` prints each address as "inet <ip>/<prefix>"; matching
// through the slash keeps 10.0.0.2 from matching 10.0.0.20.
func hasAlias(a Alias) (bool, error) {
	out, err := output("ip", "-4", "addr", "show", "dev", a.Iface)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", a.Iface, err)
	}
	return strings.Contains(out, "inet "+a.AliasIP+"/"), nil
}

// verifyUp checks that the alias IPs exist and the redirect table still holds
// its rules (nftables has no global disable, so there is no third leg).
func verifyUp(s *State) error {
	for _, a := range s.Aliases {
		ok, err := hasAlias(a)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("alias IP %s is missing from %s", a.AliasIP, a.Iface)
		}
	}
	out, err := output("nft", "list", "table", "ip", s.Name)
	if err != nil {
		return fmt.Errorf("redirect table %s is missing: %w", s.Name, err)
	}
	if !strings.Contains(out, "dport") {
		return fmt.Errorf("redirect table %s holds no rules", s.Name)
	}
	return nil
}

// reapply converges the system to the recorded state: absent aliases are
// re-added, and the redirect table is dropped and rebuilt — `nft add rule`
// appends, so reloading in place would stack duplicates.
func reapply(s *State) error {
	for _, a := range s.Aliases {
		ok, err := hasAlias(a)
		if err != nil {
			return err
		}
		if !ok {
			if err := run("ip", aliasAddArgs(a)...); err != nil {
				return fmt.Errorf("re-adding alias IP %s: %w", a.AliasIP, err)
			}
		}
	}
	_ = run("nft", nftDelTableArgs(s.Name)...)
	steps := [][]string{nftAddTableArgs(s.Name), nftAddChainArgs(s.Name)}
	steps = append(steps, nftRuleSteps(s.Name, &s.Options)...)
	for _, args := range steps {
		if err := run("nft", args...); err != nil {
			return fmt.Errorf("reinstalling nftables redirect: %w", err)
		}
	}
	return nil
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
		if err := run("ip", aliasDelArgs(a)...); err != nil && !isAbsentAddr(err) {
			note(fmt.Errorf("removing alias IP %s: %w", a.AliasIP, err))
		}
	}
	return firstErr
}
