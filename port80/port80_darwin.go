//go:build darwin

package port80

import (
	"fmt"
	"os/exec"
	"strings"
)

// macOS uses ifconfig for the alias IPs and pf for the redirect. Rather than
// edit /etc/pf.conf, the redirect is loaded into the sub-anchor
// "com.apple/<name>": the stock pf.conf already declares `rdr-anchor
// "com.apple/*"`, whose wildcard evaluates every sub-anchor under com.apple/.
// So loading rules there is enough for pf to apply them — no system file is
// touched, and teardown is a flush of just our sub-anchor. (This is the same
// hook Docker and various VPNs have historically used.)

const supported = true

func pfSubAnchor(name string) string { return "com.apple/" + name }

// aliasAddArgs adds the alias as a host route (/32), not the LAN's subnet
// mask. The alias IP is always in a subnet the interface already carries (the
// caller derives the interface from the IP's subnet), and macOS rejects a
// second address with that subnet's mask — it installs a REJECT route that
// drops all traffic to the alias. A /32 (255.255.255.255) gives it a clean
// host route instead; LAN clients still reach it via ARP on the interface.
// The `netmask` keyword is explicit because a positional mask is misparsed.
func aliasAddArgs(a Alias) []string {
	return []string{a.Iface, "alias", a.AliasIP, "netmask", "255.255.255.255"}
}
func aliasDelArgs(a Alias) []string { return []string{a.Iface, "-alias", a.AliasIP} }

// renderPFAnchor is the rdr ruleset for the sub-anchor: two rules per
// (alias × public port), redirecting each alias IP's public ports to the
// service's single unprivileged port.
//
// Traffic arriving from the LAN must retain the alias IP as its redirect
// target: macOS drops a physical-interface packet redirected to loopback as a
// martian. Traffic originating on this host traverses lo0 instead of the LAN
// interface, so it needs a separate rule targeting 127.0.0.1. Together these
// make the bare URL work both from LAN clients and from the hosting Mac while
// leaving the host's primary-IP public ports untouched. Rules are emitted
// aliases-outer, ports-inner, with the LAN rule before its loopback companion.
// Pure for testing.
func renderPFAnchor(o *Options) string {
	var b strings.Builder
	for _, a := range o.Aliases {
		for _, p := range o.Ports {
			fmt.Fprintf(&b, "rdr pass on %s inet proto tcp from any to %s port %d -> %s port %d\n",
				a.Iface, a.AliasIP, p, a.AliasIP, o.ToPort)
			fmt.Fprintf(&b, "rdr pass on lo0 inet proto tcp from any to %s port %d -> 127.0.0.1 port %d\n",
				a.AliasIP, p, o.ToPort)
		}
	}
	return b.String()
}

func applyUp(o *Options) (*State, error) {
	st := &State{Options: *o, Backend: "pf"}
	added := make([]Alias, 0, len(o.Aliases))
	for _, a := range o.Aliases {
		// Clear any stale host route for this IP first: a REJECT route orphaned
		// by an earlier run (or a removed alias) would otherwise shadow the new
		// alias and drop all traffic to it.
		_ = run("route", "-n", "delete", a.AliasIP)
		if err := run("ifconfig", aliasAddArgs(a)...); err != nil {
			for _, done := range added {
				_ = run("ifconfig", aliasDelArgs(done)...)
			}
			return nil, fmt.Errorf("adding alias IP %s: %w", a.AliasIP, err)
		}
		added = append(added, a)
	}
	if err := installPFRedirect(o, st); err != nil {
		for _, a := range added {
			_ = run("ifconfig", aliasDelArgs(a)...)
		}
		return nil, err
	}
	return st, nil
}

// installPFRedirect loads the redirects into the com.apple/<name> sub-anchor
// and enables pf, recording the enable token. It first verifies the stock
// wildcard rdr-anchor is present, since without it the sub-anchor would load
// but never be evaluated.
func installPFRedirect(o *Options, st *State) error {
	anchor := pfSubAnchor(o.Name)
	if err := ensureAppleRdrAnchor(); err != nil {
		return err
	}
	if err := pfLoadAnchor(anchor, renderPFAnchor(o)); err != nil {
		return err
	}
	tok, err := output("pfctl", "-E")
	if err != nil {
		_ = run("pfctl", "-a", anchor, "-F", "all") // unload what we just added
		return fmt.Errorf("enabling pf: %w", err)
	}
	st.PFToken = parsePFToken(tok)
	return nil
}

// ensureAppleRdrAnchor checks that the loaded ruleset references the
// `com.apple/*` rdr-anchor that evaluates our sub-anchor.
func ensureAppleRdrAnchor() error {
	out, err := output("pfctl", "-sn")
	if err != nil {
		return fmt.Errorf("reading pf ruleset: %w", err)
	}
	if !strings.Contains(out, "com.apple/*") {
		return fmt.Errorf("this Mac's pf ruleset has no `rdr-anchor \"com.apple/*\"`, so the " +
			"redirect anchor would never be evaluated; restore the stock /etc/pf.conf and reload it " +
			"(sudo pfctl -f /etc/pf.conf)")
	}
	return nil
}

// pfLoadAnchor loads rules into the given sub-anchor via stdin.
func pfLoadAnchor(anchor, rules string) error {
	cmd := exec.Command("pfctl", "-a", anchor, "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("loading pf anchor %s: %w: %s", anchor, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// hasAlias reports whether the interface currently carries the alias IP.
// ifconfig prints each IPv4 address as "inet <ip> "; the trailing space keeps
// 127.0.0.2 from matching 127.0.0.20.
func hasAlias(a Alias) (bool, error) {
	out, err := output("ifconfig", a.Iface)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", a.Iface, err)
	}
	return strings.Contains(out, "inet "+a.AliasIP+" "), nil
}

// pfEnabled reports whether pf is currently enabled.
func pfEnabled() (bool, error) {
	out, err := output("pfctl", "-s", "info")
	if err != nil {
		return false, fmt.Errorf("reading pf status: %w", err)
	}
	return strings.Contains(out, "Status: Enabled"), nil
}

// parseSkippedIfaces extracts the interfaces flagged `skip` from
// `pfctl -s Interfaces -v` output, whose lines read "lo0 (skip)". A skipped
// interface is exempt from pf entirely: rules on it stay loaded and visible
// but are never evaluated. Pure for testing.
func parseSkippedIfaces(out string) map[string]bool {
	skipped := make(map[string]bool)
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == "(skip)" {
			skipped[f[0]] = true
		}
	}
	return skipped
}

// skippedAliasIfaces returns the binding's interfaces that pf currently
// skips, deduplicated in alias order.
func skippedAliasIfaces(s *State) ([]string, error) {
	out, err := output("pfctl", "-s", "Interfaces", "-v")
	if err != nil {
		return nil, fmt.Errorf("reading pf interface flags: %w", err)
	}
	flagged := parseSkippedIfaces(out)
	var hit []string
	seen := make(map[string]bool)
	for _, a := range s.Aliases {
		if flagged[a.Iface] && !seen[a.Iface] {
			hit = append(hit, a.Iface)
			seen[a.Iface] = true
		}
	}
	return hit, nil
}

// renderMainRuleset reassembles a loadable main ruleset from live pfctl dumps
// (`-sr`, `-s nat`, `-s dummynet`), reordered into pf.conf section order:
// scrub, translation, dummynet, filter. The point of rebuilding from the live
// ruleset rather than reloading /etc/pf.conf is to preserve the anchor
// attachments system services (Internet Sharing / vmnet — i.e. VM NAT) insert
// dynamically at runtime; a stock-file reload would drop them and cut off VM
// networking. pfctl's ALTQ stderr noise is filtered out. Pure for testing.
func renderMainRuleset(filterDump, natDump, dummynetDump string) string {
	var scrub, nat, dummynet, filter []string
	section := func(dst *[]string, dump string, keep func(string) bool) {
		for line := range strings.SplitSeq(dump, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.Contains(line, "ALTQ") || !keep(line) {
				continue
			}
			*dst = append(*dst, line)
		}
	}
	isScrub := func(l string) bool { return strings.HasPrefix(l, "scrub") }
	section(&scrub, filterDump, isScrub)
	section(&filter, filterDump, func(l string) bool { return !isScrub(l) })
	all := func(string) bool { return true }
	section(&nat, natDump, all)
	section(&dummynet, dummynetDump, all)
	lines := make([]string, 0, len(scrub)+len(nat)+len(dummynet)+len(filter))
	for _, sec := range [][]string{scrub, nat, dummynet, filter} {
		lines = append(lines, sec...)
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// clearPFSkip drops pf's per-interface skip flags. macOS's vmnet/Internet
// Sharing machinery (Virtualization.framework NAT — colima's vz mode, Apple's
// `container` CLI) reloads pf on network reconfiguration and sets
// `set skip on lo0`, after which every loopback rule is dead while looking
// perfectly loaded. Only a main-ruleset load clears interface flags —
// sub-anchor loads (which is all the keeper otherwise does) never touch them —
// so the live main ruleset is dumped, reassembled, and loaded back. Sub-anchor
// contents live outside the main ruleset and survive untouched.
func clearPFSkip() error {
	filterDump, err := output("pfctl", "-sr")
	if err != nil {
		return fmt.Errorf("dumping pf filter rules: %w", err)
	}
	natDump, err := output("pfctl", "-s", "nat")
	if err != nil {
		return fmt.Errorf("dumping pf nat rules: %w", err)
	}
	dummynetDump, err := output("pfctl", "-s", "dummynet")
	if err != nil {
		// dummynet is an Apple extension; a pfctl that can't dump it just has
		// nothing to preserve there.
		dummynetDump = ""
	}
	conf := renderMainRuleset(filterDump, natDump, dummynetDump)
	// Refuse to load a ruleset that lost the com.apple wildcard: an empty or
	// truncated dump would otherwise replace the main ruleset with less than
	// what is running now.
	if !strings.Contains(conf, `"com.apple/*"`) {
		return fmt.Errorf("live pf ruleset dump is missing the com.apple/* anchors; refusing to reload it")
	}
	cmd := exec.Command("pfctl", "-f", "-")
	cmd.Stdin = strings.NewReader(conf)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("reloading pf main ruleset: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// verifyUp checks the four legs a working binding stands on: the alias IPs
// exist, the sub-anchor still holds redirect rules, pf is enabled, and pf is
// not skipping the interfaces the rules match on.
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
	out, err := output("pfctl", "-a", pfSubAnchor(s.Name), "-sn")
	if err != nil {
		return fmt.Errorf("reading pf sub-anchor %s: %w", pfSubAnchor(s.Name), err)
	}
	if !strings.Contains(out, "rdr") {
		return fmt.Errorf("pf sub-anchor %s holds no redirect rules (flushed by a pf reload?)", pfSubAnchor(s.Name))
	}
	on, err := pfEnabled()
	if err != nil {
		return err
	}
	if !on {
		return fmt.Errorf("pf is disabled")
	}
	skipped, err := skippedAliasIfaces(s)
	if err != nil {
		return err
	}
	if len(skipped) > 0 {
		return fmt.Errorf("pf is skipping %s (`set skip` flag — the redirect rules are loaded but never evaluated)",
			strings.Join(skipped, ", "))
	}
	return nil
}

// reapply converges the system to the recorded state in place: absent aliases
// are re-added, a skip flag on any of the binding's interfaces is cleared (see
// clearPFSkip), the sub-anchor is reloaded (idempotent — loading replaces its
// contents), and pf is re-enabled only if something disabled it, taking a
// fresh enable token then. Re-enabling unconditionally would leak a pf
// reference per heal; keeping the old token while pf is up costs nothing
// (a stale token just makes the eventual `pfctl -X` a no-op).
func reapply(s *State) error {
	for _, a := range s.Aliases {
		ok, err := hasAlias(a)
		if err != nil {
			return err
		}
		if !ok {
			_ = run("route", "-n", "delete", a.AliasIP)
			if err := run("ifconfig", aliasAddArgs(a)...); err != nil {
				return fmt.Errorf("re-adding alias IP %s: %w", a.AliasIP, err)
			}
		}
	}
	if err := ensureAppleRdrAnchor(); err != nil {
		return err
	}
	if skipped, err := skippedAliasIfaces(s); err != nil {
		return err
	} else if len(skipped) > 0 {
		if err := clearPFSkip(); err != nil {
			return fmt.Errorf("clearing pf skip flag on %s: %w", strings.Join(skipped, ", "), err)
		}
	}
	if err := pfLoadAnchor(pfSubAnchor(s.Name), renderPFAnchor(&s.Options)); err != nil {
		return err
	}
	on, err := pfEnabled()
	if err != nil {
		return err
	}
	if !on {
		tok, err := output("pfctl", "-E")
		if err != nil {
			return fmt.Errorf("re-enabling pf: %w", err)
		}
		s.PFToken = parsePFToken(tok)
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
	// Flush our sub-anchor's rules — this is what actually removes the
	// redirect; everything below is cleanup.
	_ = run("pfctl", "-a", pfSubAnchor(s.Name), "-F", "all")
	// Drop our enable reference, best-effort: the token can be invalid if pf
	// was reloaded since Up, and a failure here must not abort teardown (the
	// redirect is already gone above). Surfacing it would otherwise leave the
	// state file uncleared and block the next Up.
	if s.PFToken != "" {
		_ = run("pfctl", "-X", s.PFToken)
	} else {
		_ = run("pfctl", "-d")
	}
	for _, a := range s.Aliases {
		if err := run("ifconfig", aliasDelArgs(a)...); err != nil && !isAbsentAddr(err) {
			note(fmt.Errorf("removing alias IP %s: %w", a.AliasIP, err))
		}
		// Drop the cloned host route too; ifconfig usually removes it, but a
		// route left behind would shadow a future alias for the same IP.
		_ = run("route", "-n", "delete", a.AliasIP)
	}
	return firstErr
}

// parsePFToken extracts the enable-reference token from `pfctl -E` output,
// whose relevant line reads "Token : 1234567890".
func parsePFToken(out string) string {
	for line := range strings.SplitSeq(out, "\n") {
		if i := strings.Index(line, "Token"); i >= 0 {
			if c := strings.Index(line[i:], ":"); c >= 0 {
				tok := strings.TrimSpace(line[i+c+1:])
				// A pf enable-reference token is a decimal integer. Anything
				// else means we misparsed; store nothing rather than a value
				// that would later be handed to `pfctl -X`.
				if tok != "" && strings.IndexFunc(tok, func(r rune) bool { return r < '0' || r > '9' }) < 0 {
					return tok
				}
				return ""
			}
		}
	}
	return ""
}
