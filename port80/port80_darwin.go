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

// renderPFAnchor is the rdr ruleset for the sub-anchor: one rule per
// (alias × public port), redirecting each alias IP's public ports to the
// service's single unprivileged port. The redirect target is the alias IP
// itself (port translation only), NOT 127.0.0.1: a packet that arrives on a
// physical interface and is redirected to a loopback address is dropped by
// macOS as a martian, so loopback works only for host-local traffic. Keeping
// the destination on the alias IP (which a 0.0.0.0-bound server also accepts)
// delivers LAN traffic correctly. Rules are emitted aliases-outer,
// ports-inner for a stable order. Pure for testing.
func renderPFAnchor(o *Options) string {
	var b strings.Builder
	for _, a := range o.Aliases {
		for _, p := range o.Ports {
			fmt.Fprintf(&b, "rdr pass on %s inet proto tcp from any to %s port %d -> %s port %d\n",
				a.Iface, a.AliasIP, p, a.AliasIP, o.ToPort)
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

// verifyUp checks the three legs a working binding stands on: the alias IPs
// exist, the sub-anchor still holds redirect rules, and pf is enabled.
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
	return nil
}

// reapply converges the system to the recorded state in place: absent aliases
// are re-added, the sub-anchor is reloaded (idempotent — loading replaces its
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
