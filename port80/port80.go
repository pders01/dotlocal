// Package port80 makes a service reachable at http://<name>.local on one or
// more standard public ports (80 by default, optionally 443 as well) without
// binding a privileged port and without colliding with any server the host
// already runs on those ports.
//
// It works at the network layer rather than in the web server:
//
//  1. A dedicated alias IP is added to a LAN interface (one per LAN), giving
//     the service its own address on the segment, distinct from the host's.
//  2. A firewall redirect (pf on macOS, nftables on Linux) rewrites each of
//     that alias IP's public ports to the service's single unprivileged port in
//     the kernel PREROUTING/rdr path — before the socket lookup, so it works
//     even when the host already binds 0.0.0.0:80, and never touches the host's
//     own public ports.
//
// Advertise the alias IPs over mDNS (see dotlocal/mdns.AdvertiseScoped) so
// <name>.local resolves to the redirect target on whichever LAN a client is on.
//
// Up/Down need root (interface + firewall changes); they are meant for a
// privileged CLI step separate from running the unprivileged server. State is
// recorded under the root-owned /var/run/dotlocal/<name>.json so Down reverses
// the exact change. The binding is not reboot-persistent; re-run Up after a
// reboot.
package port80

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/pders01/dotlocal/internal/lan"
)

// Alias is one dedicated IP to give the service on a specific interface — one
// per LAN, so the public ports can be reached as <name>.local on each.
type Alias struct {
	Iface   string `json:"iface"`    // LAN interface, e.g. "en0" (macOS) or "eth0" (Linux)
	AliasIP string `json:"alias_ip"` // dedicated IP to add on that interface
	Prefix  int    `json:"prefix"`   // CIDR prefix length (Linux); default 24
	Mask    string `json:"mask"`     // dotted netmask (macOS); default 255.255.255.0
}

// Options describes a requested binding. Zero numeric fields take defaults.
type Options struct {
	Name    string  `json:"name"`    // identifies the firewall anchor/table and state file
	Aliases []Alias `json:"aliases"` // one or more dedicated alias IPs, one per LAN
	Port    int     `json:"port"`    // public port to redirect from; default 80. Kept for back-compat; equals Ports[0] after applyDefaults
	Ports   []int   `json:"ports"`   // set of public ports to redirect onto ToPort; defaults to {Port}
	ToPort  int     `json:"to_port"` // the service's single unprivileged port; default 8080
}

// State is the persisted record of an applied Up, enough to reverse it.
type State struct {
	Options
	Backend string `json:"backend"`            // "pf" or "nftables"
	PFToken string `json:"pf_token,omitempty"` // macOS: pfctl -E enable-reference token
}

// ErrNoBinding is returned by Down/Status when no active binding is recorded.
var ErrNoBinding = errors.New("no active port80 binding")

// ErrUnsupported is returned on platforms without a backend.
var ErrUnsupported = errors.New("port80 is only supported on Linux and macOS")

// Supported reports whether this platform has a backend.
func Supported() bool { return supported }

// DetectIface returns the up, non-loopback interface whose subnet contains
// aliasIP. The alias IP already encodes its target subnet, so callers can
// derive the interface rather than require it — and the match is exact, not a
// default-route guess that breaks on a multi-homed host.
func DetectIface(aliasIP string) (string, error) {
	ip := net.ParseIP(aliasIP)
	if ip == nil {
		return "", fmt.Errorf("%q is not a valid IP", aliasIP)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	if ifn := lan.InterfaceForIP(ifaces, ip); ifn != "" {
		return ifn, nil
	}
	return "", fmt.Errorf("no active interface has a subnet containing %s", aliasIP)
}

func (o *Options) applyDefaults() {
	if o.Port == 0 {
		o.Port = 80
	}
	if o.ToPort == 0 {
		o.ToPort = 8080
	}
	// Default the port set from the single Port for back-compat, then de-dup
	// while preserving order. Keep Port == Ports[0] so any reader still using
	// the scalar field sees a consistent value.
	if len(o.Ports) == 0 {
		o.Ports = []int{o.Port}
	}
	seen := make(map[int]struct{}, len(o.Ports))
	deduped := o.Ports[:0]
	for _, p := range o.Ports {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		deduped = append(deduped, p)
	}
	o.Ports = deduped
	o.Port = o.Ports[0]
	for i := range o.Aliases {
		if o.Aliases[i].Prefix == 0 {
			o.Aliases[i].Prefix = 24
		}
		if o.Aliases[i].Mask == "" {
			o.Aliases[i].Mask = "255.255.255.0"
		}
	}
}

// isToken reports whether s is non-empty and made only of [A-Za-z0-9] plus the
// runes in extra. It rejects whitespace, path separators, and shell/pf-rule
// metacharacters — important because these values run as root command
// arguments, are interpolated into a pf ruleset, and (Name) become a
// filesystem path. Keeping them to a strict charset closes argument/rule
// injection and path traversal at the source.
func isToken(s, extra string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune(extra, r):
		default:
			return false
		}
	}
	return true
}

func (o *Options) validate() error {
	// Name becomes the <name>.local host, an nftables table, a pf anchor
	// segment, and a state-file path. A valid DNS label satisfies all of them at
	// once (and is a strict subset of the path/shell-safe charset), so it is the
	// single rule rather than a per-package variant.
	if !lan.ValidLabel(o.Name) {
		return fmt.Errorf("Name %q must be a DNS label (1–63 letters/digits/hyphens, no leading or trailing hyphen)", o.Name)
	}
	if len(o.Aliases) == 0 {
		return fmt.Errorf("at least one alias IP is required")
	}
	for _, a := range o.Aliases {
		// Iface is interpolated into the pf ruleset fed to `pfctl -f -`, so a
		// newline or space would let it inject rules; restrict to real
		// interface-name characters.
		if !isToken(a.Iface, "._:-") {
			return fmt.Errorf("interface %q is not a valid interface name", a.Iface)
		}
		if ip := net.ParseIP(a.AliasIP); ip == nil || ip.To4() == nil {
			return fmt.Errorf("%q is not a valid IPv4 address", a.AliasIP)
		}
		if a.Prefix < 1 || a.Prefix > 32 {
			return fmt.Errorf("prefix for %s must be 1–32 (got %d)", a.AliasIP, a.Prefix)
		}
		maskIP := net.ParseIP(a.Mask)
		if maskIP == nil || maskIP.To4() == nil {
			return fmt.Errorf("mask %q for %s is not a valid IPv4 address", a.Mask, a.AliasIP)
		}
		// Reject non-contiguous masks (e.g. 255.0.255.0): Size() returns
		// (0, 0) for a non-canonical mask, (ones, 32) for a valid one.
		if _, bits := net.IPMask(maskIP.To4()).Size(); bits != 32 {
			return fmt.Errorf("mask %q for %s is not a contiguous netmask", a.Mask, a.AliasIP)
		}
	}
	// Validate the effective public-port set. validate may run before
	// applyDefaults (e.g. on freshly built Options), so fall back to the scalar
	// Port when Ports is empty — applyDefaults derives Ports from it anyway.
	ports := o.Ports
	if len(ports) == 0 {
		ports = []int{o.Port}
	}
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("public ports must be 1–65535 (got %d)", p)
		}
	}
	// Port is a back-compat shadow of Ports[0]; reject a state where the two
	// disagree (e.g. a hand-edited file) so the scalar a legacy reader trusts
	// can never lie. applyDefaults keeps them in sync; this guards a State
	// loaded straight from disk in Down.
	if len(o.Ports) > 0 && o.Port != 0 && o.Port != o.Ports[0] {
		return fmt.Errorf("Port %d must equal Ports[0]=%d", o.Port, o.Ports[0])
	}
	if o.ToPort < 1 || o.ToPort > 65535 {
		return fmt.Errorf("to-port must be 1–65535 (got %d)", o.ToPort)
	}
	return nil
}

// Up adds the alias IPs and installs the redirects, recording state so Down
// can reverse it. It requires root.
func Up(o Options) (*State, error) {
	if !supported {
		return nil, ErrUnsupported
	}
	o.applyDefaults()
	if err := o.validate(); err != nil {
		return nil, err
	}
	if err := requireRoot(); err != nil {
		return nil, err
	}
	if existing, _ := loadState(o.Name); existing != nil {
		return nil, fmt.Errorf("a binding named %q is already active (%d alias(es)); run Down first",
			o.Name, len(existing.Aliases))
	}
	st, err := applyUp(&o)
	if err != nil {
		return nil, err
	}
	if err := saveState(st); err != nil {
		_ = applyDown(st) // best-effort rollback so we don't leave an untracked rule
		return nil, fmt.Errorf("recording state: %w", err)
	}
	return st, nil
}

// Down reverses the recorded binding for name and clears its state. Root only.
func Down(name string) (*State, error) {
	if !supported {
		return nil, ErrUnsupported
	}
	if err := requireRoot(); err != nil {
		return nil, err
	}
	st, err := loadState(name)
	if err != nil {
		return nil, err
	}
	// Defence in depth: the state file's values become root command arguments
	// below, so reject a tampered/garbage file rather than feeding it to
	// ifconfig/ip/nft.
	if verr := st.Options.validate(); verr != nil {
		return nil, fmt.Errorf("refusing to act on invalid state %s: %w", name, verr)
	}
	// PFToken (macOS) becomes a `pfctl -X <token>` argument; it is a decimal
	// reference token, so reject anything non-alphanumeric from the file.
	if st.PFToken != "" && !isToken(st.PFToken, "") {
		return nil, fmt.Errorf("refusing to act on invalid pf token in state %s", name)
	}
	applyErr := applyDown(st)
	// Always clear the recorded state, even if teardown reported a non-fatal
	// error (e.g. pf was reloaded out from under us and the enable token is
	// stale). Otherwise the binding looks "active" forever and Up refuses to
	// run — leaving no way to recover without deleting the file by hand.
	if err := clearState(name); err != nil {
		return st, fmt.Errorf("removing state file: %w", err)
	}
	return st, applyErr
}

// Status returns the active binding for name, or ErrNoBinding if none.
func Status(name string) (*State, error) { return loadState(name) }

func requireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root")
	}
	return nil
}

// stateDir is a root-owned system directory, deliberately NOT the invoking
// user's $HOME: under sudo, $HOME stays user-owned, so writing root state there
// is a TOCTOU/tamper vector (a local user could pre-seed or swap the file that
// Down later feeds to root commands). /var/run is root-owned and cleared on
// reboot — which matches port80's non-persistent binding.
// stateDir is a var only so tests can redirect it to a temp dir; production
// never reassigns it.
var stateDir = "/var/run/dotlocal"

func statePath(name string) (string, error) {
	// Guard here too: name reaches statePath via Down/Status without going
	// through validate(), and it becomes a filesystem path.
	if !isToken(name, "_-") {
		return "", fmt.Errorf("invalid name %q", name)
	}
	return filepath.Join(stateDir, name+".json"), nil
}

func saveState(s *State) error {
	p, err := statePath(s.Name)
	if err != nil {
		return err
	}
	if mkErr := os.MkdirAll(filepath.Dir(p), 0o700); mkErr != nil {
		return mkErr
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}

func loadState(name string) (*State, error) {
	p, err := statePath(name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoBinding
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", p, err)
	}
	return &s, nil
}

func clearState(name string) error {
	p, err := statePath(name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
