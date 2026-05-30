// Package port80 makes a service reachable at http://<name>.local on the
// standard HTTP port (80) without binding a privileged port and without
// colliding with any server the host already runs on port 80.
//
// It works at the network layer rather than in the web server:
//
//  1. A dedicated alias IP is added to a LAN interface (one per LAN), giving
//     the service its own address on the segment, distinct from the host's.
//  2. A firewall redirect (pf on macOS, nftables on Linux) rewrites that alias
//     IP's port 80 to the service's unprivileged port in the kernel
//     PREROUTING/rdr path — before the socket lookup, so it works even when the
//     host already binds 0.0.0.0:80, and never touches the host's own :80.
//
// Advertise the alias IPs over mDNS (see dotlocal/mdns.AdvertiseScoped) so
// <name>.local resolves to the redirect target on whichever LAN a client is on.
//
// Up/Down need root (interface + firewall changes); they are meant for a
// privileged CLI step separate from running the unprivileged server. State is
// recorded under ~/.<name>/port80.json so Down reverses the exact change. The
// binding is not reboot-persistent; re-run Up after a reboot.
package port80

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// Alias is one dedicated IP to give the service on a specific interface — one
// per LAN, so port 80 can be reached as <name>.local on each.
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
	Port    int     `json:"port"`    // public port to redirect from; default 80
	ToPort  int     `json:"to_port"` // the service's unprivileged port; default 8080
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
	for i := range ifaces {
		ifi := ifaces[i]
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.Contains(ip) {
				return ifi.Name, nil
			}
		}
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
	for i := range o.Aliases {
		if o.Aliases[i].Prefix == 0 {
			o.Aliases[i].Prefix = 24
		}
		if o.Aliases[i].Mask == "" {
			o.Aliases[i].Mask = "255.255.255.0"
		}
	}
}

func (o *Options) validate() error {
	if o.Name == "" {
		return fmt.Errorf("Name is required")
	}
	if len(o.Aliases) == 0 {
		return fmt.Errorf("at least one alias IP is required")
	}
	for _, a := range o.Aliases {
		if a.Iface == "" {
			return fmt.Errorf("alias %s has no interface", a.AliasIP)
		}
		if ip := net.ParseIP(a.AliasIP); ip == nil || ip.To4() == nil {
			return fmt.Errorf("%q is not a valid IPv4 address", a.AliasIP)
		}
	}
	if o.Port < 1 || o.Port > 65535 || o.ToPort < 1 || o.ToPort > 65535 {
		return fmt.Errorf("ports must be 1–65535 (got port=%d to-port=%d)", o.Port, o.ToPort)
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
	if err := applyDown(st); err != nil {
		return st, err
	}
	if err := clearState(name); err != nil {
		return st, fmt.Errorf("removing state file: %w", err)
	}
	return st, nil
}

// Status returns the active binding for name, or ErrNoBinding if none.
func Status(name string) (*State, error) { return loadState(name) }

func requireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root")
	}
	return nil
}

func statePath(name string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "."+name, "port80.json"), nil
}

func saveState(s *State) error {
	p, err := statePath(s.Name)
	if err != nil {
		return err
	}
	if mkErr := os.MkdirAll(filepath.Dir(p), 0o755); mkErr != nil {
		return mkErr
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o644)
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
