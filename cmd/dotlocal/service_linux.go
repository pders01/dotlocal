//go:build linux

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pders01/dotlocal/port80"
)

// The daemon is a systemd system unit: keep needs root for ip/nft, and the
// binding should exist from boot. Install always rewrites the unit and
// restarts it, so re-running install is also the repair/upgrade procedure.

func serviceUnitName(name string) string { return "dotlocal-" + name + ".service" }

func serviceUnitPath(name string) string {
	return "/etc/systemd/system/" + serviceUnitName(name)
}

func serviceInstall(bf *bindingFlags, _ *port80.Options, interval time.Duration) error {
	if os.Geteuid() != 0 {
		return errors.New("service install must run as root")
	}
	bin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating own binary: %w", err)
	}
	if resolved, rerr := filepath.EvalSymlinks(bin); rerr == nil {
		bin = resolved
	}

	// systemd splits ExecStart on whitespace; every argument here is either
	// charset-validated upstream or (for --info) may contain spaces, which
	// systemd handles with quoting.
	args := make([]string, 0, 16)
	for _, a := range keepArgs(bf, interval) {
		if strings.ContainsAny(a, " \t") {
			a = `"` + a + `"`
		}
		args = append(args, a)
	}
	unit := fmt.Sprintf(`[Unit]
Description=dotlocal keeper for %s.local
After=network.target

[Service]
ExecStart=%s %s
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, bf.name, bin, strings.Join(args, " "))

	path := serviceUnitPath(bf.name)
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := run("systemctl", "enable", "--now", serviceUnitName(bf.name)); err != nil {
		return err
	}
	// enable --now is a no-op for an already-running unit; restart makes a
	// re-install actually pick up the rewritten unit.
	if err := run("systemctl", "restart", serviceUnitName(bf.name)); err != nil {
		return err
	}
	log.Printf("installed %s: keep runs at boot and self-heals every %s", serviceUnitName(bf.name), interval)
	return nil
}

func serviceUninstall(name string) error {
	if os.Geteuid() != 0 {
		return errors.New("service uninstall must run as root")
	}
	_ = run("systemctl", "disable", "--now", serviceUnitName(name))
	if err := os.Remove(serviceUnitPath(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing unit: %w", err)
	}
	_ = run("systemctl", "daemon-reload")
	if _, err := port80.Down(name); err != nil && !errors.Is(err, port80.ErrNoBinding) {
		return fmt.Errorf("removing binding: %w", err)
	}
	log.Printf("uninstalled %s", serviceUnitName(name))
	return nil
}
