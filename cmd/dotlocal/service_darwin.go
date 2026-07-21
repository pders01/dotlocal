//go:build darwin

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

// The daemon is a system LaunchDaemon (not a user agent): keep needs root for
// pfctl/ifconfig, and the binding should exist from boot, not from login.
//
// Install always rewrites the plist and reloads the daemon. A plist that
// embeds an absolute binary path and is written only once outlives the truth
// it captured — the binary moves or the flags change, and the daemon then
// dies with exit 127 on every boot while looking "installed". Regenerating on
// every install makes re-running it the repair procedure.

func serviceLabel(name string) string { return "com.dotlocal." + name }

func servicePlistPath(name string) string {
	return "/Library/LaunchDaemons/" + serviceLabel(name) + ".plist"
}

const serviceLogDir = "/Library/Logs/dotlocal"

func serviceInstall(bf *bindingFlags, _ *port80.Options, interval time.Duration) error {
	if os.Geteuid() != 0 {
		return errors.New("service install must run as root")
	}
	bin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating own binary: %w", err)
	}
	// Resolve symlinks: launchd will exec this path at boot as root, so it
	// should be the real file, not a link that may later dangle.
	if resolved, rerr := filepath.EvalSymlinks(bin); rerr == nil {
		bin = resolved
	}

	label := serviceLabel(bf.name)
	logPath := filepath.Join(serviceLogDir, bf.name+".log")
	if err := os.MkdirAll(serviceLogDir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", serviceLogDir, err)
	}
	plist := renderPlist(label, append([]string{bin}, keepArgs(bf, interval)...), logPath)
	path := servicePlistPath(bf.name)
	if err := os.WriteFile(path, []byte(plist), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}

	// bootout before bootstrap so a re-install picks up the fresh plist; the
	// first install has nothing to boot out, hence best-effort.
	_ = run("launchctl", "bootout", "system/"+label)
	if err := run("launchctl", "bootstrap", "system", path); err != nil {
		return fmt.Errorf("loading daemon: %w", err)
	}
	log.Printf("installed %s: %s keep runs at boot and self-heals every %s (log: %s)",
		label, filepath.Base(bin), interval, logPath)
	return nil
}

func serviceUninstall(name string) error {
	if os.Geteuid() != 0 {
		return errors.New("service uninstall must run as root")
	}
	label := serviceLabel(name)
	_ = run("launchctl", "bootout", "system/"+label)
	if err := os.Remove(servicePlistPath(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing plist: %w", err)
	}
	// The daemon leaves its binding in place by design; uninstall is the
	// explicit teardown, so take it down too.
	if _, err := port80.Down(name); err != nil && !errors.Is(err, port80.ErrNoBinding) {
		return fmt.Errorf("removing binding: %w", err)
	}
	log.Printf("uninstalled %s", label)
	return nil
}

// renderPlist emits the LaunchDaemon definition. Values are XML-escaped:
// everything but --info is charset-validated upstream, but escaping all of
// them means this function has no opinion on which flags are free text.
func renderPlist(label string, programArgs []string, logPath string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>` + xmlEscape(label) + `</string>
    <key>ProgramArguments</key>
    <array>
`)
	for _, a := range programArgs {
		b.WriteString("        <string>" + xmlEscape(a) + "</string>\n")
	}
	b.WriteString(`    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>` + xmlEscape(logPath) + `</string>
    <key>StandardErrorPath</key>
    <string>` + xmlEscape(logPath) + `</string>
</dict>
</plist>
`)
	return b.String()
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
