//go:build linux || darwin

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// run executes a system command, folding its output into the error so a
// failure is diagnosable from the log line alone.
func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
