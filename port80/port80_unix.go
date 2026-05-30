//go:build linux || darwin

package port80

import (
	"fmt"
	"os/exec"
	"strings"
)

// run executes a command and folds combined output into the error so failures
// are diagnosable without a separate logging path.
func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// output runs a command and returns combined stdout+stderr, for callers that
// need to parse a result (e.g. pfctl -E's enable-reference token).
func output(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
