//go:build linux || darwin

package port80

import (
	"fmt"
	"os/exec"
	"strings"
)

// isAbsentAddr reports whether err is the "address already gone" failure from
// removing an alias that isn't there (macOS: "Can't assign requested address";
// Linux: "Cannot assign requested address"). Teardown is idempotent, so this
// is success, not a failure to surface.
func isAbsentAddr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "assign requested address")
}

// output runs a command and returns combined stdout+stderr, folding a failure
// into the error so it is diagnosable without a separate logging path. Callers
// that need the output (e.g. parsing pfctl -E's enable token) use it directly.
func output(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// run executes a command, discarding the output and surfacing only the error.
func run(name string, args ...string) error {
	_, err := output(name, args...)
	return err
}
