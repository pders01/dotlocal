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

// run executes a command and folds combined output into the error so failures
// are diagnosable without a separate logging path.
func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
