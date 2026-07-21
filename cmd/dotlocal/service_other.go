//go:build !linux && !darwin

package main

import (
	"errors"
	"time"

	"github.com/pders01/dotlocal/port80"
)

func serviceInstall(_ *bindingFlags, _ *port80.Options, _ time.Duration) error {
	return errors.New("dotlocal service is only supported on Linux and macOS")
}

func serviceUninstall(_ string) error {
	return errors.New("dotlocal service is only supported on Linux and macOS")
}
