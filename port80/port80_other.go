//go:build !linux && !darwin

package port80

const supported = false

func applyUp(_ *Options) (*State, error) { return nil, ErrUnsupported }

func applyDown(_ *State) error { return ErrUnsupported }

func verifyUp(_ *State) error { return ErrUnsupported }

func reapply(_ *State) error { return ErrUnsupported }
