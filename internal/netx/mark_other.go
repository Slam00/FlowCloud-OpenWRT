//go:build !linux

package netx

// Development builds on other systems ignore marks.
func setMark(int, uint32) error { return nil }
