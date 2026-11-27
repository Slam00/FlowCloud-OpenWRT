//go:build !linux

package opera

import (
	"context"
	"errors"
)

// Transparent needs Linux (SO_ORIGINAL_DST); elsewhere it only builds.
type Transparent struct {
	Port   int
	Client *Client
	Name   string
}

// Serve reports that the platform has no transparent proxy.
func (t *Transparent) Serve(context.Context) error {
	return errors.New("transparent proxy needs Linux")
}
