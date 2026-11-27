//go:build !linux

package opera

import (
	"context"
	"errors"
	"net/netip"
)

// Transparent needs Linux (SO_ORIGINAL_DST); elsewhere it only builds.
type Transparent struct {
	Port   int
	Client *Client
	Name   string
	Route  func(host string, ip netip.Addr) Route
}

// Serve reports that the platform has no transparent proxy.
func (t *Transparent) Serve(context.Context) error {
	return errors.New("transparent proxy needs Linux")
}
