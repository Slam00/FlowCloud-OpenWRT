// Package netx holds the socket helpers the daemon needs on OpenWrt.
package netx

import (
	"context"
	"net"
	"net/http"
	"syscall"
	"time"
)

// Marks the daemon owns: four bits of the packet mark. 0x01-0x0d select a
// tunnel, MarkDirect keeps a packet on the main routing table and out of
// every section (it has no ip rule of its own).
const (
	MarkMask   uint32 = 0x0f000000
	MarkShift         = 24
	MarkDirect uint32 = 0x0e000000
)

// TunnelMark returns the fwmark of the tunnel with this 1-based index.
func TunnelMark(index int) uint32 {
	return uint32(index) << MarkShift
}

// MarkedDialer returns a dialer whose sockets carry mark. Mark 0 leaves
// sockets unmarked.
func MarkedDialer(mark uint32, timeout time.Duration) *net.Dialer {
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	if mark != 0 {
		dialer.Control = func(_, _ string, raw syscall.RawConn) error {
			var controlErr error
			err := raw.Control(func(fd uintptr) {
				controlErr = setMark(int(fd), mark)
			})
			if err != nil {
				return err
			}
			return controlErr
		}
	}
	return dialer
}

// DirectHTTPClient never goes through a tunnel, so list downloads and WARP
// registration work while tunnels are down or fail closed.
func DirectHTTPClient(timeout time.Duration) *http.Client {
	dialer := MarkedDialer(MarkDirect, 15*time.Second)
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        4,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: timeout}
}
