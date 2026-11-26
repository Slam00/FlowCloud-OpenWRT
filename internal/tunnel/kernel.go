// Package tunnel drives the kernel AmneziaWG interface of a WARP tunnel and
// checks that tunnels pass traffic.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"flowcloud-openwrt/internal/netx"
	"flowcloud-openwrt/internal/system"
	"flowcloud-openwrt/internal/warp"
)

// MTU fits WARP over mobile and PPPoE uplinks.
const MTU = 1280

// Kernel is a WARP tunnel carried by kmod-amneziawg.
type Kernel struct {
	Device  string
	KeyFile string
}

// Supported reports whether the kernel can create AmneziaWG interfaces.
func Supported() bool {
	_, err := system.Run("awg", "--version")
	if err != nil {
		return false
	}
	probe := "fcprobe0"
	if _, err := system.Run("ip", "link", "add", "dev", probe, "type", "amneziawg"); err != nil {
		return false
	}
	_, _ = system.Run("ip", "link", "del", "dev", probe)
	return true
}

// Ensure creates and configures the device for the account. The device
// marks its encrypted packets as direct so they never re-enter a tunnel.
func (k *Kernel) Ensure(peer *warp.Peer) error {
	if !system.LinkExists(k.Device) {
		if _, err := system.Run("ip", "link", "add", "dev", k.Device, "type", "amneziawg"); err != nil {
			return err
		}
	}
	if _, err := system.Run("ip", "link", "set", "dev", k.Device, "mtu", fmt.Sprint(MTU)); err != nil {
		return err
	}
	if _, err := system.Run("ip", "address", "replace", peer.AddressV4.String()+"/32", "dev", k.Device); err != nil {
		return err
	}
	if _, err := system.Run("awg", "set", k.Device, "private-key", k.KeyFile, "fwmark", fmt.Sprintf("0x%x", netx.MarkDirect)); err != nil {
		return err
	}
	_, err := system.Run("ip", "link", "set", "dev", k.Device, "up")
	return err
}

// Apply switches the device to the selected endpoint and profile without
// taking it down. The peer is removed first: a kept peer would go on sending
// with its old session, which the new endpoint does not know, and WireGuard
// would only start a fresh handshake after about 15 silent seconds.
//
// Every apply also moves the device to a new random UDP source port. The
// ISP's DPI blocks a flow "source port -> endpoint" it once flagged: the
// handshake still gets through, the data does not, and a new handshake on
// the same port does not help (seen on the test router). Selection probes
// always use fresh ports, so without this the probes pass and the tunnel
// on its long-lived port fails.
func (k *Kernel) Apply(peer *warp.Peer, selection warp.Selection, publicKey string) error {
	_, _ = system.Run("awg", "set", k.Device, "peer", publicKey, "remove")
	args := []string{"set", k.Device, "listen-port", "0"}
	args = append(args, selection.Profile.AWGArgs()...)
	args = append(args, "peer", publicKey, "endpoint", selection.Endpoint,
		"allowed-ips", "0.0.0.0/0", "persistent-keepalive", "25")
	_, err := system.Run("awg", args...)
	return err
}

// Remove deletes the device.
func (k *Kernel) Remove() {
	if system.LinkExists(k.Device) {
		_, _ = system.Run("ip", "link", "del", "dev", k.Device)
	}
}

// Endpoints returns the peer endpoints of a WireGuard/AmneziaWG device, so
// they can bypass routing. Other devices return nothing.
func Endpoints(device string) []string {
	var output string
	var err error
	for _, tool := range []string{"awg", "wg"} {
		output, err = system.Run(tool, "show", device, "endpoints")
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil
	}
	var endpoints []string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] != "(none)" {
			endpoints = append(endpoints, fields[1])
		}
	}
	return endpoints
}

// pingTarget answers a plain HTTP request from the same Cloudflare edge as
// the WARP endpoint.
const pingTarget = "1.1.1.1:80"

// pingRequest is a HEAD the edge answers with a redirect of a few hundred
// bytes.
const pingRequest = "HEAD / HTTP/1.1\r\nHost: 1.1.1.1\r\nUser-Agent: flowcloud\r\nConnection: close\r\n\r\n"

// Ping checks the tunnel with this mark and returns the round trip of its
// TCP handshake. A handshake alone is not proof: a WARP endpoint has been
// seen completing TCP handshakes while no reply with data came back (found
// by WindseekerTunnel), so Ping also sends a request and waits for the
// start of the response.
func Ping(ctx context.Context, mark uint32, timeout time.Duration) (time.Duration, error) {
	pingContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := netx.MarkedDialer(mark, timeout)
	started := time.Now()
	connection, err := dialer.DialContext(pingContext, "tcp4", pingTarget)
	if err != nil {
		return 0, err
	}
	defer connection.Close()
	elapsed := time.Since(started)
	if deadline, ok := pingContext.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if _, err := io.WriteString(connection, pingRequest); err != nil {
		return 0, fmt.Errorf("send through tunnel: %w", err)
	}
	reply := make([]byte, 8)
	if _, err := io.ReadFull(connection, reply); err != nil {
		return 0, fmt.Errorf("no data through tunnel: %w", err)
	}
	if !strings.HasPrefix(string(reply), "HTTP/1.") {
		return 0, errors.New("unexpected reply through tunnel")
	}
	return elapsed, nil
}
