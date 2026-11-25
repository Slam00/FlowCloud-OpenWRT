package daemon

import (
	"context"
	"errors"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"flowcloud-openwrt/internal/config"
	"flowcloud-openwrt/internal/netx"
	"flowcloud-openwrt/internal/route"
	"flowcloud-openwrt/internal/system"
	"flowcloud-openwrt/internal/tunnel"
	"flowcloud-openwrt/internal/warp"
)

const (
	retryDelay      = 30 * time.Second
	selectTimeout   = 90 * time.Second
	pingTimeout     = 4 * time.Second
	failedPings     = 2
	handshakeGrace  = 3 * time.Second
	initialAttempts = 3
)

// warpBypass are the WARP anycast pools: encrypted WARP packets and probes go
// there and must never be routed into a tunnel.
func warpBypass() []netip.Prefix {
	prefixes := warp.Pools()
	prefixes = append(prefixes,
		netip.MustParsePrefix("162.159.192.0/22"),
		netip.MustParsePrefix("188.114.96.0/21"),
	)
	return prefixes
}

func removeWarpDevice(device string) {
	(&tunnel.Kernel{Device: device}).Remove()
}

func sleep(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (d *Daemon) tunnelDown(t *config.Tunnel, state, message string) {
	if t.FailClosed {
		_ = route.FailClosedOnly(t.Index)
	} else {
		route.Clear(t.Index)
	}
	d.board.tunnel(t.Name, func(status *TunnelStatus) {
		status.State = state
		status.Error = message
		status.PingMs = -1
	})
}

// loadOrRegister returns the stored WARP account or registers a new one.
func (d *Daemon) loadOrRegister(ctx context.Context, t *config.Tunnel, path string) (*warp.Account, error) {
	account, err := warp.LoadAccount(path)
	if err == nil {
		return account, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		log.Printf("tunnel %s: stored account unusable (%v); registering a new one", t.Name, err)
	}
	d.board.tunnel(t.Name, func(status *TunnelStatus) { status.State = "registering" })
	registerContext, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	account, err = warp.Register(registerContext)
	if err != nil {
		return nil, err
	}
	if err := warp.SaveAccount(path, account); err != nil {
		return nil, err
	}
	log.Printf("tunnel %s: WARP device registered", t.Name)
	return account, nil
}

func writeKeyFile(path, key string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(key+"\n"), 0o600)
}

// runWarp keeps a WARP tunnel on a working endpoint: it selects one in
// userspace, applies it to the kernel device, checks it every health
// interval and selects a new one when two pings in a row fail.
func (d *Daemon) runWarp(ctx context.Context, t *config.Tunnel) {
	directory := filepath.Join(d.opts.StateDir, "warp")
	accountPath := filepath.Join(directory, t.Name+".json")
	keyPath := filepath.Join(directory, t.Name+".key")
	cache := warp.NewEndpointCache(filepath.Join(directory, t.Name+"-endpoints.json"))
	kernel := &tunnel.Kernel{Device: t.Device, KeyFile: keyPath}
	mark := netx.TunnelMark(t.Index)
	d.tunnelDown(t, "starting", "")

	if !tunnel.Supported() {
		d.tunnelDown(t, "error", "kmod-amneziawg and amneziawg-tools are required for WARP tunnels")
		return
	}

	var account *warp.Account
	var peer *warp.Peer
	for ctx.Err() == nil {
		var err error
		account, err = d.loadOrRegister(ctx, t, accountPath)
		if err == nil {
			peer, err = account.Peer()
		}
		if err == nil {
			err = writeKeyFile(keyPath, account.PrivateKey)
		}
		if err == nil {
			err = kernel.Ensure(peer)
		}
		if err == nil {
			break
		}
		log.Printf("tunnel %s: %v", t.Name, err)
		d.tunnelDown(t, "error", err.Error())
		if !sleep(ctx, retryDelay) {
			return
		}
	}

	for ctx.Err() == nil {
		d.board.tunnel(t.Name, func(status *TunnelStatus) { status.State = "selecting"; status.Error = "" })
		selectContext, cancel := context.WithTimeout(ctx, selectTimeout)
		selection, err := warp.Select(selectContext, peer, cache, t.ProbeParallel, netx.MarkDirect)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("tunnel %s: %v", t.Name, err)
			d.tunnelDown(t, "down", err.Error())
			if !sleep(ctx, retryDelay) {
				return
			}
			continue
		}
		if err := kernel.Apply(peer, selection, account.PeerPublicKey); err == nil {
			err = route.SetDevice(t.Index, t.Device, t.FailClosed)
		} else {
			log.Printf("tunnel %s: apply %s: %v", t.Name, selection.Endpoint, err)
			d.tunnelDown(t, "error", err.Error())
			if !sleep(ctx, retryDelay) {
				return
			}
			continue
		}
		log.Printf("tunnel %s: endpoint %s [%s %s] selected in %s", t.Name, selection.Endpoint, selection.Source, selection.Profile.Name, selection.Latency.Round(time.Millisecond))
		d.board.tunnel(t.Name, func(status *TunnelStatus) {
			status.State = "up"
			status.Endpoint = selection.Endpoint
			status.Profile = selection.Profile.String()
			status.Source = selection.Source
			status.Switches++
			status.Error = ""
		})
		if !d.watch(ctx, t, mark, true) {
			return
		}
		cache.Forget(selection.Endpoint)
		log.Printf("tunnel %s: endpoint %s stopped passing traffic; selecting a new one", t.Name, selection.Endpoint)
	}
}

// watch pings through the tunnel until it fails (returns true) or ctx ends
// (returns false). A fresh WARP endpoint gets a few attempts for its first
// handshake.
func (d *Daemon) watch(ctx context.Context, t *config.Tunnel, mark uint32, fresh bool) bool {
	failures := 0
	attempts := failedPings
	if fresh {
		attempts = initialAttempts
		if !sleep(ctx, handshakeGrace) {
			return false
		}
	}
	for {
		rtt, err := tunnel.Ping(ctx, mark, pingTimeout)
		if ctx.Err() != nil {
			return false
		}
		if err == nil {
			failures = 0
			attempts = failedPings
			d.board.tunnel(t.Name, func(status *TunnelStatus) {
				status.State = "up"
				status.PingMs = rtt.Milliseconds()
				if status.PingMs == 0 {
					status.PingMs = 1
				}
				status.CheckedAt = time.Now().Unix()
				status.Error = ""
			})
			if !sleep(ctx, t.HealthInterval) {
				return false
			}
			continue
		}
		failures++
		d.board.tunnel(t.Name, func(status *TunnelStatus) {
			status.PingMs = -1
			status.CheckedAt = time.Now().Unix()
			status.Error = err.Error()
		})
		if failures >= attempts {
			return true
		}
		if !sleep(ctx, 2*time.Second) {
			return false
		}
	}
}

// runInterface follows an existing netifd interface (AmneziaWG, WireGuard,
// OpenVPN...): it points the tunnel's table at its device while it is up and
// keeps its peer endpoints out of the routed sets.
func (d *Daemon) runInterface(ctx context.Context, t *config.Tunnel) {
	mark := netx.TunnelMark(t.Index)
	for ctx.Err() == nil {
		device, up, err := system.InterfaceDevice(t.Device)
		switch {
		case err != nil:
			d.tunnelDown(t, "error", "interface "+t.Device+": "+err.Error())
		case !up || device == "":
			d.tunnelDown(t, "down", "interface "+t.Device+" is down")
		default:
			d.setBypass(t.Name, endpointPrefixes(tunnel.Endpoints(device)))
			if err := route.SetDevice(t.Index, device, t.FailClosed); err != nil {
				d.tunnelDown(t, "error", err.Error())
				break
			}
			rtt, pingErr := tunnel.Ping(ctx, mark, pingTimeout)
			d.board.tunnel(t.Name, func(status *TunnelStatus) {
				status.State = "up"
				status.Endpoint = device
				status.CheckedAt = time.Now().Unix()
				if pingErr != nil {
					status.PingMs = -1
					status.Error = pingErr.Error()
				} else {
					status.PingMs = rtt.Milliseconds()
					if status.PingMs == 0 {
						status.PingMs = 1
					}
					status.Error = ""
				}
			})
		}
		if !sleep(ctx, t.HealthInterval) {
			return
		}
	}
}
