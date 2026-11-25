package daemon

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"flowcloud-openwrt/internal/config"
	"flowcloud-openwrt/internal/netx"
	"flowcloud-openwrt/internal/nft"
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

// The bypass set holds only the endpoints tunnels currently use. The WARP
// pools themselves must not be bypassed: Cloudflare serves ordinary sites
// (chatgpt.com, ...) from the same /24s. Encrypted WARP packets and probe
// sockets carry the direct mark, so they cannot loop anyway.

// lowMemoryParallel is the default number of parallel WARP probes on routers
// with little RAM: every probe holds a userspace network stack.
const (
	lowMemoryParallel  = 4
	highMemoryParallel = 8
	lowMemoryKB        = 300 * 1024
)

func defaultProbeParallel() int {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return lowMemoryParallel
	}
	var totalKB int
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				totalKB, _ = strconv.Atoi(fields[1])
			}
			break
		}
	}
	if totalKB > 0 && totalKB < lowMemoryKB {
		return lowMemoryParallel
	}
	return highMemoryParallel
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
			err = nft.SetReplyMSS(mark, tunnel.MTU)
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

	// Probes use a second WARP device. With the tunnel's own key every probe
	// handshake would look to Cloudflare like the peer roaming to the probe's
	// address, and the kernel tunnel would lose its answers.
	var probePeer *warp.Peer
	for ctx.Err() == nil {
		probeAccount, err := d.loadOrRegister(ctx, t, filepath.Join(directory, t.Name+"-probe.json"))
		if err == nil {
			probePeer, err = probeAccount.Peer()
		}
		if err == nil {
			break
		}
		log.Printf("tunnel %s: probe device: %v", t.Name, err)
		d.tunnelDown(t, "error", "probe device: "+err.Error())
		if !sleep(ctx, retryDelay) {
			return
		}
	}
	if probePeer == nil {
		return
	}

	limits := qualityLimits{MaxPingMs: t.MaxPingMs, MaxLossPct: t.MaxLossPct}
	parallel := t.ProbeParallel
	if parallel == 0 {
		parallel = defaultProbeParallel()
	}
	selectBest := func(exclude string) (warp.Selection, error) {
		selectContext, cancel := context.WithTimeout(ctx, selectTimeout)
		selection, err := warp.Select(selectContext, probePeer, cache, parallel, netx.MarkDirect, exclude)
		cancel()
		// Return the probes' memory before the tunnel settles down.
		debug.FreeOSMemory()
		return selection, err
	}
	apply := func(selection warp.Selection, reason string) error {
		if err := kernel.Apply(peer, selection, account.PeerPublicKey); err != nil {
			return err
		}
		d.setBypass(t.Name, endpointPrefixes([]string{selection.Endpoint}))
		if err := route.SetDevice(t.Index, t.Device, t.FailClosed); err != nil {
			return err
		}
		log.Printf("tunnel %s: endpoint %s [%s %s] selected in %s, %s through it%s", t.Name, selection.Endpoint,
			selection.Source, selection.Profile.Name, selection.Latency.Round(time.Millisecond),
			selection.RTT.Round(time.Millisecond), reason)
		d.board.tunnel(t.Name, func(status *TunnelStatus) {
			status.State = "up"
			status.Endpoint = selection.Endpoint
			status.Profile = selection.Profile.String()
			status.Source = selection.Source
			status.Switches++
			status.Error = ""
			status.MedianMs = -1
			status.LossPct = 0
		})
		return nil
	}

	switchRequests, unregister := d.switchChannel(t.Name)
	defer unregister()

	var lastQualityCheck time.Time
	for ctx.Err() == nil {
		d.board.tunnel(t.Name, func(status *TunnelStatus) { status.State = "selecting"; status.Error = "" })
		selection, err := selectBest("")
		if err == nil {
			err = apply(selection, "")
		}
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

		fresh := true
		var window qualityWindow
		for {
			result := d.watch(ctx, t, mark, fresh, &window, limits, switchRequests)
			fresh = false
			if result == watchStopped {
				return
			}
			if result == watchSwitch {
				// Asked from LuCI: any other working pair, faster or not.
				log.Printf("tunnel %s: switching away from %s on request", t.Name, selection.Endpoint)
				d.board.tunnel(t.Name, func(status *TunnelStatus) { status.Quality = "смена сервера по запросу…" })
				candidate, err := selectBest(selection.Endpoint)
				if err == nil {
					err = apply(candidate, "; on request, was "+selection.Endpoint)
				}
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					log.Printf("tunnel %s: switch on request: %v", t.Name, err)
					d.board.tunnel(t.Name, func(status *TunnelStatus) {
						status.Quality = "смена по запросу не удалась: " + err.Error()
					})
					continue
				}
				d.board.tunnel(t.Name, func(status *TunnelStatus) {
					status.Quality = "сервер сменён по запросу, был " + selection.Endpoint
				})
				selection = candidate
				window.reset()
				fresh = true
				continue
			}
			if result == watchFailed {
				cache.Forget(selection.Endpoint)
				log.Printf("tunnel %s: endpoint %s stopped passing traffic; selecting a new one", t.Name, selection.Endpoint)
				break
			}
			// watchPoor: look for a clearly better pair, at most once per
			// cooldown, while the current endpoint keeps carrying traffic.
			median, loss := window.stats()
			_, reason := limits.poor(median, loss)
			window.reset()
			if time.Since(lastQualityCheck) < qualityCooldown {
				continue
			}
			lastQualityCheck = time.Now()
			log.Printf("tunnel %s: endpoint %s has poor quality (%s); looking for a better one", t.Name, selection.Endpoint, reason)
			d.board.tunnel(t.Name, func(status *TunnelStatus) { status.Quality = "поиск сервера лучше: " + reason })
			candidate, err := selectBest(selection.Endpoint)
			if err != nil || !limits.better(median, loss, candidate.RTT.Milliseconds()) {
				note := "лучше не найдено"
				if err == nil {
					note = fmt.Sprintf("лучший найденный %s: %d мс", candidate.Endpoint, candidate.RTT.Milliseconds())
				}
				log.Printf("tunnel %s: keeping %s (%s)", t.Name, selection.Endpoint, note)
				d.board.tunnel(t.Name, func(status *TunnelStatus) { status.Quality = reason + "; " + note })
				continue
			}
			if err := apply(candidate, "; replaced "+selection.Endpoint+": "+reason); err != nil {
				log.Printf("tunnel %s: apply %s: %v", t.Name, candidate.Endpoint, err)
				d.board.tunnel(t.Name, func(status *TunnelStatus) { status.Quality = reason + "; не удалось переключить" })
				continue
			}
			d.board.tunnel(t.Name, func(status *TunnelStatus) {
				status.Quality = fmt.Sprintf("переключено с %s: %s", selection.Endpoint, reason)
			})
			selection = candidate
			fresh = true
		}
	}
}

type watchResult int

const (
	watchStopped watchResult = iota
	watchFailed
	watchPoor
	watchSwitch
)

// pause waits for delay like sleep and reports watchSwitch when a manual
// switch is requested meanwhile, watchStopped when ctx ends, else -1.
func pause(ctx context.Context, delay time.Duration, switchRequests <-chan struct{}) watchResult {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return watchStopped
	case <-switchRequests:
		return watchSwitch
	case <-timer.C:
		return -1
	}
}

// watch pings through the tunnel every health interval. It returns
// watchFailed after consecutive failed pings (a fresh WARP endpoint gets a few
// attempts for its first handshake), watchPoor when a full quality window
// breaks a limit, watchSwitch on a manual switch request, or watchStopped
// when ctx ends.
func (d *Daemon) watch(ctx context.Context, t *config.Tunnel, mark uint32, fresh bool, window *qualityWindow, limits qualityLimits, switchRequests <-chan struct{}) watchResult {
	failures := 0
	attempts := failedPings
	if fresh {
		attempts = initialAttempts
		if !sleep(ctx, handshakeGrace) {
			return watchStopped
		}
	}
	for {
		rtt, err := tunnel.Ping(ctx, mark, pingTimeout)
		if ctx.Err() != nil {
			return watchStopped
		}
		if err == nil {
			failures = 0
			attempts = failedPings
			ms := rtt.Milliseconds()
			if ms == 0 {
				ms = 1
			}
			window.add(ms)
		} else {
			failures++
			window.add(-1)
		}
		median, loss := window.stats()
		d.board.tunnel(t.Name, func(status *TunnelStatus) {
			status.CheckedAt = time.Now().Unix()
			status.MedianMs = median
			status.LossPct = loss
			if err == nil {
				status.State = "up"
				status.PingMs = rtt.Milliseconds()
				if status.PingMs == 0 {
					status.PingMs = 1
				}
				status.Error = ""
			} else {
				status.PingMs = -1
				status.Error = err.Error()
			}
		})
		if err != nil {
			if failures >= attempts {
				return watchFailed
			}
			if !sleep(ctx, 2*time.Second) {
				return watchStopped
			}
			continue
		}
		if window.full() {
			if poor, _ := limits.poor(median, loss); poor {
				return watchPoor
			}
		}
		if result := pause(ctx, t.HealthInterval, switchRequests); result >= 0 {
			return result
		}
	}
}

// runInterface follows an existing netifd interface (AmneziaWG, WireGuard,
// OpenVPN...): it points the tunnel's table at its device while it is up and
// keeps its peer endpoints out of the routed sets.
func (d *Daemon) runInterface(ctx context.Context, t *config.Tunnel) {
	mark := netx.TunnelMark(t.Index)
	var lastMTU int
	for ctx.Err() == nil {
		device, up, err := system.InterfaceDevice(t.Device)
		switch {
		case err != nil:
			d.tunnelDown(t, "error", "interface "+t.Device+": "+err.Error())
		case !up || device == "":
			d.tunnelDown(t, "down", "interface "+t.Device+" is down")
		default:
			link, err := net.InterfaceByName(device)
			if err != nil {
				d.tunnelDown(t, "error", err.Error())
				break
			}
			if link.MTU != lastMTU {
				if err := nft.SetReplyMSS(mark, link.MTU); err != nil {
					d.tunnelDown(t, "error", err.Error())
					break
				}
				lastMTU = link.MTU
			}
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
