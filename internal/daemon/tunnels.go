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
	"flowcloud-openwrt/internal/zapret"
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
		selection, err := warp.Select(selectContext, probePeer, cache, warp.Options{
			Parallel:   parallel,
			Fwmark:     netx.MarkDirect,
			Exclude:    exclude,
			TestURLs:   t.TestURLs,
			AvoidColos: t.AvoidColos,
		})
		cancel()
		// Return the probes' memory before the tunnel settles down.
		debug.FreeOSMemory()
		return selection, err
	}
	applyOne := func(selection warp.Selection) error {
		if err := kernel.Apply(peer, selection, account.PeerPublicKey); err != nil {
			return err
		}
		d.setBypass(t.Name, endpointPrefixes([]string{selection.Endpoint}))
		return route.SetDevice(t.Index, t.Device, t.FailClosed)
	}
	announce := func(selection warp.Selection, reason string) {
		sites := ""
		switch {
		case selection.SitesOK < 0:
			sites = ", backup without a site test"
		case selection.SitesTotal > 0:
			sites = fmt.Sprintf(", test sites %d/%d", selection.SitesOK, selection.SitesTotal)
		}
		log.Printf("tunnel %s: endpoint %s [%s %s] exit %s selected in %s, %s through it%s%s", t.Name, selection.Endpoint,
			selection.Source, selection.Profile.Name, orDash(selection.Colo), selection.Latency.Round(time.Millisecond),
			selection.RTT.Round(time.Millisecond), sites, reason)
		d.board.tunnel(t.Name, func(status *TunnelStatus) {
			status.State = "up"
			status.Endpoint = selection.Endpoint
			status.Profile = selection.Profile.String()
			status.Source = selection.Source
			status.Colo = selection.Colo
			status.Sites = nil
			status.Switches++
			status.Error = ""
			status.MedianMs = -1
			status.LossPct = 0
		})
	}

	// connect applies the winner and keeps it if traffic flows within a few
	// seconds. A pair the probe just passed often carries nothing once on
	// the tunnel (the handshake works, the data does not: some flows get
	// blocked on the way), so the alternates from the same round come next,
	// and then the previous pair when it was working. It reports whether it
	// fell back to previous. With nothing working it leaves the winner on
	// the device and lets the health check decide.
	connect := func(selection warp.Selection, reason string, previous *warp.Selection) (warp.Selection, bool, error) {
		tries := append([]warp.Selection{selection}, selection.Alternates...)
		for index, candidate := range tries {
			if err := applyOne(candidate); err != nil {
				return selection, false, err
			}
			if carries(ctx, mark) {
				if index > 0 {
					reason += fmt.Sprintf("; backup %d of the round", index)
				}
				announce(candidate, reason)
				return candidate, false, nil
			}
			if ctx.Err() != nil {
				return selection, false, ctx.Err()
			}
			cache.SitesFailed(candidate.Endpoint)
			log.Printf("tunnel %s: no traffic through %s once applied; trying the next candidate", t.Name, candidate.Endpoint)
		}
		if previous != nil {
			if err := applyOne(*previous); err == nil && carries(ctx, mark) {
				log.Printf("tunnel %s: no candidate carried traffic; back on %s", t.Name, previous.Endpoint)
				d.board.tunnel(t.Name, func(status *TunnelStatus) { status.State = "up"; status.Error = "" })
				return *previous, true, nil
			}
		}
		if err := applyOne(selection); err != nil {
			return selection, false, err
		}
		announce(selection, reason+"; no traffic yet")
		return selection, false, nil
	}
	switchRequests, unregister := d.switchChannel(t.Name)
	defer unregister()

	var lastQualityCheck time.Time
	// reconnects counts flows revived from a new source port.
	reconnects := 0
	for ctx.Err() == nil {
		d.board.tunnel(t.Name, func(status *TunnelStatus) { status.State = "selecting"; status.Error = "" })
		selection, err := selectBest("")
		if err == nil {
			selection, _, err = connect(selection, "", nil)
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
		siteSwitches := 0
		var window qualityWindow
		for {
			checkSites := fresh && len(t.TestURLs) > 0 && siteSwitches < maxSiteSwitches
			result := d.watch(ctx, t, mark, fresh, &window, limits, switchRequests, checkSites)
			fresh = false
			if result == watchStopped {
				return
			}
			if result == watchSites {
				// The probe account opened the test sites through this endpoint,
				// the tunnel's own account does not: its exit may differ.
				siteSwitches++
				cache.SitesFailed(selection.Endpoint)
				if siteSwitches >= maxSiteSwitches {
					log.Printf("tunnel %s: test sites fail through %d endpoints in a row; keeping %s", t.Name, siteSwitches, selection.Endpoint)
					d.board.tunnel(t.Name, func(status *TunnelStatus) {
						status.Quality = fmt.Sprintf("тестовые сайты не открываются через WARP: проверено серверов подряд: %d, оставлен текущий", siteSwitches)
					})
					continue
				}
				log.Printf("tunnel %s: test sites do not open through %s; selecting another endpoint", t.Name, selection.Endpoint)
				d.board.tunnel(t.Name, func(status *TunnelStatus) {
					status.Quality = "тестовые сайты не открываются, подбор другого сервера…"
				})
				candidate, err := selectBest(selection.Endpoint)
				rolledBack := false
				if err == nil {
					candidate, rolledBack, err = connect(candidate, "; test sites failed through "+selection.Endpoint, &selection)
				}
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					log.Printf("tunnel %s: %v", t.Name, err)
					continue
				}
				if rolledBack {
					continue
				}
				selection = candidate
				window.reset()
				fresh = true
				continue
			}
			siteSwitches = 0
			if result == watchSwitch {
				// Asked from LuCI: any other working pair, faster or not.
				log.Printf("tunnel %s: switching away from %s on request", t.Name, selection.Endpoint)
				d.board.tunnel(t.Name, func(status *TunnelStatus) { status.Quality = "смена сервера по запросу…" })
				candidate, err := selectBest(selection.Endpoint)
				rolledBack := false
				if err == nil {
					candidate, rolledBack, err = connect(candidate, "; on request, was "+selection.Endpoint, &selection)
				}
				if err == nil && rolledBack {
					err = errors.New("ни один найденный сервер не пропустил трафик, оставлен прежний")
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
				// A dead flow is usually the DPI cutting this UDP flow (seen
				// after a couple of minutes or a few MB), not a dead endpoint:
				// the same pair from a new source port with a new handshake
				// (Apply does both) works again at once.
				log.Printf("tunnel %s: no traffic through %s; reconnecting from a new source port", t.Name, selection.Endpoint)
				if applyOne(selection) == nil && carries(ctx, mark) {
					reconnects++
					d.board.tunnel(t.Name, func(status *TunnelStatus) {
						status.State = "up"
						status.Error = ""
						status.Reconnects = reconnects
					})
					window.reset()
					continue
				}
				if ctx.Err() != nil {
					return
				}
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
			sitesWorse := err == nil && candidate.SitesOK < candidate.SitesTotal
			if err != nil || sitesWorse || !limits.better(median, loss, candidate.RTT.Milliseconds()) {
				note := "лучше не найдено"
				if sitesWorse {
					note = fmt.Sprintf("у найденного %s открываются не все тестовые сайты", candidate.Endpoint)
				} else if err == nil {
					note = fmt.Sprintf("лучший найденный %s: %d мс", candidate.Endpoint, candidate.RTT.Milliseconds())
				}
				log.Printf("tunnel %s: keeping %s (%s)", t.Name, selection.Endpoint, note)
				d.board.tunnel(t.Name, func(status *TunnelStatus) { status.Quality = reason + "; " + note })
				continue
			}
			applied, rolledBack, err := connect(candidate, "; replaced "+selection.Endpoint+": "+reason, &selection)
			if err != nil || rolledBack {
				log.Printf("tunnel %s: switch to %s failed: %v", t.Name, candidate.Endpoint, err)
				d.board.tunnel(t.Name, func(status *TunnelStatus) { status.Quality = reason + "; не удалось переключить" })
				continue
			}
			candidate = applied
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
	watchSites
)

// maxSiteSwitches bounds endpoint changes in a row made because the test
// sites did not open through the applied tunnel: if no exit opens them, the
// tunnel stays on a working endpoint instead of hopping forever.
const maxSiteSwitches = 3

// After an apply, carries gives the new session carryGrace for its
// handshake, then up to carryAttempts pings of carryTimeout: a pair that
// works answers within a second or two.
const (
	carryGrace    = time.Second
	carryAttempts = 4
	carryTimeout  = 1500 * time.Millisecond
)

// carries reports whether traffic flows through the tunnel with this mark
// shortly after an apply.
func carries(ctx context.Context, mark uint32) bool {
	if !sleep(ctx, carryGrace) {
		return false
	}
	for attempt := 0; attempt < carryAttempts; attempt++ {
		if _, err := tunnel.Ping(ctx, mark, carryTimeout); err == nil {
			return true
		}
		if ctx.Err() != nil {
			return false
		}
	}
	return false
}

func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

// Between health checks the tunnel's interface counters are read every
// stallTick: when it keeps sending for stallWindow and receives nothing, the
// flow was most likely cut, and two quick pings confirm it at once instead
// of at the next health check.
const (
	stallTick   = 2 * time.Second
	stallWindow = 4 * time.Second
	// stallMinSent ignores keepalives and stray packets.
	stallMinSent = 600
)

// pauseWatching waits one health interval like pause, and returns
// watchFailed early when the tunnel stalls.
func (d *Daemon) pauseWatching(ctx context.Context, t *config.Tunnel, mark uint32, switchRequests <-chan struct{}) watchResult {
	deadline := time.Now().Add(t.HealthInterval)
	type sample struct {
		at     time.Time
		rx, tx uint64
	}
	var samples []sample
	for time.Now().Before(deadline) {
		if result := pause(ctx, stallTick, switchRequests); result >= 0 {
			return result
		}
		rx, tx, ok := system.InterfaceBytes(t.Device)
		if !ok {
			continue
		}
		now := sample{time.Now(), rx, tx}
		samples = append(samples, now)
		for len(samples) > 1 && now.at.Sub(samples[0].at) > stallWindow {
			samples = samples[1:]
		}
		first := samples[0]
		if now.at.Sub(first.at) < stallWindow-stallTick/2 || now.rx != first.rx || now.tx-first.tx < stallMinSent {
			continue
		}
		stalled := true
		for attempt := 0; attempt < 2 && stalled; attempt++ {
			if _, err := tunnel.Ping(ctx, mark, carryTimeout); err == nil {
				stalled = false
			}
		}
		if ctx.Err() != nil {
			return watchStopped
		}
		if stalled {
			d.board.tunnel(t.Name, func(status *TunnelStatus) {
				status.PingMs = -1
				status.Error = "нет ответа через туннель"
			})
			return watchFailed
		}
		samples = samples[:0]
	}
	return -1
}

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
func (d *Daemon) watch(ctx context.Context, t *config.Tunnel, mark uint32, fresh bool, window *qualityWindow, limits qualityLimits, switchRequests <-chan struct{}, checkSites bool) watchResult {
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
		if err == nil && checkSites {
			// Once per new endpoint: the test sites through the tunnel itself,
			// with its own account, the way LAN devices will reach them.
			checkSites = false
			results := zapret.Probe(ctx, t.TestURLs, mark)
			if ctx.Err() != nil {
				return watchStopped
			}
			passed := zapret.AllOK(results)
			d.board.tunnel(t.Name, func(status *TunnelStatus) {
				status.Sites = results
				if passed && strings.HasPrefix(status.Quality, "тестовые сайты") {
					status.Quality = ""
				}
			})
			if !zapret.AllOK(results) {
				return watchSites
			}
		}
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
		if result := d.pauseWatching(ctx, t, mark, switchRequests); result >= 0 {
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
