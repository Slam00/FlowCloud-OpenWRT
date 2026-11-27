package warp

import (
	"context"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

var errNoRegisteredEndpoint = errors.New("Cloudflare returned no WARP endpoint")

// Profile is the exported name of an obfuscation profile.
type Profile = awgProfile

// EndpointCache is the exported name of the endpoint cache.
type EndpointCache = endpointCache

// NewEndpointCache loads the cache file at path ("" keeps it in memory).
func NewEndpointCache(path string) *EndpointCache { return newEndpointCache(path) }

// Selection is the endpoint and profile a round picked.
type Selection struct {
	Endpoint string
	Profile  Profile
	Source   string
	// Latency is how long the round took; RTT is one TCP handshake through
	// the winner once its WireGuard session is up, comparable with tunnel pings.
	Latency time.Duration
	RTT     time.Duration
	// Colo is the Cloudflare location the endpoint exits from ("" when not
	// checked). SitesOK of SitesTotal test URLs opened through it.
	Colo       string
	SitesOK    int
	SitesTotal int
	SiteErrors []string
	// Alternates back the winner up, best first. SitesOK -1 marks one that
	// answered the ping but was not site-tested.
	Alternates []Selection
}

// Options tune a selection round.
type Options struct {
	Parallel int
	// Fwmark marks probe sockets so they never loop back into a tunnel.
	Fwmark uint32
	// Exclude skips one endpoint, the current one when looking for another.
	Exclude string
	// TestURLs must open through the winner; AvoidColos are Cloudflare
	// locations taken only when no other endpoint opens every test URL.
	TestURLs   []string
	AvoidColos []string
	// AWG3 adds the AmneziaWG 3 client parameters (awg3.go) to the probes.
	AWG3 bool
}

const (
	// shortlistSize endpoints that answer the ping go on to the site test;
	// collectWindow is how long the ping stage waits for more after the
	// first answer.
	shortlistSize = 6
	collectWindow = time.Second
	siteTimeout   = 5 * time.Second
	// fastPathTries cached pairs that opened every site are tried before
	// the ping stage.
	fastPathTries = 2
	// A test URL passes when its body ends or this much arrives: blocks
	// often freeze a connection after the first 16 KB.
	siteEnoughBytes = 64 * 1024
	traceURL        = "https://1.1.1.1/cdn-cgi/trace"
)

const (
	// ProbeTarget is Cloudflare's resolver, served from the same edge as the
	// WARP endpoint: a TCP handshake through the tunnel proves data flows.
	ProbeTarget  = "1.1.1.1:443"
	probeTimeout = 5 * time.Second
	probeMTU     = 1280
)

// AWGArgs returns the `awg set` arguments that apply the profile to a kernel
// interface. An empty I1 clears a decoy left from a previous profile.
func (p awgProfile) AWGArgs() []string {
	return []string{
		"jc", strconv.Itoa(p.Jc), "jmin", strconv.Itoa(p.Jmin), "jmax", strconv.Itoa(p.Jmax),
		"s1", "0", "s2", "0", "s3", "0", "s4", "0",
		"h1", "1", "h2", "2", "h3", "3", "h4", "4",
		"i1", p.I1,
	}
}

// probeTunnel is a userspace AmneziaWG device used only to test a candidate.
type probeTunnel struct {
	device *device.Device
	net    *netstack.Net
}

func (t *probeTunnel) close() {
	if t != nil && t.device != nil {
		t.device.Close()
	}
}

func openProbe(peer *Peer, candidate warpCandidate, fwmark uint32, awg3 bool) (*probeTunnel, error) {
	if err := candidate.profile.validate(); err != nil {
		return nil, fmt.Errorf("profile %s: %w", candidate.profile.Name, err)
	}
	tunDevice, tunnelNet, err := netstack.CreateNetTUN([]netip.Addr{peer.AddressV4}, nil, probeMTU)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tunDevice, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "flowcloud-probe"))
	lines := []string{"private_key=" + KeyHex(peer.PrivateKey)}
	if fwmark != 0 {
		lines = append(lines, "fwmark="+strconv.FormatUint(uint64(fwmark), 10))
	}
	lines = append(lines, candidate.profile.uapi()...)
	// Probes test an endpoint with the same obfuscation the tunnel will use.
	lines = append(lines, awg3UAPI(awg3, mrand.New(mrand.NewSource(time.Now().UnixNano())))...)
	lines = append(lines,
		"replace_peers=true",
		"public_key="+KeyHex(peer.PublicKey),
		"endpoint="+candidate.endpoint,
		"replace_allowed_ips=true",
		"allowed_ip=0.0.0.0/0",
		"persistent_keepalive_interval="+Keepalive(awg3),
	)
	if err := dev.IpcSet(strings.Join(lines, "\n") + "\n\n"); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	return &probeTunnel{device: dev, net: tunnelNet}, nil
}

// probe proves data flows through the candidate, then measures one more TCP
// handshake: the first includes the WireGuard handshake, the second is the
// plain round trip through the tunnel.
func (t *probeTunnel) probe(ctx context.Context) (time.Duration, error) {
	probeContext, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	address, err := net.ResolveTCPAddr("tcp", ProbeTarget)
	if err != nil {
		return 0, err
	}
	started := time.Now()
	connection, err := t.net.DialContextTCP(probeContext, address)
	if err != nil {
		return 0, err
	}
	first := time.Since(started)
	// A handshake alone is not proof that data flows: the edge must answer.
	plain, err := net.ResolveTCPAddr("tcp", "1.1.1.1:80")
	if err == nil {
		var check net.Conn
		check, err = t.net.DialContextTCP(probeContext, plain)
		if err == nil {
			err = expectHTTP(probeContext, check)
			check.Close()
		}
	}
	if err != nil {
		_ = connection.Close()
		return 0, fmt.Errorf("no data through the endpoint: %w", err)
	}
	_ = connection.Close()
	started = time.Now()
	connection, err = t.net.DialContextTCP(probeContext, address)
	if err != nil {
		return first, nil
	}
	_ = connection.Close()
	return time.Since(started), nil
}

// Check proves data flows through one pair now, with peer (the probe
// device, so the live tunnel keeps its session). It returns the plain round
// trip through it.
func Check(ctx context.Context, peer *Peer, selection Selection, fwmark uint32, awg3 bool) (time.Duration, error) {
	candidate := warpCandidate{endpoint: selection.Endpoint, profile: selection.Profile, source: candidateSource(selection.Source)}
	tunnel, err := openProbe(peer, candidate, fwmark, awg3)
	if err != nil {
		return 0, err
	}
	defer tunnel.close()
	return tunnel.probe(ctx)
}

// pinged is a candidate that answered the ping stage.
type pinged struct {
	candidate warpCandidate
	rtt       time.Duration
}

// expectHTTP sends a HEAD and waits for the start of the response.
func expectHTTP(ctx context.Context, connection net.Conn) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if _, err := io.WriteString(connection, "HEAD / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n"); err != nil {
		return err
	}
	reply := make([]byte, 8)
	if _, err := io.ReadFull(connection, reply); err != nil {
		return err
	}
	if !strings.HasPrefix(string(reply), "HTTP/1.") {
		return errors.New("unexpected reply")
	}
	return nil
}

// Select runs one selection round in two stages. The ping stage tests up to
// opts.Parallel candidates at a time, each in its own userspace tunnel, and
// keeps the first few that pass. The site stage then opens the shortlist one
// at a time, fastest first: it reads the exit location and fetches the test
// URLs, and the first endpoint that opens all of them outside the avoided
// locations wins. One at a time because every probe tunnel uses the same
// key, and a newer handshake takes the session from the older tunnel.
func Select(ctx context.Context, peer *Peer, cache *EndpointCache, opts Options) (Selection, error) {
	if peer == nil {
		return Selection{}, errors.New("WARP account is missing")
	}
	started := time.Now()
	if len(opts.TestURLs) == 0 && len(opts.AvoidColos) == 0 {
		shortlist, err := pingStage(ctx, peer, cache, opts, nil)
		if err != nil {
			return Selection{}, err
		}
		sort.SliceStable(shortlist, func(i, j int) bool { return shortlist[i].rtt < shortlist[j].rtt })
		best := Selection{Endpoint: shortlist[0].candidate.endpoint, Profile: shortlist[0].candidate.profile,
			Source: string(shortlist[0].candidate.source), RTT: shortlist[0].rtt, Latency: time.Since(started)}
		cache.rememberSelection(best)
		return best, nil
	}

	addresses := resolveTestHosts(ctx, opts.TestURLs)
	var best Selection
	found := false
	perfect := func(selection Selection) bool {
		return selection.SitesOK == selection.SitesTotal && !avoided(selection.Colo, opts.AvoidColos)
	}
	var evaluated []Selection
	// pending are candidates that passed a ping but were not site-tested
	// because an earlier one won; they back the winner up.
	var pending []warpCandidate
	consider := func(selection Selection) {
		cache.noteColo(selection.Endpoint, selection.Colo)
		evaluated = append(evaluated, selection)
		if !found || betterSelection(selection, best, opts.AvoidColos) {
			best, found = selection, true
		}
	}
	finish := func() (Selection, error) {
		best.Latency = time.Since(started)
		cache.rememberSelection(best)
		best.Alternates = alternates(best, evaluated, pending, cache, opts.AvoidColos)
		return best, nil
	}

	// Fast path: the pairs that opened every site last time, outside the
	// avoided locations. Usually the first one still does.
	tried := map[string]bool{}
	fast := 0
	var good []cachedEndpoint
	for _, entry := range cache.snapshot() {
		if entry.Sites && !avoided(entry.Colo, opts.AvoidColos) && entry.Endpoint != opts.Exclude {
			good = append(good, entry)
		}
	}
	for index, entry := range good {
		if fast == fastPathTries || ctx.Err() != nil {
			break
		}
		pending = pending[:0]
		for _, rest := range good[index+1:] {
			pending = append(pending, warpCandidate{rest.Endpoint, rest.Profile, sourceCached})
		}
		fast++
		tried[entry.Endpoint] = true
		selection, _, err := evaluate(ctx, peer, warpCandidate{entry.Endpoint, entry.Profile, sourceCached}, opts, addresses, false)
		if err != nil {
			cache.fail(entry.Endpoint)
			continue
		}
		consider(selection)
		if perfect(selection) {
			return finish()
		}
	}

	shortlist, err := pingStage(ctx, peer, cache, opts, tried)
	if err != nil {
		if found {
			return finish()
		}
		return Selection{}, err
	}
	// Pools seen exiting in an avoided location go last, then by round trip.
	sort.SliceStable(shortlist, func(i, j int) bool {
		avoidI := avoided(cache.poolColo(shortlist[i].candidate.endpoint), opts.AvoidColos)
		avoidJ := avoided(cache.poolColo(shortlist[j].candidate.endpoint), opts.AvoidColos)
		if avoidI != avoidJ {
			return avoidJ
		}
		return shortlist[i].rtt < shortlist[j].rtt
	})
	// An endpoint in an avoided location skips the site test while other
	// candidates remain: a blocked site costs a full timeout each time.
	var deferred []warpCandidate
	for index, entry := range shortlist {
		if ctx.Err() != nil {
			return Selection{}, ctx.Err()
		}
		pending = pending[:0]
		for _, rest := range shortlist[index+1:] {
			if !avoided(cache.poolColo(rest.candidate.endpoint), opts.AvoidColos) {
				pending = append(pending, rest.candidate)
			}
		}
		selection, skipped, err := evaluate(ctx, peer, entry.candidate, opts, addresses, true)
		if err != nil {
			continue
		}
		cache.noteColo(selection.Endpoint, selection.Colo)
		if skipped {
			deferred = append(deferred, entry.candidate)
			continue
		}
		consider(selection)
		if perfect(selection) {
			return finish()
		}
	}
	// Nothing outside the avoided locations opened every site: test those.
	pending = nil
	for _, candidate := range deferred {
		if ctx.Err() != nil {
			return Selection{}, ctx.Err()
		}
		if found && best.SitesOK == best.SitesTotal {
			break
		}
		selection, _, err := evaluate(ctx, peer, candidate, opts, addresses, false)
		if err == nil {
			consider(selection)
		}
	}
	if !found {
		return Selection{}, errors.New("no WARP endpoint passed the second check")
	}
	return finish()
}

// maxAlternates bounds the backups returned with a winner.
const maxAlternates = 3

// alternates lists backups for best: evaluated endpoints that opened as many
// sites, then pinged ones not tested yet. When the winner carries no traffic
// once applied to the tunnel, the daemon tries these before a new round.
func alternates(best Selection, evaluated []Selection, pending []warpCandidate, cache *EndpointCache, avoid []string) []Selection {
	var result []Selection
	sorted := append([]Selection(nil), evaluated...)
	sort.SliceStable(sorted, func(i, j int) bool { return betterSelection(sorted[i], sorted[j], avoid) })
	seen := map[string]bool{best.Endpoint: true}
	for _, selection := range sorted {
		if len(result) == maxAlternates {
			return result
		}
		if seen[selection.Endpoint] || selection.SitesOK < best.SitesOK {
			continue
		}
		seen[selection.Endpoint] = true
		selection.Alternates = nil
		result = append(result, selection)
	}
	for _, candidate := range pending {
		if len(result) == maxAlternates {
			break
		}
		if seen[candidate.endpoint] {
			continue
		}
		seen[candidate.endpoint] = true
		result = append(result, Selection{Endpoint: candidate.endpoint, Profile: candidate.profile,
			Source: string(candidate.source), Colo: cache.poolColo(candidate.endpoint), SitesOK: -1, SitesTotal: best.SitesTotal})
	}
	return result
}

// pingStage returns up to shortlistSize candidates that passed the ping,
// collecting for collectWindow after the first one. All its tunnels are
// closed when it returns.
func pingStage(ctx context.Context, peer *Peer, cache *EndpointCache, opts Options, skip map[string]bool) ([]pinged, error) {
	parallel := opts.Parallel
	if parallel < 1 {
		parallel = 1
	}
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	candidates := buildWarpCandidates(peer.RegisteredHost, peer.RegisteredPort, cache.snapshot(), rng)
	if opts.Exclude != "" || len(skip) > 0 {
		kept := candidates[:0]
		for _, candidate := range candidates {
			if candidate.endpoint != opts.Exclude && !skip[candidate.endpoint] {
				kept = append(kept, candidate)
			}
		}
		candidates = kept
	}
	if len(candidates) == 0 {
		return nil, errors.New("no WARP endpoint candidates")
	}
	// Pools seen exiting outside the avoided locations are pinged first, so
	// the shortlist rarely holds only avoided ones; cached pairs stay first.
	rank := func(candidate warpCandidate) int {
		if candidate.source == sourceCached {
			return 0
		}
		switch colo := cache.poolColo(candidate.endpoint); {
		case colo == "":
			return 2
		case avoided(colo, opts.AvoidColos):
			return 3
		default:
			return 1
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool { return rank(candidates[i]) < rank(candidates[j]) })
	type result struct {
		candidate warpCandidate
		rtt       time.Duration
		err       error
	}
	roundContext, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan result, len(candidates))
	slots := make(chan struct{}, parallel)
	var workers sync.WaitGroup
	// The site stage must not start while a ping-stage tunnel can still
	// handshake with the shared key.
	defer workers.Wait()
	workers.Add(1)
	go func() {
		defer workers.Done()
		for _, candidate := range candidates {
			select {
			case slots <- struct{}{}:
			case <-roundContext.Done():
				results <- result{candidate: candidate, err: roundContext.Err()}
				continue
			}
			workers.Add(1)
			go func(candidate warpCandidate) {
				defer workers.Done()
				defer func() { <-slots }()
				var rtt time.Duration
				tunnel, err := openProbe(peer, candidate, opts.Fwmark, opts.AWG3)
				if err == nil {
					rtt, err = tunnel.probe(roundContext)
				}
				tunnel.close()
				results <- result{candidate: candidate, rtt: rtt, err: err}
			}(candidate)
		}
	}()

	var shortlist []pinged
	var lastErr error
	var window <-chan time.Time
	for completed := 0; completed < len(candidates) && len(shortlist) < shortlistSize; completed++ {
		select {
		case outcome := <-results:
			if outcome.err == nil {
				shortlist = append(shortlist, pinged{candidate: outcome.candidate, rtt: outcome.rtt})
				if window == nil {
					window = time.After(collectWindow)
				}
				continue
			}
			if roundContext.Err() == nil {
				lastErr = outcome.err
				if outcome.candidate.source == sourceCached {
					cache.fail(outcome.candidate.endpoint)
				}
			}
		case <-window:
			completed = len(candidates)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	cancel()
	if len(shortlist) > 0 {
		return shortlist, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no WARP endpoint answered")
	}
	return nil, fmt.Errorf("no working WARP endpoint: %w", lastErr)
}

// evaluate opens one candidate again and runs the site stage through it.
// With deferAvoided, an endpoint exiting in an avoided location returns
// after the location check with skipped set and no site results.
func evaluate(ctx context.Context, peer *Peer, candidate warpCandidate, opts Options, addresses map[string]string, deferAvoided bool) (Selection, bool, error) {
	tunnel, err := openProbe(peer, candidate, opts.Fwmark, opts.AWG3)
	if err != nil {
		return Selection{}, false, err
	}
	defer tunnel.close()
	rtt, err := tunnel.probe(ctx)
	if err != nil {
		return Selection{}, false, err
	}
	selection := Selection{Endpoint: candidate.endpoint, Profile: candidate.profile, Source: string(candidate.source),
		RTT: rtt, SitesTotal: len(opts.TestURLs)}
	client := tunnel.httpClient(addresses)
	selection.Colo = traceColo(ctx, client)
	if deferAvoided && avoided(selection.Colo, opts.AvoidColos) {
		return selection, true, nil
	}
	type outcome struct {
		url string
		err error
	}
	outcomes := make(chan outcome, len(opts.TestURLs))
	for _, url := range opts.TestURLs {
		go func(url string) { outcomes <- outcome{url, fetch(ctx, client, url)} }(url)
	}
	for range opts.TestURLs {
		result := <-outcomes
		if result.err == nil {
			selection.SitesOK++
		} else {
			selection.SiteErrors = append(selection.SiteErrors, result.url+": "+result.err.Error())
		}
	}
	return selection, false, nil
}

// betterSelection ranks by test URLs opened, then by an exit outside the
// avoided locations, then by round trip.
func betterSelection(a, b Selection, avoid []string) bool {
	if a.SitesOK != b.SitesOK {
		return a.SitesOK > b.SitesOK
	}
	if avoidA, avoidB := avoided(a.Colo, avoid), avoided(b.Colo, avoid); avoidA != avoidB {
		return avoidB
	}
	return a.RTT < b.RTT
}

func avoided(colo string, avoid []string) bool {
	for _, code := range avoid {
		if strings.EqualFold(code, colo) {
			return true
		}
	}
	return false
}

// resolveTestHosts resolves the test hosts once, outside the tunnel: the
// probe tunnels have no DNS of their own.
func resolveTestHosts(ctx context.Context, urls []string) map[string]string {
	addresses := map[string]string{}
	for _, raw := range urls {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		host := parsed.Hostname()
		if _, done := addresses[host]; done || net.ParseIP(host) != nil {
			continue
		}
		resolveContext, cancel := context.WithTimeout(ctx, 5*time.Second)
		found, err := net.DefaultResolver.LookupNetIP(resolveContext, "ip4", host)
		cancel()
		if err == nil && len(found) > 0 {
			addresses[host] = found[0].String()
		}
	}
	return addresses
}

// httpClient fetches through the probe tunnel, dialing resolved addresses.
func (t *probeTunnel) httpClient(addresses map[string]string) *http.Client {
	return &http.Client{
		Timeout: siteTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				if resolved, ok := addresses[host]; ok {
					host = resolved
				}
				target, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
				if err != nil {
					return nil, err
				}
				return t.net.DialContextTCP(ctx, target)
			},
		},
	}
}

func traceColo(ctx context.Context, client *http.Client) string {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, traceURL, nil)
	if err != nil {
		return ""
	}
	response, err := client.Do(request)
	if err != nil {
		return ""
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	for _, line := range strings.Split(string(body), "\n") {
		if colo, ok := strings.CutPrefix(line, "colo="); ok {
			return strings.TrimSpace(colo)
		}
	}
	return ""
}

func fetch(ctx context.Context, client *http.Client, target string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36")
	response, err := client.Do(request)
	if err != nil {
		return shortError(err)
	}
	defer response.Body.Close()
	read, err := io.CopyN(io.Discard, response.Body, siteEnoughBytes)
	if err == nil || errors.Is(err, io.EOF) {
		return nil
	}
	return fmt.Errorf("stalled after %d bytes", read)
}

func shortError(err error) error {
	message := err.Error()
	if len(message) > 120 {
		message = message[:120] + "..."
	}
	return errors.New(message)
}

// Forget evicts an endpoint that stopped passing traffic.
func (c *endpointCache) Forget(endpoint string) { c.drop(endpoint) }

// Remember stores a pair that is known to work.
func (c *endpointCache) Remember(selection Selection) {
	c.remember(warpCandidate{endpoint: selection.Endpoint, profile: selection.Profile, source: candidateSource(selection.Source)}, selection.RTT)
}

// Snapshot returns the cached pairs, best first.
func (c *endpointCache) Snapshot() []cachedEndpoint { return c.snapshot() }

// Pools returns the WARP anycast prefixes, which must always bypass tunnels.
func Pools() []netip.Prefix {
	return append([]netip.Prefix(nil), warpPoolsV4...)
}
