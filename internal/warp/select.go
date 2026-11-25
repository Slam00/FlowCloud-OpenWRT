package warp

import (
	"context"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
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
}

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

func openProbe(peer *Peer, candidate warpCandidate, fwmark uint32) (*probeTunnel, error) {
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
	lines = append(lines,
		"replace_peers=true",
		"public_key="+KeyHex(peer.PublicKey),
		"endpoint="+candidate.endpoint,
		"replace_allowed_ips=true",
		"allowed_ip=0.0.0.0/0",
		"persistent_keepalive_interval=25",
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
	_ = connection.Close()
	started = time.Now()
	connection, err = t.net.DialContextTCP(probeContext, address)
	if err != nil {
		return first, nil
	}
	_ = connection.Close()
	return time.Since(started), nil
}

// Select runs one selection round: up to `parallel` candidates are tested at a
// time, each in its own userspace tunnel, and the first that passes wins.
// Probe sockets carry fwmark so they never loop back into a tunnel.
// exclude skips one endpoint, the current one when looking for a better pair.
func Select(ctx context.Context, peer *Peer, cache *EndpointCache, parallel int, fwmark uint32, exclude string) (Selection, error) {
	if peer == nil {
		return Selection{}, errors.New("WARP account is missing")
	}
	if parallel < 1 {
		parallel = 1
	}
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	candidates := buildWarpCandidates(peer.RegisteredHost, peer.RegisteredPort, cache.snapshot(), rng)
	if exclude != "" {
		kept := candidates[:0]
		for _, candidate := range candidates {
			if candidate.endpoint != exclude {
				kept = append(kept, candidate)
			}
		}
		candidates = kept
	}
	if len(candidates) == 0 {
		return Selection{}, errors.New("no WARP endpoint candidates")
	}
	type result struct {
		candidate warpCandidate
		rtt       time.Duration
		err       error
	}
	roundContext, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan result, len(candidates))
	slots := make(chan struct{}, parallel)
	started := time.Now()
	go func() {
		for _, candidate := range candidates {
			select {
			case slots <- struct{}{}:
			case <-roundContext.Done():
				results <- result{candidate: candidate, err: roundContext.Err()}
				continue
			}
			go func(candidate warpCandidate) {
				defer func() { <-slots }()
				var rtt time.Duration
				tunnel, err := openProbe(peer, candidate, fwmark)
				if err == nil {
					rtt, err = tunnel.probe(roundContext)
				}
				tunnel.close()
				results <- result{candidate: candidate, rtt: rtt, err: err}
			}(candidate)
		}
	}()

	var lastErr error
	for completed := 0; completed < len(candidates); completed++ {
		select {
		case outcome := <-results:
			if outcome.err == nil {
				cancel()
				cache.remember(outcome.candidate, outcome.rtt)
				return Selection{
					Endpoint: outcome.candidate.endpoint,
					Profile:  outcome.candidate.profile,
					Source:   string(outcome.candidate.source),
					Latency:  time.Since(started),
					RTT:      outcome.rtt,
				}, nil
			}
			if roundContext.Err() == nil {
				lastErr = outcome.err
			}
			if outcome.candidate.source == sourceCached && roundContext.Err() == nil {
				cache.fail(outcome.candidate.endpoint)
			}
		case <-ctx.Done():
			return Selection{}, ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no WARP endpoint answered")
	}
	return Selection{}, fmt.Errorf("no working WARP endpoint: %w", lastErr)
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
