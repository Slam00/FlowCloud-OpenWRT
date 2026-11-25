package warp

import (
	"encoding/json"
	mrand "math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WARP WireGuard anycast pools and ports. Source: WARPSCOUT
// (https://github.com/vernette/warpscout, internal/warpscout/pools.go and
// warp.go, MIT License, Copyright (c) 2026 Nikita S.); the same tables ship in
// FlowCloud for Android and WindseekerTunnel. MASQUE lives on 162.159.198.0/23
// and is not part of these pools.
var warpPoolsV4 = []netip.Prefix{
	netip.MustParsePrefix("8.6.112.0/24"),
	netip.MustParsePrefix("8.34.70.0/24"),
	netip.MustParsePrefix("8.34.146.0/24"),
	netip.MustParsePrefix("8.35.211.0/24"),
	netip.MustParsePrefix("8.39.125.0/24"),
	netip.MustParsePrefix("8.39.204.0/24"),
	netip.MustParsePrefix("8.39.214.0/24"),
	netip.MustParsePrefix("8.47.69.0/24"),
	netip.MustParsePrefix("162.159.192.0/24"),
	netip.MustParsePrefix("162.159.195.0/24"),
	netip.MustParsePrefix("188.114.96.0/24"),
	netip.MustParsePrefix("188.114.97.0/24"),
	netip.MustParsePrefix("188.114.98.0/24"),
	netip.MustParsePrefix("188.114.99.0/24"),
}

var (
	// registeredHostPorts are the ports the helper always tried on the
	// endpoint from the registration; they stay first for that host.
	registeredHostPorts = []int{903, 854, 894, 2408, 500, 1701, 4500}
	primaryWarpPorts    = []int{2408, 500, 1701, 4500}
	extendedWarpPorts   = []int{
		854, 859, 864, 878, 880, 890, 891, 894, 903, 908,
		928, 934, 939, 942, 943, 945, 946, 955, 968, 987,
		988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843,
		2371, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279,
		5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886,
	}
)

const (
	// warpRoundSize bounds how many AmneziaWG devices one selection round runs
	// in parallel.
	warpRoundSize = 24
	// warpDefaultProfileShare is how many pool samples keep the default
	// profile; the rest try random junk/I1 sets.
	warpDefaultProfileShare = 6
	warpCachedPerRound      = 4
)

type candidateSource string

const (
	sourceCached     candidateSource = "cached"
	sourceRegistered candidateSource = "registered"
	sourcePool       candidateSource = "pool"
)

type warpCandidate struct {
	endpoint string
	profile  awgProfile
	source   candidateSource
}

// randomPoolAddress picks a host address inside a random WARP pool, avoiding
// the network and broadcast addresses of the /24.
func randomPoolAddress(rng *mrand.Rand) netip.Addr {
	prefix := warpPoolsV4[rng.Intn(len(warpPoolsV4))]
	base := prefix.Masked().Addr().As4()
	base[3] = byte(randRange(rng, 1, 254))
	return netip.AddrFrom4(base)
}

func randomWarpPort(rng *mrand.Rand) int {
	// Mostly the four ports every client uses; sometimes an alternate port for
	// networks that filter those.
	if rng.Intn(4) == 0 {
		return extendedWarpPorts[rng.Intn(len(extendedWarpPorts))]
	}
	return primaryWarpPorts[rng.Intn(len(primaryWarpPorts))]
}

// buildWarpCandidates assembles one selection round: pairs that worked before
// first, then the endpoint from the registration on the helper's usual ports,
// then random samples from the WARP pools. Profiles are mixed so a round
// explores both the address and the obfuscation dimension.
func buildWarpCandidates(registeredHost string, registeredPort int, cached []cachedEndpoint, rng *mrand.Rand) []warpCandidate {
	result := make([]warpCandidate, 0, warpRoundSize)
	seen := make(map[string]struct{})
	add := func(candidate warpCandidate) bool {
		if len(result) >= warpRoundSize {
			return false
		}
		address, err := netip.ParseAddrPort(candidate.endpoint)
		if err != nil || !address.Addr().Is4() || address.Port() == 0 {
			return false
		}
		if _, exists := seen[candidate.endpoint]; exists {
			return false
		}
		seen[candidate.endpoint] = struct{}{}
		result = append(result, candidate)
		return true
	}

	used := 0
	for _, entry := range cached {
		if used < warpCachedPerRound && add(warpCandidate{entry.Endpoint, entry.Profile, sourceCached}) {
			used++
		}
	}

	if registeredHost != "" {
		ports := registeredHostPorts
		if registeredPort > 0 {
			ports = append([]int{registeredPort}, registeredHostPorts...)
		}
		for _, port := range ports {
			add(warpCandidate{net.JoinHostPort(registeredHost, strconv.Itoa(port)), defaultAWGProfile(), sourceRegistered})
		}
	}

	sampled := 0
	for attempts := 0; len(result) < warpRoundSize && attempts < warpRoundSize*8; attempts++ {
		profile := defaultAWGProfile()
		if sampled >= warpDefaultProfileShare {
			profile = randomAWGProfile(rng)
		}
		endpoint := net.JoinHostPort(randomPoolAddress(rng).String(), strconv.Itoa(randomWarpPort(rng)))
		if add(warpCandidate{endpoint, profile, sourcePool}) {
			sampled++
		}
	}
	return result
}

// splitRegisteredEndpoint returns the IPv4 host and port Cloudflare handed out
// (port 0 means "any").
func splitRegisteredEndpoint(v4, host string) (string, int, error) {
	endpoint := strings.TrimSpace(v4)
	if endpoint == "" {
		endpoint = strings.TrimSpace(host)
	}
	if endpoint == "" {
		return "", 0, errNoRegisteredEndpoint
	}
	hostPart, portPart, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.ParseUint(portPart, 10, 16)
	if err != nil {
		return "", 0, err
	}
	address, err := netip.ParseAddr(hostPart)
	if err != nil || !address.Is4() {
		// A hostname or IPv6 endpoint cannot be used with the IPv4-only bind;
		// pool samples still cover the round.
		return "", 0, nil
	}
	return address.String(), int(port), nil
}

// cachedEndpoint is an endpoint+profile pair that passed the probe.
type cachedEndpoint struct {
	Endpoint  string     `json:"endpoint"`
	Profile   awgProfile `json:"profile"`
	LatencyMs int64      `json:"latency_ms"`
	OKAt      int64      `json:"ok_at"`
	Fails     int        `json:"fails"`
	// Colo is where the endpoint exits; Sites is true when every test URL
	// opened through it last time. Such entries are tried first, before
	// the ping stage, which makes the usual reselection take seconds.
	Colo  string `json:"colo,omitempty"`
	Sites bool   `json:"sites,omitempty"`
}

const (
	endpointCacheVersion   = 1
	endpointCacheMax       = 8
	endpointCacheTTL       = 14 * 24 * time.Hour
	endpointCacheMaxFails  = 3
	endpointCacheFileLimit = 1 << 20
)

type endpointCacheFile struct {
	Version int              `json:"version"`
	Entries []cachedEndpoint `json:"entries"`
	// Colos maps a pool /24 to the Cloudflare location it was last seen
	// exiting from: a network reaches each /24 through one location, so
	// the site stage can test likely good pools first.
	Colos map[string]string `json:"colos,omitempty"`
}

// poolColosMax bounds the remembered /24 locations.
const poolColosMax = 256

// endpointCache persists working WARP endpoints across restarts so the next
// selection probes known-good pairs first. A nil cache is valid and stores
// nothing.
type endpointCache struct {
	path    string
	mutex   sync.Mutex
	entries []cachedEndpoint
	colos   map[string]string
	now     func() time.Time
}

func poolKey(endpoint string) string {
	address, err := netip.ParseAddrPort(endpoint)
	if err != nil || !address.Addr().Is4() {
		return ""
	}
	prefix, _ := address.Addr().Prefix(24)
	return prefix.String()
}

// poolColo returns the location last seen for the endpoint's /24.
func (c *endpointCache) poolColo(endpoint string) string {
	if c == nil {
		return ""
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.colos[poolKey(endpoint)]
}

// noteColo remembers where an endpoint's /24 exits.
func (c *endpointCache) noteColo(endpoint, colo string) {
	key := poolKey(endpoint)
	if c == nil || key == "" || colo == "" {
		return
	}
	c.mutex.Lock()
	if c.colos == nil {
		c.colos = map[string]string{}
	}
	previous, known := c.colos[key]
	changed := previous != colo && (known || len(c.colos) < poolColosMax)
	if changed {
		c.colos[key] = colo
	}
	c.mutex.Unlock()
	if changed {
		c.save()
	}
}

// rememberSelection stores a winner with its location and site result.
func (c *endpointCache) rememberSelection(selection Selection) {
	if c == nil {
		return
	}
	c.remember(warpCandidate{endpoint: selection.Endpoint, profile: selection.Profile, source: candidateSource(selection.Source)}, selection.RTT)
	c.update(selection.Endpoint, func(entry *cachedEndpoint) bool {
		entry.Colo = selection.Colo
		entry.Sites = selection.SitesTotal > 0 && selection.SitesOK == selection.SitesTotal
		return true
	})
	c.noteColo(selection.Endpoint, selection.Colo)
}

// SitesFailed records that the test URLs did not open through an endpoint
// once it carried the tunnel, so it is not tried first again.
func (c *endpointCache) SitesFailed(endpoint string) {
	c.update(endpoint, func(entry *cachedEndpoint) bool {
		entry.Sites = false
		return true
	})
}

func newEndpointCache(path string) *endpointCache {
	cache := &endpointCache{path: path, now: time.Now}
	cache.load()
	return cache
}

func (c *endpointCache) load() {
	if c.path == "" {
		return
	}
	info, err := os.Stat(c.path)
	if err != nil || info.Size() > endpointCacheFileLimit {
		return
	}
	data, err := os.ReadFile(c.path)
	if err != nil {
		return
	}
	var file endpointCacheFile
	if json.Unmarshal(data, &file) != nil || file.Version != endpointCacheVersion {
		return
	}
	for key, colo := range file.Colos {
		if _, err := netip.ParsePrefix(key); err == nil && len(colo) <= 8 && len(c.colos) < poolColosMax {
			if c.colos == nil {
				c.colos = map[string]string{}
			}
			c.colos[key] = colo
		}
	}
	now := c.now()
	for _, entry := range file.Entries {
		if entry.Fails >= endpointCacheMaxFails || entry.Profile.validate() != nil {
			continue
		}
		if address, parseErr := netip.ParseAddrPort(entry.Endpoint); parseErr != nil || !address.Addr().Is4() {
			continue
		}
		if now.Sub(time.Unix(entry.OKAt, 0)) > endpointCacheTTL {
			continue
		}
		c.entries = append(c.entries, entry)
	}
	c.sortLocked()
}

// snapshot returns the entries, best first.
func (c *endpointCache) snapshot() []cachedEndpoint {
	if c == nil {
		return nil
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return append([]cachedEndpoint(nil), c.entries...)
}

// sortLocked orders by fewest recent failures, then most recent success, then
// latency.
func (c *endpointCache) sortLocked() {
	sort.SliceStable(c.entries, func(i, j int) bool {
		a, b := c.entries[i], c.entries[j]
		if a.Fails != b.Fails {
			return a.Fails < b.Fails
		}
		if a.OKAt != b.OKAt {
			return a.OKAt > b.OKAt
		}
		return a.LatencyMs < b.LatencyMs
	})
}

func (c *endpointCache) remember(candidate warpCandidate, latency time.Duration) {
	if c == nil {
		return
	}
	c.mutex.Lock()
	entry := cachedEndpoint{
		Endpoint:  candidate.endpoint,
		Profile:   candidate.profile,
		LatencyMs: latency.Milliseconds(),
		OKAt:      c.now().Unix(),
	}
	replaced := false
	for index := range c.entries {
		if c.entries[index].Endpoint == entry.Endpoint {
			c.entries[index] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		c.entries = append(c.entries, entry)
	}
	c.sortLocked()
	if len(c.entries) > endpointCacheMax {
		c.entries = c.entries[:endpointCacheMax]
	}
	c.mutex.Unlock()
	c.save()
}

// fail counts a failed probe of a cached pair; repeated failures evict it.
func (c *endpointCache) fail(endpoint string) {
	c.update(endpoint, func(entry *cachedEndpoint) bool {
		entry.Fails++
		return entry.Fails < endpointCacheMaxFails
	})
}

// drop evicts a pair whose tunnel stopped passing traffic.
func (c *endpointCache) drop(endpoint string) {
	c.update(endpoint, func(*cachedEndpoint) bool { return false })
}

func (c *endpointCache) update(endpoint string, keep func(*cachedEndpoint) bool) {
	if c == nil {
		return
	}
	c.mutex.Lock()
	changed := false
	kept := c.entries[:0]
	for _, entry := range c.entries {
		if entry.Endpoint == endpoint {
			changed = true
			if !keep(&entry) {
				continue
			}
		}
		kept = append(kept, entry)
	}
	c.entries = kept
	c.sortLocked()
	c.mutex.Unlock()
	if changed {
		c.save()
	}
}

func (c *endpointCache) save() {
	if c == nil || c.path == "" {
		return
	}
	c.mutex.Lock()
	data, err := json.Marshal(endpointCacheFile{Version: endpointCacheVersion, Entries: c.entries, Colos: c.colos})
	c.mutex.Unlock()
	if err != nil || os.MkdirAll(filepath.Dir(c.path), 0o700) != nil {
		return
	}
	temporary := c.path + ".tmp"
	if os.WriteFile(temporary, data, 0o600) == nil {
		_ = os.Rename(temporary, c.path)
	}
}
