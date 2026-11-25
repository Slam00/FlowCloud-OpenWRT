package warp

import (
	mrand "math/rand"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildWarpCandidatesOrderAndBounds(t *testing.T) {
	rng := mrand.New(mrand.NewSource(1))
	cached := []cachedEndpoint{{Endpoint: "8.6.112.7:4500", Profile: defaultAWGProfile()}}
	candidates := buildWarpCandidates("162.159.192.9", 0, cached, rng)
	if len(candidates) != warpRoundSize {
		t.Fatalf("len = %d, want %d", len(candidates), warpRoundSize)
	}
	if candidates[0].endpoint != "8.6.112.7:4500" || candidates[0].source != sourceCached {
		t.Fatalf("first candidate = %+v, want the cached pair", candidates[0])
	}
	seen := map[string]bool{}
	pool, randomProfiles := 0, 0
	for _, candidate := range candidates {
		if seen[candidate.endpoint] {
			t.Fatalf("duplicate candidate %s", candidate.endpoint)
		}
		seen[candidate.endpoint] = true
		if err := candidate.profile.validate(); err != nil {
			t.Fatalf("candidate %s: %v", candidate.endpoint, err)
		}
		if candidate.source == sourcePool {
			pool++
			address := netip.MustParseAddrPort(candidate.endpoint).Addr()
			inPool := false
			for _, prefix := range warpPoolsV4 {
				inPool = inPool || prefix.Contains(address)
			}
			if !inPool {
				t.Fatalf("pool candidate %s is outside the WARP pools", candidate.endpoint)
			}
			if candidate.profile.Name != defaultAWGProfile().Name {
				randomProfiles++
			}
		}
	}
	if pool == 0 || randomProfiles == 0 {
		t.Fatalf("pool=%d randomProfiles=%d, want both > 0", pool, randomProfiles)
	}
}

func TestEndpointCachePersistsAndForgets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoints.json")
	cache := NewEndpointCache(path)
	cache.Remember(Selection{Endpoint: "8.39.125.10:2408", Profile: defaultAWGProfile(), Latency: time.Second})
	if entries := NewEndpointCache(path).Snapshot(); len(entries) != 1 || entries[0].Profile.I1 != warpCPSPacket {
		t.Fatalf("reloaded entries = %+v", entries)
	}
	cache.Forget("8.39.125.10:2408")
	if entries := NewEndpointCache(path).Snapshot(); len(entries) != 0 {
		t.Fatalf("forgotten endpoint is still cached: %+v", entries)
	}
}

// Every I1 variant must be accepted by amneziawg-go's own parser, otherwise a
// candidate would fail on IpcSet instead of on the network.
func TestProfilesAreAcceptedByDevice(t *testing.T) {
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index + 1)
	}
	peer := &Peer{PrivateKey: key, PublicKey: key, AddressV4: netip.MustParseAddr("172.16.0.2")}
	rng := mrand.New(mrand.NewSource(3))
	profiles := []awgProfile{defaultAWGProfile()}
	for _, variant := range i1Variants {
		chain, err := variant.generate(rng)
		if err != nil {
			t.Fatalf("%s: %v", variant.name, err)
		}
		profiles = append(profiles, awgProfile{Name: variant.name, Jc: 4, Jmin: 20, Jmax: 90, I1: chain})
	}
	for _, profile := range profiles {
		tunnel, err := openProbe(peer, warpCandidate{endpoint: "127.0.0.1:9", profile: profile}, 0)
		if err != nil {
			t.Fatalf("profile %s rejected: %v", profile.Name, err)
		}
		tunnel.close()
		if args := profile.AWGArgs(); args[len(args)-2] != "i1" || args[len(args)-1] != profile.I1 {
			t.Fatalf("profile %s: awg arguments %q", profile.Name, args)
		}
	}
}
