package dnsproxy

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// recentLimit bounds the hosts Recent remembers.
const recentLimit = 64

// Recent remembers the hosts LAN devices recently resolved in watched
// sections (zapret2), so the service can test the hosts that are really in
// use, such as the video node of a nearby Google cache, and not only the
// configured test URLs.
type Recent struct {
	mutex sync.Mutex
	hosts map[string]RecentHost
	now   func() time.Time
}

// RecentHost is one resolved host and its IPv4 addresses.
type RecentHost struct {
	Name      string
	Addresses []netip.Addr
	Seen      time.Time
}

func (r *Recent) note(name string, addresses []netip.Addr) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" || len(addresses) == 0 {
		return
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.hosts == nil {
		r.hosts = map[string]RecentHost{}
	}
	r.hosts[name] = RecentHost{Name: name, Addresses: addresses, Seen: r.clock()}
	if len(r.hosts) <= recentLimit {
		return
	}
	oldest := ""
	for key, host := range r.hosts {
		if oldest == "" || host.Seen.Before(r.hosts[oldest].Seen) {
			oldest = key
		}
	}
	delete(r.hosts, oldest)
}

func (r *Recent) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// Pick returns up to limit hosts seen within maxAge, newest first, skipping
// hosts in skip and hosts whose first address shares a /24 with a host
// already picked: one host per server group is enough to test it.
func (r *Recent) Pick(limit int, maxAge time.Duration, skip func(string) bool) []RecentHost {
	r.mutex.Lock()
	hosts := make([]RecentHost, 0, len(r.hosts))
	cutoff := r.clock().Add(-maxAge)
	for _, host := range r.hosts {
		if host.Seen.After(cutoff) {
			hosts = append(hosts, host)
		}
	}
	r.mutex.Unlock()
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Seen.After(hosts[j].Seen) })
	var picked []RecentHost
	groups := map[netip.Prefix]bool{}
	for _, host := range hosts {
		if len(picked) == limit {
			break
		}
		if skip != nil && skip(host.Name) {
			continue
		}
		group, err := host.Addresses[0].Prefix(24)
		if err != nil || groups[group] {
			continue
		}
		groups[group] = true
		picked = append(picked, host)
	}
	return picked
}
