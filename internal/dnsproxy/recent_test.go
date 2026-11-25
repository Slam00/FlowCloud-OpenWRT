package dnsproxy

import (
	"net/netip"
	"testing"
	"time"
)

func TestRecentPick(t *testing.T) {
	now := time.Unix(1000, 0)
	recent := &Recent{now: func() time.Time { return now }}
	address := func(text string) []netip.Addr { return []netip.Addr{netip.MustParseAddr(text)} }

	recent.note("old.example.", address("10.0.0.1"))
	now = now.Add(20 * time.Minute)
	recent.note("WWW.YouTube.com.", address("142.251.1.4"))
	now = now.Add(time.Second)
	recent.note("i.ytimg.com.", address("142.251.1.9")) // same /24 as www
	now = now.Add(time.Second)
	recent.note("rr1---sn-x.googlevideo.com.", address("178.66.83.79"))
	now = now.Add(time.Second)
	recent.note("skip.example.", address("192.0.2.1"))

	picked := recent.Pick(3, 15*time.Minute, func(name string) bool { return name == "skip.example" })
	var names []string
	for _, host := range picked {
		names = append(names, host.Name)
	}
	want := []string{"rr1---sn-x.googlevideo.com", "i.ytimg.com"}
	if len(names) != len(want) || names[0] != want[0] || names[1] != want[1] {
		t.Fatalf("picked %v, want %v", names, want)
	}

	for index := 0; index < recentLimit+5; index++ {
		recent.note(string(rune('a'+index%26))+string(rune('a'+index/26))+".test.", address("10.1.0.1"))
	}
	if len(recent.hosts) > recentLimit {
		t.Fatalf("kept %d hosts, limit %d", len(recent.hosts), recentLimit)
	}
}
