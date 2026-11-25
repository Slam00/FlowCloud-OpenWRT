package config

import (
	"testing"

	"flowcloud-openwrt/internal/uci"
)

func load(t *testing.T, text string) (*Config, error) {
	t.Helper()
	sections, err := uci.Parse("flowcloud", text)
	if err != nil {
		t.Fatal(err)
	}
	return FromUCI(sections)
}

func TestFromUCI(t *testing.T) {
	config, err := load(t, `flowcloud.settings=settings
flowcloud.settings.update_interval='12h'
flowcloud.warp=tunnel
flowcloud.warp.type='warp'
flowcloud.awg=tunnel
flowcloud.awg.type='interface'
flowcloud.awg.interface='Awg'
flowcloud.yt=section
flowcloud.yt.tunnel='warp'
flowcloud.yt.community_lists='youtube'
flowcloud.yt.domains_text='YouTube.com, *.ytimg.com
.googlevideo.com // comment
bad..domain'
flowcloud.yt.subnets_text='1.2.3.4 10.0.0.0/8 2001:db8::/32 nope'
flowcloud.ads=section
flowcloud.ads.action='block'
`)
	if err != nil {
		t.Fatal(err)
	}
	if config.Settings.UpdateInterval.Hours() != 12 {
		t.Fatalf("update interval = %s", config.Settings.UpdateInterval)
	}
	if len(config.Tunnels) != 2 || config.Tunnels[0].Device != "fcwarp" || config.Tunnels[0].Index != 1 || config.Tunnels[1].Device != "Awg" {
		t.Fatalf("tunnels = %+v %+v", config.Tunnels[0], config.Tunnels[1])
	}
	yt := config.Sections[0]
	want := []string{"googlevideo.com", "youtube.com", "ytimg.com"}
	if len(yt.Domains) != len(want) {
		t.Fatalf("domains = %q", yt.Domains)
	}
	for index := range want {
		if yt.Domains[index] != want[index] {
			t.Fatalf("domains = %q, want %q", yt.Domains, want)
		}
	}
	if len(yt.Subnets) != 2 || yt.Subnets[0].String() != "1.2.3.4/32" || yt.Subnets[1].String() != "10.0.0.0/8" {
		t.Fatalf("subnets = %v", yt.Subnets)
	}
	if len(yt.InvalidUserEntries) != 2 {
		t.Fatalf("invalid = %q", yt.InvalidUserEntries)
	}
	if config.Sections[1].Action != ActionBlock {
		t.Fatalf("action = %q", config.Sections[1].Action)
	}
}

func TestFromUCIRejectsUnknownTunnel(t *testing.T) {
	if _, err := load(t, "flowcloud.a=section\nflowcloud.a.tunnel='missing'\n"); err == nil {
		t.Fatal("a section routed to a missing tunnel must fail")
	}
	if _, err := load(t, "flowcloud.a=tunnel\nflowcloud.a.type='interface'\n"); err == nil {
		t.Fatal("an interface tunnel without an interface must fail")
	}
}

func TestNormalizeDomainKeepsZones(t *testing.T) {
	if domain, ok := NormalizeDomain(".ua"); !ok || domain != "ua" {
		t.Fatalf(".ua = %q %v", domain, ok)
	}
	if _, ok := NormalizeDomain("exa mple.com"); ok {
		t.Fatal("spaces are not allowed")
	}
}
