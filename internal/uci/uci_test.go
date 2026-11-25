package uci

import "testing"

const sample = `flowcloud.settings=settings
flowcloud.settings.dns_upstream='https://1.1.1.1/dns-query'
flowcloud.warp=tunnel
flowcloud.warp.type='warp'
flowcloud.main=section
flowcloud.main.tunnel='warp'
flowcloud.main.community_lists='youtube' 'telegram'
flowcloud.main.domains_text='youtube.com
ytimg.com // video
it'\''s.example'
flowcloud.cfg0a1b2c=section
flowcloud.cfg0a1b2c.enabled='0'
`

func TestParse(t *testing.T) {
	sections, err := Parse("flowcloud", sample)
	if err != nil {
		t.Fatal(err)
	}
	if len(sections) != 4 {
		t.Fatalf("sections = %d, want 4", len(sections))
	}
	main := sections[2]
	if main.Name != "main" || main.Type != "section" || main.Get("tunnel", "") != "warp" {
		t.Fatalf("main = %+v", main)
	}
	lists := main.List("community_lists")
	if len(lists) != 2 || lists[0] != "youtube" || lists[1] != "telegram" {
		t.Fatalf("community_lists = %q", lists)
	}
	if got := main.Get("domains_text", ""); got != "youtube.com\nytimg.com // video\nit's.example" {
		t.Fatalf("domains_text = %q", got)
	}
	if sections[3].Bool("enabled", true) {
		t.Fatal("enabled='0' must read as false")
	}
	if !main.Bool("enabled", true) {
		t.Fatal("a missing flag must use the default")
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := Parse("flowcloud", "flowcloud.x.y='1'\n"); err == nil {
		t.Fatal("an option before its section must fail")
	}
	if _, err := Parse("flowcloud", "flowcloud.a=section\nflowcloud.a.b='open\n"); err == nil {
		t.Fatal("an unterminated quote must fail")
	}
}
