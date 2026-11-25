package nft

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestRender(t *testing.T) {
	script := Ruleset{
		SourceInterfaces: []string{"br-lan"},
		RouteRouter:      true,
		Bypass:           []netip.Prefix{netip.MustParsePrefix("162.159.192.0/24")},
		Rules: []Rule{
			{Section: "yt", Mark: 0x01000000, Subnets: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
			{Section: "ads", Block: true},
		},
		DNSTimeout:  time.Hour,
		ZapretQueue: 300,
	}.Render()
	for _, want := range []string{
		"delete table inet flowcloud",
		"set s_yt_dns {",
		"timeout 3600s",
		"elements = { 10.0.0.0/8 }",
		"ct mark and 0x0f000000 == 0x01000000 meta mark set mark or 0x01000000 return",
		"ct state != new return",
		"ip daddr @s_yt_dns meta mark set mark or 0x01000000 ct mark set ct mark or 0x01000000 counter return",
		"ip daddr @s_ads_dns counter drop",
		`iifname != { "br-lan" } return`,
		"type route hook output priority mangle",
		"tcp flags syn / syn,rst tcp option maxseg size set rt mtu",
		"tcp dport { 80, 443 } ct original packets 1-12 counter queue num 300 bypass",
		"tcp sport { 80, 443 } ct reply packets 1-12 counter queue num 300 bypass",
		"meta mark and 0x40000000 != 0 return",
		"chain mss_reply_01000000 {}",
		"meta nfproto ipv4 ct direction reply ct mark and 0x0f000000 == 0x01000000 tcp flags syn,ack / syn,ack,rst jump mss_reply_01000000",
		"elements = { 162.159.192.0/24 }",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("rendered ruleset is missing %q\n%s", want, script)
		}
	}
}

func TestAdderBatchesAndRefreshes(t *testing.T) {
	var scripts []string
	adder := &Adder{window: time.Millisecond, run: func(script string) error {
		scripts = append(scripts, script)
		return nil
	}}
	done := make(chan error, 2)
	go func() {
		done <- adder.Add([]Element{{Set: "s_a_dns", Address: netip.MustParseAddr("1.1.1.1"), Timeout: time.Hour}})
	}()
	go func() {
		done <- adder.Add([]Element{{Set: "s_a_dns", Address: netip.MustParseAddr("1.0.0.1"), Timeout: 2 * time.Hour}})
	}()
	for index := 0; index < 2; index++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	joined := strings.Join(scripts, "")
	if !strings.Contains(joined, "destroy element inet flowcloud s_a_dns") || !strings.Contains(joined, "1.1.1.1 timeout 3600s") {
		t.Fatalf("unexpected scripts: %q", scripts)
	}
}
