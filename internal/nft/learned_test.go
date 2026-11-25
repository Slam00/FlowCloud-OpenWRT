package nft

import (
	"testing"
	"time"
)

func TestParseSetJSON(t *testing.T) {
	data := []byte(`{"nftables": [{"metainfo": {"version": "1.1.1"}}, {"set": {"family": "inet", "name": "s_main_dns", "table": "flowcloud", "type": "ipv4_addr", "flags": ["timeout"], "timeout": 3600, "elem": [{"elem": {"val": "8.6.112.0", "timeout": 3600, "expires": 3412}}, {"elem": {"val": "142.250.1.1", "timeout": 3600, "expires": 0}}]}}]}`)
	elements, err := parseSetJSON(data, "s_main_dns")
	if err != nil {
		t.Fatal(err)
	}
	if len(elements) != 1 || elements[0].Address.String() != "8.6.112.0" || elements[0].Timeout != 3412*time.Second {
		t.Fatalf("elements = %+v, want only the live address with its remaining lifetime", elements)
	}
}

func TestStoredElementsRoundTrip(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	elements, _ := parseSetJSON([]byte(`{"nftables":[{"set":{"elem":[{"elem":{"val":"1.2.3.4","expires":600}}]}}]}`), "s_yt_dns")
	data, err := MarshalElements(elements, now)
	if err != nil {
		t.Fatal(err)
	}
	restored := UnmarshalElements(data, now.Add(100*time.Second))
	if len(restored) != 1 || restored[0].Set != "s_yt_dns" || restored[0].Timeout != 500*time.Second {
		t.Fatalf("restored = %+v", restored)
	}
	if expired := UnmarshalElements(data, now.Add(time.Hour)); len(expired) != 0 {
		t.Fatalf("expired elements were restored: %+v", expired)
	}
}
