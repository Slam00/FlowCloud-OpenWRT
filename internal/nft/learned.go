package nft

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

// Contains reports whether a set of the table holds ip.
func Contains(set string, ip netip.Addr) bool {
	return exec.Command("nft", "get", "element", "inet", Table, set, "{ "+ip.String()+" }").Run() == nil
}

// Dump returns the elements of the given timeout sets with their remaining
// lifetime, so learned addresses survive a reload or restart of the daemon.
func Dump(sets []string) ([]Element, error) {
	var result []Element
	for _, set := range sets {
		output, err := exec.Command("nft", "-j", "list", "set", "inet", Table, set).Output()
		if err != nil {
			continue
		}
		elements, err := parseSetJSON(output, set)
		if err != nil {
			return nil, err
		}
		result = append(result, elements...)
	}
	return result, nil
}

func parseSetJSON(data []byte, set string) ([]Element, error) {
	var document struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("nft json: %w", err)
	}
	var result []Element
	for _, entry := range document.Nftables {
		raw, ok := entry["set"]
		if !ok {
			continue
		}
		var body struct {
			Elem []json.RawMessage `json:"elem"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			return nil, err
		}
		for _, item := range body.Elem {
			var timed struct {
				Elem struct {
					Val     string `json:"val"`
					Expires int64  `json:"expires"`
				} `json:"elem"`
			}
			if err := json.Unmarshal(item, &timed); err != nil || timed.Elem.Val == "" {
				continue
			}
			address, err := netip.ParseAddr(timed.Elem.Val)
			if err != nil || timed.Elem.Expires <= 1 {
				continue
			}
			result = append(result, Element{Set: set, Address: address, Timeout: time.Duration(timed.Elem.Expires) * time.Second})
		}
	}
	return result, nil
}

// Restore adds dumped elements back, skipping sets the new ruleset lacks.
func Restore(elements []Element, existing map[string]bool) error {
	var kept []Element
	for _, element := range elements {
		if existing[element.Set] {
			kept = append(kept, element)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	// Chunks keep one nft invocation small on large sets.
	for start := 0; start < len(kept); start += 2000 {
		end := start + 2000
		if end > len(kept) {
			end = len(kept)
		}
		if err := Apply(RenderElements(kept[start:end])); err != nil {
			return err
		}
	}
	return nil
}

// marshalElements and unmarshalElements store elements in the run directory.
type storedElement struct {
	Set     string `json:"set"`
	Address string `json:"address"`
	Expires int64  `json:"expires"` // unix time
}

func MarshalElements(elements []Element, now time.Time) ([]byte, error) {
	stored := make([]storedElement, len(elements))
	for index, element := range elements {
		stored[index] = storedElement{Set: element.Set, Address: element.Address.String(), Expires: now.Add(element.Timeout).Unix()}
	}
	return json.Marshal(stored)
}

func UnmarshalElements(data []byte, now time.Time) []Element {
	var stored []storedElement
	if json.Unmarshal(bytes.TrimSpace(data), &stored) != nil {
		return nil
	}
	var result []Element
	for _, item := range stored {
		address, err := netip.ParseAddr(item.Address)
		remaining := time.Until(time.Unix(item.Expires, 0))
		if !now.IsZero() {
			remaining = time.Unix(item.Expires, 0).Sub(now)
		}
		if err != nil || remaining < 2*time.Second || !strings.HasPrefix(item.Set, "s_") {
			continue
		}
		result = append(result, Element{Set: item.Set, Address: address, Timeout: remaining})
	}
	return result
}
