// Package dnsproxy is the DNS forwarder dnsmasq sends queries to. It learns
// the addresses of routed domains and puts them into the sections' sets.
package dnsproxy

import "strings"

// Matcher maps domains (and their subdomains) to the index of the first
// section that lists them.
type Matcher struct {
	domains map[string]int
}

// NewMatcher builds a matcher; sections earlier in the slice win.
func NewMatcher(sections [][]string) *Matcher {
	matcher := &Matcher{domains: map[string]int{}}
	for index, domains := range sections {
		for _, domain := range domains {
			if _, taken := matcher.domains[domain]; !taken {
				matcher.domains[domain] = index
			}
		}
	}
	return matcher
}

// Len is the number of distinct domains.
func (m *Matcher) Len() int {
	if m == nil {
		return 0
	}
	return len(m.domains)
}

// Match returns the section of name or of its closest listed parent.
func (m *Matcher) Match(name string) (int, bool) {
	if m == nil || len(m.domains) == 0 {
		return 0, false
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	best, found := 0, false
	for {
		if index, ok := m.domains[name]; ok {
			// Like the nftables rules, the section higher in the list wins,
			// whichever of the name's parents it lists.
			if !found || index < best {
				best, found = index, true
			}
		}
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			return best, found
		}
		name = name[dot+1:]
	}
}
