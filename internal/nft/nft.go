// Package nft renders and applies the daemon's nftables table. Everything
// lives in its own `inet flowcloud` table, so it never edits fw4 or podkop
// rules; the two fw4 include files the package installs only accept and
// masquerade packets carrying a FlowCloud tunnel mark.
package nft

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"flowcloud-openwrt/internal/netx"
)

const Table = "flowcloud"

// Rule describes how one section marks traffic.
type Rule struct {
	Section string
	// Mark is the tunnel mark, netx.MarkDirect for "direct" sections, or 0
	// for "block" sections, which drop instead.
	Mark  uint32
	Block bool
	// Subnets are loaded into the static set; domain IPs are added at
	// runtime by the DNS proxy.
	Subnets []netip.Prefix
}

// Ruleset is the whole table.
type Ruleset struct {
	SourceInterfaces []string
	RouteRouter      bool
	// Bypass are destinations that must never be tunnelled: tunnel endpoints
	// and the WARP pools (otherwise encrypted packets would loop).
	Bypass []netip.Prefix
	Rules  []Rule
	// DNSTimeout is the default lifetime of IPs learned from DNS.
	DNSTimeout time.Duration
}

// DNSSet and NetSet name a section's sets.
func DNSSet(section string) string { return "s_" + section + "_dns" }
func NetSet(section string) string { return "s_" + section + "_net" }

func quoteList(values []string) string {
	quoted := make([]string, len(values))
	for index, value := range values {
		quoted[index] = fmt.Sprintf("%q", value)
	}
	return strings.Join(quoted, ", ")
}

func prefixList(prefixes []netip.Prefix) string {
	sorted := append([]netip.Prefix(nil), prefixes...)
	sort.Slice(sorted, func(i, j int) bool {
		if c := sorted[i].Addr().Compare(sorted[j].Addr()); c != 0 {
			return c < 0
		}
		return sorted[i].Bits() < sorted[j].Bits()
	})
	parts := make([]string, len(sorted))
	for index, prefix := range sorted {
		parts[index] = prefix.String()
	}
	return strings.Join(parts, ", ")
}

// Render returns an nft script that atomically replaces the table.
func (r Ruleset) Render() string {
	var b strings.Builder
	timeout := int(r.DNSTimeout / time.Second)
	if timeout < 60 {
		timeout = 3600
	}
	mask := fmt.Sprintf("0x%08x", netx.MarkMask)
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\ntable inet %s {\n", Table, Table, Table)
	fmt.Fprintf(&b, "\tset bypass {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n")
	if len(r.Bypass) > 0 {
		fmt.Fprintf(&b, "\t\telements = { %s }\n", prefixList(r.Bypass))
	}
	b.WriteString("\t}\n")
	for _, rule := range r.Rules {
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t\ttimeout %ds\n\t\tsize 262144\n\t}\n", DNSSet(rule.Section), timeout)
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n", NetSet(rule.Section))
		if len(rule.Subnets) > 0 {
			fmt.Fprintf(&b, "\t\telements = { %s }\n", prefixList(rule.Subnets))
		}
		b.WriteString("\t}\n")
	}

	// classify: restore the connection's mark, otherwise classify new flows.
	b.WriteString("\tchain classify {\n")
	fmt.Fprintf(&b, "\t\tip daddr @bypass return\n")
	marks := map[uint32]bool{}
	for _, rule := range r.Rules {
		if !rule.Block && rule.Mark != 0 {
			marks[rule.Mark] = true
		}
	}
	sortedMarks := make([]uint32, 0, len(marks))
	for mark := range marks {
		sortedMarks = append(sortedMarks, mark)
	}
	sort.Slice(sortedMarks, func(i, j int) bool { return sortedMarks[i] < sortedMarks[j] })
	for _, mark := range sortedMarks {
		fmt.Fprintf(&b, "\t\tct mark and %s == 0x%08x meta mark set mark or 0x%08x return\n", mask, mark, mark)
	}
	// Flows that started before an IP entered a set keep their route.
	b.WriteString("\t\tct state != new return\n")
	for _, rule := range r.Rules {
		for _, set := range []string{DNSSet(rule.Section), NetSet(rule.Section)} {
			if rule.Block {
				fmt.Fprintf(&b, "\t\tip daddr @%s counter drop comment %q\n", set, "section "+rule.Section)
				continue
			}
			fmt.Fprintf(&b, "\t\tip daddr @%s meta mark set mark or 0x%08x ct mark set ct mark or 0x%08x counter return comment %q\n",
				set, rule.Mark, rule.Mark, "section "+rule.Section)
		}
	}
	b.WriteString("\t}\n")

	b.WriteString("\tchain prerouting {\n\t\ttype filter hook prerouting priority mangle; policy accept;\n")
	if len(r.SourceInterfaces) > 0 {
		fmt.Fprintf(&b, "\t\tiifname != { %s } return\n", quoteList(r.SourceInterfaces))
	}
	fmt.Fprintf(&b, "\t\tmeta mark and %s != 0 return\n", mask)
	b.WriteString("\t\tmeta nfproto ipv4 jump classify\n\t}\n")

	if r.RouteRouter {
		b.WriteString("\tchain output {\n\t\ttype route hook output priority mangle; policy accept;\n")
		// Sockets that already carry a mark (WireGuard with fwmark, the
		// daemon's own direct sockets, health checks) choose their route.
		fmt.Fprintf(&b, "\t\tmeta mark and %s != 0 return\n", mask)
		b.WriteString("\t\toifname \"lo\" return\n")
		b.WriteString("\t\tmeta nfproto ipv4 jump classify\n\t}\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// Apply loads the ruleset atomically.
func Apply(script string) error {
	command := exec.Command("nft", "-f", "-")
	command.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Delete removes the table; a missing table is not an error.
func Delete() error {
	_ = exec.Command("nft", "delete", "table", "inet", Table).Run()
	return nil
}

// Element is one learned address.
type Element struct {
	Set     string
	Address netip.Addr
	Timeout time.Duration
}

// Adder batches set additions from concurrent DNS answers into one nft call.
// Add blocks until the batch containing its elements is applied, so a client
// never connects before its IP is in the set.
type Adder struct {
	mutex   sync.Mutex
	pending []Element
	waiters []chan error
	timer   *time.Timer
	window  time.Duration
	run     func(script string) error
}

func NewAdder() *Adder {
	return &Adder{window: 3 * time.Millisecond, run: Apply}
}

func (a *Adder) Add(elements []Element) error {
	if len(elements) == 0 {
		return nil
	}
	done := make(chan error, 1)
	a.mutex.Lock()
	a.pending = append(a.pending, elements...)
	a.waiters = append(a.waiters, done)
	if a.timer == nil {
		a.timer = time.AfterFunc(a.window, a.flush)
	}
	a.mutex.Unlock()
	return <-done
}

func (a *Adder) flush() {
	a.mutex.Lock()
	elements := a.pending
	waiters := a.waiters
	a.pending = nil
	a.waiters = nil
	a.timer = nil
	a.mutex.Unlock()
	err := a.run(RenderElements(elements))
	for _, waiter := range waiters {
		waiter <- err
	}
}

// RenderElements renders `add element` statements grouped by set.
func RenderElements(elements []Element) string {
	bySet := map[string][]string{}
	var order []string
	for _, element := range elements {
		if _, ok := bySet[element.Set]; !ok {
			order = append(order, element.Set)
		}
		seconds := int(element.Timeout / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		bySet[element.Set] = append(bySet[element.Set], fmt.Sprintf("%s timeout %ds", element.Address, seconds))
	}
	// `add` leaves an existing element's timeout alone; `destroy` (which
	// ignores missing elements) followed by `add` refreshes it in one batch.
	var b strings.Builder
	for _, set := range order {
		addresses := make([]string, len(bySet[set]))
		for index, entry := range bySet[set] {
			addresses[index], _, _ = strings.Cut(entry, " ")
		}
		fmt.Fprintf(&b, "destroy element inet %s %s { %s }\n", Table, set, strings.Join(addresses, ", "))
		fmt.Fprintf(&b, "add element inet %s %s { %s }\n", Table, set, strings.Join(bySet[set], ", "))
	}
	return b.String()
}
