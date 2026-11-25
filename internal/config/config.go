// Package config turns the `flowcloud` UCI file into typed, validated
// settings. Everything the daemon does is derived from it.
package config

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"flowcloud-openwrt/internal/uci"
)

const (
	TunnelWarp      = "warp"
	TunnelInterface = "interface"

	ActionTunnel = "tunnel"
	ActionBlock  = "block"
	ActionDirect = "direct"
	ActionZapret = "zapret"

	// MaxTunnels is bounded by the four fwmark bits the daemon owns.
	MaxTunnels = 12
)

var (
	// DefaultWarpTestURLs are what a WARP endpoint must open to be chosen.
	DefaultWarpTestURLs = []string{"https://www.youtube.com/", "https://telegram.org/"}
	// DefaultAvoidColos: Cloudflare in Moscow and Saint Petersburg. From
	// there WARP traffic leaves through Russian networks, so blocked sites
	// stay blocked; Stockholm answers as fast from the same networks.
	DefaultAvoidColos = []string{"DME", "LED"}
)

type Settings struct {
	Enabled            bool
	DNSListen          string
	DNSUpstreams       []string
	DnsmasqIntegration bool
	StripAAAA          bool
	UpdateInterval     time.Duration
	SourceInterfaces   []string
	RouteRouterTraffic bool
	MinSetTimeout      time.Duration
	LogLevel           string
}

type Tunnel struct {
	Name    string
	Type    string // warp | interface
	Enabled bool
	// Device is the kernel device for warp tunnels, the netifd interface name
	// for interface tunnels.
	Device         string
	ProbeParallel  int
	FailClosed     bool
	HealthInterval time.Duration
	// MaxPingMs and MaxLossPct make a WARP tunnel look for a better endpoint
	// when the median ping or the loss over the quality window exceed them;
	// 0 disables a check.
	MaxPingMs  int
	MaxLossPct int
	// TestURLs must open through a WARP endpoint before it is chosen, and
	// through the tunnel once it is applied. Empty: only the ping.
	TestURLs []string
	// AvoidColos are Cloudflare locations (IATA codes from cdn-cgi/trace)
	// chosen only when no other endpoint opens the test URLs.
	AvoidColos []string
	// Index is 1-based and stable for a given config: it selects the fwmark
	// and the routing table.
	Index int
}

type Section struct {
	Name               string
	Enabled            bool
	Action             string // tunnel | block | direct
	Tunnel             string
	CommunityLists     []string
	Domains            []string
	Subnets            []netip.Prefix
	RemoteDomainLists  []string
	RemoteSubnetLists  []string
	InvalidUserEntries []string
	Index              int
}

// Zapret configures the optional zapret2 DPI bypass used by "zapret" sections.
type Zapret struct {
	Enabled bool
	Binary  string
	LuaDir  string
	Queue   int
	// Strategy is "auto", a built-in strategy name or "custom".
	Strategy      string
	CustomArgs    string
	CheckInterval time.Duration
	TestURLs      []string
}

type Config struct {
	Zapret   Zapret
	Settings Settings
	Tunnels  []*Tunnel
	Sections []*Section
}

// Tunnel returns the tunnel with this name or nil.
func (c *Config) Tunnel(name string) *Tunnel {
	for _, tunnel := range c.Tunnels {
		if tunnel.Name == name {
			return tunnel
		}
	}
	return nil
}

var (
	deviceName  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
	sectionName = regexp.MustCompile(`^[A-Za-z0-9_]{1,32}$`)
)

// FromUCI builds and validates the configuration.
func FromUCI(sections []*uci.Section) (*Config, error) {
	config := &Config{Settings: defaultSettings(), Zapret: defaultZapret()}
	for _, section := range sections {
		switch section.Type {
		case "settings":
			if err := readSettings(&config.Settings, section); err != nil {
				return nil, err
			}
		case "tunnel":
			tunnel, err := readTunnel(section)
			if err != nil {
				return nil, err
			}
			config.Tunnels = append(config.Tunnels, tunnel)
		case "zapret":
			if err := readZapret(&config.Zapret, section); err != nil {
				return nil, err
			}
		case "section":
			config.Sections = append(config.Sections, readSection(section))
		}
	}
	if len(config.Tunnels) > MaxTunnels {
		return nil, fmt.Errorf("at most %d tunnels are supported", MaxTunnels)
	}
	devices := map[string]string{}
	for index, tunnel := range config.Tunnels {
		tunnel.Index = index + 1
		if owner, taken := devices[tunnel.Device]; taken {
			return nil, fmt.Errorf("tunnels %s and %s use the same device %s", owner, tunnel.Name, tunnel.Device)
		}
		devices[tunnel.Device] = tunnel.Name
	}
	for index, section := range config.Sections {
		section.Index = index
		if section.Action == ActionTunnel {
			tunnel := config.Tunnel(section.Tunnel)
			if tunnel == nil {
				return nil, fmt.Errorf("section %s routes to unknown tunnel %q", section.Name, section.Tunnel)
			}
		}
	}
	return config, nil
}

func defaultSettings() Settings {
	return Settings{
		Enabled:            true,
		DNSListen:          "127.0.0.53:53",
		DNSUpstreams:       []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"},
		DnsmasqIntegration: true,
		StripAAAA:          true,
		UpdateInterval:     24 * time.Hour,
		SourceInterfaces:   []string{"br-lan"},
		RouteRouterTraffic: true,
		MinSetTimeout:      time.Hour,
		LogLevel:           "info",
	}
}

func readSettings(settings *Settings, section *uci.Section) error {
	settings.Enabled = section.Bool("enabled", settings.Enabled)
	settings.DNSListen = section.Get("dns_listen", settings.DNSListen)
	if upstreams := section.List("dns_upstream"); len(upstreams) > 0 {
		settings.DNSUpstreams = upstreams
	}
	settings.DnsmasqIntegration = section.Bool("dnsmasq_integration", settings.DnsmasqIntegration)
	settings.StripAAAA = section.Bool("strip_aaaa", settings.StripAAAA)
	if value := section.Get("update_interval", ""); value != "" {
		interval, err := time.ParseDuration(value)
		if err != nil || interval < time.Hour {
			return fmt.Errorf("settings: update_interval %q must be a duration of at least 1h", value)
		}
		settings.UpdateInterval = interval
	}
	if sources := section.List("source_interfaces"); len(sources) > 0 {
		for _, source := range sources {
			if !deviceName.MatchString(source) {
				return fmt.Errorf("settings: invalid source interface %q", source)
			}
		}
		settings.SourceInterfaces = sources
	}
	settings.RouteRouterTraffic = section.Bool("route_router_traffic", settings.RouteRouterTraffic)
	settings.LogLevel = section.Get("log_level", settings.LogLevel)
	if _, err := netip.ParseAddrPort(settings.DNSListen); err != nil {
		return fmt.Errorf("settings: dns_listen %q: %w", settings.DNSListen, err)
	}
	return nil
}

func readTunnel(section *uci.Section) (*Tunnel, error) {
	tunnel := &Tunnel{
		Name:           section.Name,
		Type:           section.Get("type", TunnelWarp),
		Enabled:        section.Bool("enabled", true),
		Device:         section.Get("interface", ""),
		ProbeParallel:  0, // 0: chosen by the daemon from the router's RAM
		FailClosed:     section.Bool("fail_closed", false),
		HealthInterval: 15 * time.Second,
		MaxPingMs:      300,
		MaxLossPct:     30,
		TestURLs:       append([]string(nil), DefaultWarpTestURLs...),
		AvoidColos:     append([]string(nil), DefaultAvoidColos...),
	}
	if urls := section.List("test_url"); len(urls) > 0 {
		for _, url := range urls {
			if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
				return nil, fmt.Errorf("tunnel %s: test URL %q must start with http:// or https://", section.Name, url)
			}
		}
		tunnel.TestURLs = urls
	}
	if !section.Bool("site_test", true) {
		tunnel.TestURLs = nil
	}
	if colos := section.List("avoid_colo"); len(colos) > 0 {
		tunnel.AvoidColos = nil
		for _, colo := range colos {
			// "-" alone keeps the list empty: prefer no location.
			for _, code := range strings.Fields(strings.ToUpper(colo)) {
				if code != "-" {
					tunnel.AvoidColos = append(tunnel.AvoidColos, code)
				}
			}
		}
	}
	if !sectionName.MatchString(tunnel.Name) {
		return nil, fmt.Errorf("tunnel name %q: use letters, digits and _", tunnel.Name)
	}
	switch tunnel.Type {
	case TunnelWarp:
		// WARP tunnels name the kernel device they create in "device"; LuCI
		// keeps "interface" for the netifd interface of interface tunnels.
		tunnel.Device = section.Get("device", tunnel.Device)
		if tunnel.Device == "" {
			tunnel.Device = "fc" + tunnel.Name
			if len(tunnel.Device) > 15 {
				tunnel.Device = tunnel.Device[:15]
			}
		}
	case TunnelInterface:
		if tunnel.Device == "" {
			return nil, fmt.Errorf("tunnel %s: choose a network interface", tunnel.Name)
		}
	default:
		return nil, fmt.Errorf("tunnel %s: unknown type %q", tunnel.Name, tunnel.Type)
	}
	if !deviceName.MatchString(tunnel.Device) {
		return nil, fmt.Errorf("tunnel %s: invalid interface name %q", tunnel.Name, tunnel.Device)
	}
	if value := section.Get("probe_parallel", ""); value != "" {
		parallel, err := strconv.Atoi(value)
		if err != nil || parallel < 1 || parallel > 24 {
			return nil, fmt.Errorf("tunnel %s: probe_parallel must be 1-24", tunnel.Name)
		}
		tunnel.ProbeParallel = parallel
	}
	if value := section.Get("max_ping", ""); value != "" {
		maxPing, err := strconv.Atoi(value)
		if err != nil || maxPing < 0 || maxPing > 10000 {
			return nil, fmt.Errorf("tunnel %s: max_ping must be 0-10000 ms", tunnel.Name)
		}
		tunnel.MaxPingMs = maxPing
	}
	if value := section.Get("max_loss", ""); value != "" {
		maxLoss, err := strconv.Atoi(value)
		if err != nil || maxLoss < 0 || maxLoss > 100 {
			return nil, fmt.Errorf("tunnel %s: max_loss must be 0-100 %%", tunnel.Name)
		}
		tunnel.MaxLossPct = maxLoss
	}
	if value := section.Get("health_interval", ""); value != "" {
		seconds, err := strconv.Atoi(value)
		if err != nil || seconds < 5 || seconds > 3600 {
			return nil, fmt.Errorf("tunnel %s: health_interval must be 5-3600 seconds", tunnel.Name)
		}
		tunnel.HealthInterval = time.Duration(seconds) * time.Second
	}
	return tunnel, nil
}

func readSection(section *uci.Section) *Section {
	result := &Section{
		Name:              section.Name,
		Enabled:           section.Bool("enabled", true),
		Action:            section.Get("action", ActionTunnel),
		Tunnel:            section.Get("tunnel", ""),
		CommunityLists:    section.List("community_lists"),
		RemoteDomainLists: section.List("remote_domain_lists"),
		RemoteSubnetLists: section.List("remote_subnet_lists"),
	}
	switch result.Action {
	case ActionTunnel, ActionBlock, ActionDirect, ActionZapret:
	default:
		result.Action = ActionTunnel
	}
	domains, invalidDomains := ParseDomains(strings.Join(append(section.List("domains"), section.Get("domains_text", "")), "\n"))
	subnets, invalidSubnets := ParseSubnets(strings.Join(append(section.List("subnets"), section.Get("subnets_text", "")), "\n"))
	result.Domains = domains
	result.Subnets = subnets
	result.InvalidUserEntries = append(invalidDomains, invalidSubnets...)
	return result
}

var domainLabel = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)

// tokens splits list text on commas, whitespace and newlines and drops
// comments (`#` or `//` to the end of the line).
func tokens(text string) []string {
	var result []string
	for _, line := range strings.Split(text, "\n") {
		if index := strings.Index(line, "//"); index >= 0 {
			line = line[:index]
		}
		if index := strings.Index(line, "#"); index >= 0 {
			line = line[:index]
		}
		for _, field := range strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == ';'
		}) {
			result = append(result, field)
		}
	}
	return result
}

// NormalizeDomain lowercases a domain and strips a leading "*." or ".", which
// all mean "this domain and its subdomains". A bare TLD such as "ua" is
// accepted on purpose: community lists use ".ua" for a whole zone.
func NormalizeDomain(value string) (string, bool) {
	domain := strings.ToLower(strings.TrimSpace(value))
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimPrefix(domain, ".")
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" || len(domain) > 253 {
		return "", false
	}
	for _, label := range strings.Split(domain, ".") {
		if !domainLabel.MatchString(label) {
			return "", false
		}
	}
	return domain, true
}

// ParseDomains returns unique valid domains and the entries it rejected.
func ParseDomains(text string) ([]string, []string) {
	seen := map[string]bool{}
	var domains, invalid []string
	for _, token := range tokens(text) {
		domain, ok := NormalizeDomain(token)
		if !ok {
			invalid = append(invalid, token)
			continue
		}
		if !seen[domain] {
			seen[domain] = true
			domains = append(domains, domain)
		}
	}
	sort.Strings(domains)
	return domains, invalid
}

// ParseSubnets accepts IPv4 addresses and prefixes; IPv6 entries are skipped
// (the daemon routes IPv4 and strips AAAA for routed domains).
func ParseSubnets(text string) ([]netip.Prefix, []string) {
	seen := map[netip.Prefix]bool{}
	var subnets []netip.Prefix
	var invalid []string
	for _, token := range tokens(text) {
		var prefix netip.Prefix
		var err error
		if strings.Contains(token, "/") {
			prefix, err = netip.ParsePrefix(token)
		} else {
			var address netip.Addr
			address, err = netip.ParseAddr(token)
			if err == nil {
				prefix = netip.PrefixFrom(address, address.BitLen())
			}
		}
		if err != nil {
			invalid = append(invalid, token)
			continue
		}
		if !prefix.Addr().Is4() {
			continue
		}
		prefix = prefix.Masked()
		if !seen[prefix] {
			seen[prefix] = true
			subnets = append(subnets, prefix)
		}
	}
	return subnets, invalid
}

func defaultZapret() Zapret {
	return Zapret{
		Enabled:       true,
		Binary:        "/usr/lib/flowcloud/zapret2/nfqws2",
		LuaDir:        "/usr/lib/flowcloud/zapret2/lua",
		Queue:         300,
		Strategy:      "auto",
		CheckInterval: 5 * time.Minute,
		TestURLs: []string{
			"https://www.youtube.com/",
			"https://i.ytimg.com/generate_204",
			"https://redirector.googlevideo.com/report_mapping",
		},
	}
}

func readZapret(zapret *Zapret, section *uci.Section) error {
	zapret.Enabled = section.Bool("enabled", zapret.Enabled)
	zapret.Binary = section.Get("binary", zapret.Binary)
	zapret.LuaDir = section.Get("lua_dir", zapret.LuaDir)
	zapret.Strategy = section.Get("strategy", zapret.Strategy)
	zapret.CustomArgs = section.Get("custom_args", "")
	if value := section.Get("queue", ""); value != "" {
		queue, err := strconv.Atoi(value)
		if err != nil || queue < 0 || queue > 65535 {
			return fmt.Errorf("zapret: queue must be 0-65535")
		}
		zapret.Queue = queue
	}
	if value := section.Get("check_interval", ""); value != "" {
		seconds, err := strconv.Atoi(value)
		if err != nil || seconds < 60 || seconds > 86400 {
			return fmt.Errorf("zapret: check_interval must be 60-86400 seconds")
		}
		zapret.CheckInterval = time.Duration(seconds) * time.Second
	}
	if urls := section.List("test_url"); len(urls) > 0 {
		for _, url := range urls {
			if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
				return fmt.Errorf("zapret: test URL %q must start with http:// or https://", url)
			}
		}
		zapret.TestURLs = urls
	}
	if zapret.Strategy == "custom" && strings.TrimSpace(zapret.CustomArgs) == "" {
		return fmt.Errorf("zapret: the custom strategy needs nfqws2 arguments")
	}
	return nil
}
