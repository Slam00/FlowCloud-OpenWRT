// Package daemon runs FlowCloud on the router: it keeps the WARP and
// interface tunnels, the section lists, the DNS proxy and the nftables and
// routing state in line with the `flowcloud` UCI config.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"flowcloud-openwrt/internal/config"
	"flowcloud-openwrt/internal/dnsproxy"
	"flowcloud-openwrt/internal/lists"
	"flowcloud-openwrt/internal/netx"
	"flowcloud-openwrt/internal/nft"
	"flowcloud-openwrt/internal/route"
	"flowcloud-openwrt/internal/system"
	"flowcloud-openwrt/internal/uci"
)

type Options struct {
	ConfigName string
	StateDir   string // persistent: accounts, endpoint caches, lists
	RunDir     string // volatile: status, pid
	Version    string
}

// Signals the daemon reacts to.
type Signals struct {
	Reload      <-chan struct{}
	UpdateLists <-chan struct{}
	// Switch asks WARP tunnels with a request file (RequestSwitch) to move
	// to another endpoint now.
	Switch <-chan struct{}
}

type Daemon struct {
	opts  Options
	board *statusBoard

	mutex    sync.Mutex
	cfg      *config.Config
	store    *lists.Store
	proxy    *dnsproxy.Proxy
	adder    *nft.Adder
	resolved map[string]lists.Result
	bypass   map[string][]netip.Prefix // extra bypass prefixes by tunnel
	// recent outlives reloads, so zapret checks keep the hosts in use.
	recent *dnsproxy.Recent
	// switches holds a channel per running WARP tunnel for manual switches.
	switches map[string]chan struct{}
}

func New(opts Options) *Daemon {
	return &Daemon{
		opts:   opts,
		board:  &statusBoard{path: filepath.Join(opts.RunDir, "status.json")},
		recent: &dnsproxy.Recent{},
	}
}

// StatusPath is where `flowcloudd status` reads from.
func StatusPath(runDir string) string { return filepath.Join(runDir, "status.json") }

// Run serves until ctx ends, reloading the config on every Reload signal.
func (d *Daemon) Run(ctx context.Context, signals Signals) error {
	_ = os.MkdirAll(d.opts.RunDir, 0o755)
	// The init script's restart leaves this flag so the stopping daemon keeps
	// dnsmasq pointed at FlowCloud; the new daemon clears it.
	_ = os.Remove(d.restartFlag())
	_ = os.WriteFile(filepath.Join(d.opts.RunDir, "flowcloudd.pid"), []byte(fmt.Sprint(os.Getpid())), 0o644)
	defer os.Remove(filepath.Join(d.opts.RunDir, "flowcloudd.pid"))
	d.board.update(func(status *Status) {
		status.Version = d.opts.Version
		status.StartedAt = time.Now().Unix()
	})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-signals.Switch:
				d.deliverSwitches()
			}
		}
	}()
	for {
		runContext, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- d.runOnce(runContext, signals.UpdateLists) }()
		select {
		case <-ctx.Done():
			cancel()
			<-done
			d.shutdown(true)
			return nil
		case <-signals.Reload:
			log.Printf("reloading configuration")
			cancel()
			<-done
			d.shutdown(false)
		case err := <-done:
			cancel()
			d.shutdown(false)
			if err != nil {
				log.Printf("stopped: %v", err)
				d.board.update(func(status *Status) { status.Running = false; status.Error = err.Error() })
				d.board.write()
			}
			// Wait for a config change (reload) or exit.
			select {
			case <-ctx.Done():
				d.shutdown(true)
				return nil
			case <-signals.Reload:
			}
		}
	}
}

func (d *Daemon) loadConfig() (*config.Config, error) {
	sections, err := uci.Load(d.opts.ConfigName)
	if err != nil {
		return nil, err
	}
	return config.FromUCI(sections)
}

func (d *Daemon) runOnce(ctx context.Context, updateLists <-chan struct{}) error {
	cfg, err := d.loadConfig()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	d.dropStaleWarpDevices(cfg)
	d.board.update(func(status *Status) {
		*status = Status{Version: d.opts.Version, StartedAt: status.StartedAt}
		status.DNS.Listen = cfg.Settings.DNSListen
		status.DNS.Upstreams = cfg.Settings.DNSUpstreams
		status.DNS.Dnsmasq = cfg.Settings.DnsmasqIntegration
		for _, tunnel := range cfg.Tunnels {
			state := "starting"
			if !tunnel.Enabled {
				state = "disabled"
			}
			status.Tunnels = append(status.Tunnels, TunnelStatus{Name: tunnel.Name, Index: tunnel.Index, Type: tunnel.Type, Device: tunnel.Device, State: state, PingMs: -1, MedianMs: -1})
		}
	})
	if !cfg.Settings.Enabled {
		d.board.update(func(status *Status) { status.Error = "FlowCloud is disabled in settings" })
		d.board.write()
		<-ctx.Done()
		return nil
	}

	upstreams := make([]dnsproxy.Upstream, 0, len(cfg.Settings.DNSUpstreams))
	for _, value := range cfg.Settings.DNSUpstreams {
		upstream, err := dnsproxy.ParseUpstream(value)
		if err != nil {
			return fmt.Errorf("DNS upstream: %w", err)
		}
		upstreams = append(upstreams, upstream)
	}

	d.mutex.Lock()
	d.cfg = cfg
	d.store = lists.NewStore(filepath.Join(d.opts.StateDir, "lists"), netx.DirectHTTPClient(60*time.Second))
	d.adder = nft.NewAdder()
	d.bypass = map[string][]netip.Prefix{}
	d.resolved = map[string]lists.Result{}
	d.mutex.Unlock()

	d.resolveSections()
	ruleset := d.ruleset()
	if err := nft.Apply(ruleset.Render()); err != nil {
		return err
	}
	d.restoreLearned(ruleset)
	route.Cleanup(config.MaxTunnels)
	for _, tunnel := range cfg.Tunnels {
		if tunnel.Enabled {
			if err := route.Install(tunnel.Index); err != nil {
				return err
			}
		}
	}

	d.proxy = &dnsproxy.Proxy{
		Listen:     cfg.Settings.DNSListen,
		Upstreams:  upstreams,
		StripAAAA:  cfg.Settings.StripAAAA,
		MinTimeout: cfg.Settings.MinSetTimeout,
		Adder:      d.adder,
		Recent:     d.recent,
	}
	d.proxy.SetState(d.dnsState())
	dnsErrors := make(chan error, 1)
	go func() { dnsErrors <- d.proxy.Serve(ctx) }()

	backupPath := filepath.Join(d.opts.StateDir, "dnsmasq-backup.json")
	if cfg.Settings.DnsmasqIntegration {
		if err := takeOverDnsmasq(cfg.Settings.DNSListen, backupPath); err != nil {
			d.warn("dnsmasq: " + err.Error())
		}
	} else if err := restoreDnsmasq(cfg.Settings.DNSListen, backupPath); err != nil {
		d.warn("dnsmasq: " + err.Error())
	}
	if podkopRunning() && cfg.Settings.DnsmasqIntegration {
		d.warn("podkop is running: both services redirect DNS and mark traffic; disable one of them")
	}

	// Only tunnels an enabled section routes to are brought up: an unused WARP
	// tunnel would keep probing endpoints and holding memory for nothing.
	used := map[string]bool{}
	d.mutex.Lock()
	for _, section := range d.activeSections() {
		if section.Action == config.ActionTunnel {
			used[section.Tunnel] = true
		}
	}
	d.mutex.Unlock()
	var wait sync.WaitGroup
	for _, tunnel := range cfg.Tunnels {
		if !tunnel.Enabled {
			if tunnel.Type == config.TunnelWarp {
				removeWarpDevice(tunnel.Device)
			}
			continue
		}
		if !used[tunnel.Name] {
			d.board.tunnel(tunnel.Name, func(status *TunnelStatus) {
				status.State = "idle"
				status.Error = ""
			})
			if tunnel.Type == config.TunnelWarp {
				removeWarpDevice(tunnel.Device)
			}
			continue
		}
		wait.Add(1)
		go func(tunnel *config.Tunnel) {
			defer wait.Done()
			switch tunnel.Type {
			case config.TunnelWarp:
				d.runWarp(ctx, tunnel)
			case config.TunnelInterface:
				d.runInterface(ctx, tunnel)
			}
		}(tunnel)
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		d.runLists(ctx, updateLists)
	}()
	d.mutex.Lock()
	runZapret := cfg.Zapret.Enabled && d.zapretWanted()
	d.mutex.Unlock()
	if runZapret {
		wait.Add(1)
		go func() {
			defer wait.Done()
			d.runZapret(ctx, cfg.Zapret)
		}()
	}

	d.board.update(func(status *Status) { status.Running = true })
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		d.refreshStatus()
		d.board.write()
		select {
		case <-ctx.Done():
			wait.Wait()
			return nil
		case err := <-dnsErrors:
			if err != nil {
				wait.Wait()
				return fmt.Errorf("DNS proxy on %s: %w", cfg.Settings.DNSListen, err)
			}
		case <-ticker.C:
		}
	}
}

// shutdown removes everything the daemon installed. dnsmasq is restored only
// when the daemon exits, so a reload does not restart it needlessly.
func (d *Daemon) shutdown(final bool) {
	d.mutex.Lock()
	cfg := d.cfg
	d.mutex.Unlock()
	d.saveLearned()
	_ = nft.Delete()
	route.Cleanup(config.MaxTunnels)
	if cfg != nil {
		// A reload or a restart keeps the WARP devices with their sessions:
		// the next run adopts a device that still carries traffic instead of
		// selecting again, which on some networks costs tens of seconds
		// before a fresh flow passes data.
		_, restartErr := os.Stat(d.restartFlag())
		keep := !final || restartErr == nil
		var kept []string
		for _, tunnel := range cfg.Tunnels {
			if tunnel.Type != config.TunnelWarp {
				continue
			}
			if keep && tunnel.Enabled && system.LinkExists(tunnel.Device) {
				kept = append(kept, tunnel.Device)
				continue
			}
			removeWarpDevice(tunnel.Device)
		}
		if len(kept) > 0 {
			_ = os.WriteFile(d.keptDevicesPath(), []byte(strings.Join(kept, "\n")+"\n"), 0o644)
		}
		_, restarting := os.Stat(d.restartFlag())
		if final && cfg.Settings.DnsmasqIntegration && restarting != nil {
			_ = restoreDnsmasq(cfg.Settings.DNSListen, filepath.Join(d.opts.StateDir, "dnsmasq-backup.json"))
		}
	}
	d.board.update(func(status *Status) { status.Running = false })
	d.board.write()
}

func (d *Daemon) warn(message string) {
	log.Printf("warning: %s", message)
	d.board.update(func(status *Status) {
		for _, existing := range status.Warnings {
			if existing == message {
				return
			}
		}
		status.Warnings = append(status.Warnings, message)
	})
}

func podkopRunning() bool {
	output, err := system.Run("pgrep", "-f", "sing-box run")
	return err == nil && strings.TrimSpace(output) != ""
}

// activeSections are the enabled sections whose tunnel exists and is enabled.
func (d *Daemon) activeSections() []*config.Section {
	var result []*config.Section
	for _, section := range d.cfg.Sections {
		if !section.Enabled {
			continue
		}
		if section.Action == config.ActionTunnel {
			tunnel := d.cfg.Tunnel(section.Tunnel)
			if tunnel == nil || !tunnel.Enabled {
				continue
			}
		}
		result = append(result, section)
	}
	return result
}

func (d *Daemon) resolveSections() {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	for _, section := range d.activeSections() {
		d.resolved[section.Name] = d.store.Resolve(section)
	}
}

func (d *Daemon) sectionMark(section *config.Section) (uint32, bool) {
	switch section.Action {
	case config.ActionBlock:
		return 0, true
	case config.ActionDirect:
		return netx.MarkDirect, false
	case config.ActionZapret:
		return netx.MarkZapret, false
	default:
		return netx.TunnelMark(d.cfg.Tunnel(section.Tunnel).Index), false
	}
}

func (d *Daemon) bypassPrefixes() []netip.Prefix {
	var prefixes []netip.Prefix
	for _, extra := range d.bypass {
		prefixes = append(prefixes, extra...)
	}
	return prefixes
}

func (d *Daemon) ruleset() nft.Ruleset {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	ruleset := nft.Ruleset{
		SourceInterfaces: d.cfg.Settings.SourceInterfaces,
		RouteRouter:      d.cfg.Settings.RouteRouterTraffic,
		Bypass:           d.bypassPrefixes(),
		DNSTimeout:       d.cfg.Settings.MinSetTimeout,
		ZapretQueue:      d.zapretQueue(),
	}
	for _, section := range d.activeSections() {
		mark, block := d.sectionMark(section)
		ruleset.Rules = append(ruleset.Rules, nft.Rule{
			Section: section.Name,
			Mark:    mark,
			Block:   block,
			Subnets: d.resolved[section.Name].Subnets,
		})
	}
	return ruleset
}

func (d *Daemon) dnsState() *dnsproxy.State {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	var domains [][]string
	var routes []dnsproxy.Route
	for _, section := range d.activeSections() {
		domains = append(domains, d.resolved[section.Name].Domains)
		routes = append(routes, dnsproxy.Route{Section: section.Name, Watch: section.Action == config.ActionZapret})
	}
	return &dnsproxy.State{Matcher: dnsproxy.NewMatcher(domains), Routes: routes}
}

// applySubnets reloads the static subnet sets without touching learned IPs.
func (d *Daemon) applySubnets() error {
	ruleset := d.ruleset()
	var b strings.Builder
	for _, rule := range ruleset.Rules {
		fmt.Fprintf(&b, "flush set inet %s %s\n", nft.Table, nft.NetSet(rule.Section))
		if len(rule.Subnets) > 0 {
			parts := make([]string, len(rule.Subnets))
			for index, prefix := range rule.Subnets {
				parts[index] = prefix.String()
			}
			fmt.Fprintf(&b, "add element inet %s %s { %s }\n", nft.Table, nft.NetSet(rule.Section), strings.Join(parts, ", "))
		}
	}
	return nft.Apply(b.String())
}

// setBypass replaces a tunnel's extra bypass prefixes and reloads the set.
func (d *Daemon) setBypass(tunnel string, prefixes []netip.Prefix) {
	d.mutex.Lock()
	previous := d.bypass[tunnel]
	same := len(previous) == len(prefixes)
	for index := 0; same && index < len(prefixes); index++ {
		same = previous[index] == prefixes[index]
	}
	if same {
		d.mutex.Unlock()
		return
	}
	d.bypass[tunnel] = prefixes
	all := d.bypassPrefixes()
	d.mutex.Unlock()
	parts := make([]string, len(all))
	for index, prefix := range all {
		parts[index] = prefix.String()
	}
	script := fmt.Sprintf("flush set inet %s bypass\n", nft.Table)
	if len(parts) > 0 {
		script += fmt.Sprintf("add element inet %s bypass { %s }\n", nft.Table, strings.Join(parts, ", "))
	}
	if err := nft.Apply(script); err != nil {
		log.Printf("bypass: %v", err)
	}
}

func (d *Daemon) runLists(ctx context.Context, updateLists <-chan struct{}) {
	// failed is set when some lists did not download; they are retried soon
	// instead of at the next daily update (at boot DNS is often not up yet).
	failed := false
	update := func() {
		failed = false
		d.mutex.Lock()
		var sources []lists.Source
		for _, section := range d.activeSections() {
			sectionSources, _ := lists.Sources(section)
			sources = append(sources, sectionSources...)
		}
		store := d.store
		d.mutex.Unlock()
		if len(sources) == 0 {
			return
		}
		fetchContext, cancel := context.WithTimeout(ctx, 5*time.Minute)
		errs := store.FetchAll(fetchContext, sources)
		cancel()
		if ctx.Err() != nil {
			return
		}
		messages := make([]string, 0, len(errs))
		for _, err := range errs {
			messages = append(messages, err.Error())
		}
		sort.Strings(messages)
		d.resolveSections()
		if err := d.applySubnets(); err != nil {
			messages = append(messages, err.Error())
		}
		d.proxy.SetState(d.dnsState())
		d.board.update(func(status *Status) {
			status.ListsUpdated = time.Now().Unix()
			status.ListErrors = messages
		})
		log.Printf("lists updated: %d sources, %d errors", len(sources), len(errs))
		failed = len(errs) > 0
	}
	update()
	ticker := time.NewTicker(d.cfg.Settings.UpdateInterval)
	defer ticker.Stop()
	for {
		// A nil channel never fires: the retry is armed only after a failure.
		var retry <-chan time.Time
		if failed {
			retry = time.After(listRetryDelay)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			update()
		case <-updateLists:
			update()
		case <-retry:
			update()
		}
	}
}

const listRetryDelay = 2 * time.Minute

func (d *Daemon) refreshStatus() {
	d.mutex.Lock()
	cfg := d.cfg
	resolved := d.resolved
	d.mutex.Unlock()
	if cfg == nil {
		return
	}
	var sections []SectionStatus
	for _, section := range cfg.Sections {
		result := resolved[section.Name]
		sections = append(sections, SectionStatus{
			Name:    section.Name,
			Enabled: section.Enabled,
			Action:  section.Action,
			Tunnel:  section.Tunnel,
			Domains: len(result.Domains),
			Subnets: len(result.Subnets),
			Missing: result.Missing,
			Invalid: section.InvalidUserEntries,
		})
	}
	d.board.update(func(status *Status) {
		status.Sections = sections
		if d.proxy != nil {
			status.DNS.Queries = d.proxy.Stats.Queries.Load()
			status.DNS.Matched = d.proxy.Stats.Matched.Load()
			status.DNS.Learned = d.proxy.Stats.Learned.Load()
			status.DNS.Failures = d.proxy.Stats.Failures.Load()
		}
	})
}

// endpointPrefixes turns "ip:port" endpoints into /32 prefixes.
func endpointPrefixes(endpoints []string) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, endpoint := range endpoints {
		host, _, err := net.SplitHostPort(endpoint)
		if err != nil {
			continue
		}
		address, err := netip.ParseAddr(host)
		if err != nil || !address.Is4() {
			continue
		}
		prefixes = append(prefixes, netip.PrefixFrom(address, 32))
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].Addr().Less(prefixes[j].Addr()) })
	return prefixes
}

var errStopped = errors.New("stopped")

func (d *Daemon) restartFlag() string { return filepath.Join(d.opts.RunDir, "restarting") }

// keptDevicesPath lists the WARP devices the previous run left up.
func (d *Daemon) keptDevicesPath() string { return filepath.Join(d.opts.RunDir, "warp-kept") }

// dropStaleWarpDevices removes devices the previous run kept that no
// enabled WARP tunnel of cfg uses (a tunnel removed, renamed or disabled).
func (d *Daemon) dropStaleWarpDevices(cfg *config.Config) {
	data, err := os.ReadFile(d.keptDevicesPath())
	_ = os.Remove(d.keptDevicesPath())
	if err != nil {
		return
	}
	wanted := map[string]bool{}
	for _, tunnel := range cfg.Tunnels {
		if tunnel.Type == config.TunnelWarp && tunnel.Enabled && cfg.Settings.Enabled {
			wanted[tunnel.Device] = true
		}
	}
	for _, device := range strings.Fields(string(data)) {
		if !wanted[device] {
			removeWarpDevice(device)
		}
	}
}

func (d *Daemon) learnedPath() string { return filepath.Join(d.opts.RunDir, "learned.json") }

// saveLearned keeps the addresses learned through DNS across a reload or
// restart: without them established flows would leave their tunnel and new
// ones would go direct until clients ask DNS again.
func (d *Daemon) saveLearned() {
	d.mutex.Lock()
	var sets []string
	if d.cfg != nil {
		for _, section := range d.activeSections() {
			sets = append(sets, nft.DNSSet(section.Name))
		}
	}
	d.mutex.Unlock()
	elements, err := nft.Dump(sets)
	if err != nil || len(elements) == 0 {
		return
	}
	data, err := nft.MarshalElements(elements, time.Now())
	if err == nil {
		_ = os.WriteFile(d.learnedPath(), data, 0o600)
	}
}

func (d *Daemon) restoreLearned(ruleset nft.Ruleset) {
	data, err := os.ReadFile(d.learnedPath())
	if err != nil {
		return
	}
	_ = os.Remove(d.learnedPath())
	existing := map[string]bool{}
	for _, rule := range ruleset.Rules {
		existing[nft.DNSSet(rule.Section)] = true
	}
	elements := nft.UnmarshalElements(data, time.Now())
	if err := nft.Restore(elements, existing); err != nil {
		log.Printf("learned addresses not restored: %v", err)
		return
	}
	log.Printf("restored %d learned addresses", len(elements))
}
