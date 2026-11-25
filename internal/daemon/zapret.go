package daemon

import (
	"context"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"flowcloud-openwrt/internal/config"
	"flowcloud-openwrt/internal/netx"
	"flowcloud-openwrt/internal/system"
	"flowcloud-openwrt/internal/zapret"
)

// ZapretStatus is what LuCI shows for zapret2.
type ZapretStatus struct {
	Active    bool               `json:"active"`
	State     string             `json:"state"` // starting, ok, failing, searching, error, unavailable
	Strategy  string             `json:"strategy,omitempty"`
	Label     string             `json:"label,omitempty"`
	Auto      bool               `json:"auto"`
	CheckedAt int64              `json:"checked_at,omitempty"`
	Results   []zapret.URLResult `json:"results,omitempty"`
	Switches  int                `json:"switches"`
	Error     string             `json:"error,omitempty"`
}

const (
	zapretRecheckDelay = 10 * time.Second
	zapretSettleDelay  = 2 * time.Second
	// networkCheckURL tells "the network is down" from "the DPI blocks the
	// test hosts": without it a dead uplink would start a strategy search.
	networkCheckURL = "https://1.1.1.1/cdn-cgi/trace"
	// A check also opens up to zapretRecentHosts hosts devices resolved in
	// the last zapretRecentAge; a host no strategy opens is skipped for
	// zapretIgnoreFor.
	zapretRecentHosts = 3
	zapretRecentAge   = 15 * time.Minute
	zapretIgnoreFor   = time.Hour
)

// zapretWanted reports whether an active section uses zapret2.
func (d *Daemon) zapretWanted() bool {
	for _, section := range d.activeSections() {
		if section.Action == config.ActionZapret {
			return true
		}
	}
	return false
}

// zapretQueue is the queue for the ruleset: 0 when zapret2 is off or not
// installed, so "zapret" sections still go direct.
func (d *Daemon) zapretQueue() int {
	if !d.cfg.Zapret.Enabled || !d.zapretWanted() {
		return 0
	}
	if zapret.Available(d.cfg.Zapret.Binary, d.cfg.Zapret.LuaDir) != nil {
		return 0
	}
	return d.cfg.Zapret.Queue
}

func (d *Daemon) zapretStatus(change func(*ZapretStatus)) {
	d.board.update(func(status *Status) {
		if status.Zapret == nil {
			status.Zapret = &ZapretStatus{}
		}
		change(status.Zapret)
	})
}

// runZapret supervises nfqws2 and, in auto mode, moves to another strategy
// when the test URLs stop opening through it.
func (d *Daemon) runZapret(ctx context.Context, z config.Zapret) {
	d.zapretStatus(func(status *ZapretStatus) {
		*status = ZapretStatus{Active: true, State: "starting", Auto: z.Strategy == "auto"}
	})
	if err := zapret.Available(z.Binary, z.LuaDir); err != nil {
		d.zapretStatus(func(status *ZapretStatus) { status.State = "unavailable"; status.Error = err.Error() })
		d.warn("zapret2: " + err.Error() + "; zapret sections go direct")
		return
	}
	// nfqws2 needs conntrack to accept the out-of-window packets it sends.
	_, _ = system.Run("sysctl", "-w", "net.netfilter.nf_conntrack_tcp_be_liberal=1")

	statePath := filepath.Join(d.opts.StateDir, "zapret-strategy")
	process := &zapret.Process{Binary: z.Binary}
	defer process.Stop()

	current := zapret.Strategies[0]
	switch z.Strategy {
	case "auto":
		if data, err := os.ReadFile(statePath); err == nil {
			if saved, ok := zapret.Lookup(strings.TrimSpace(string(data))); ok {
				current = saved
			}
		}
	case "custom":
		current = zapret.Strategy{Name: "custom", Label: "custom"}
	default:
		if chosen, ok := zapret.Lookup(z.Strategy); ok {
			current = chosen
		}
	}
	custom := ""
	if z.Strategy == "custom" {
		custom = z.CustomArgs
	}

	start := func(strategy zapret.Strategy) error {
		args := zapret.Args(filepath.Dir(z.Binary), z.LuaDir, z.Queue, strategy, custom)
		if err := zapret.Validate(z.Binary, args); err != nil {
			return err
		}
		process.Start(ctx, args)
		d.zapretStatus(func(status *ZapretStatus) {
			status.Strategy = strategy.Name
			status.Label = strategy.Label
		})
		return nil
	}
	if err := start(current); err != nil {
		log.Printf("zapret: %v", err)
		d.zapretStatus(func(status *ZapretStatus) { status.State = "error"; status.Error = err.Error() })
		return
	}
	log.Printf("zapret: nfqws2 started with strategy %s", current.Name)

	// Besides the test URLs, a check opens a few hosts LAN devices resolved
	// lately in zapret sections: a nearby Google cache node can sit behind
	// a DPI that the main YouTube servers do not, and only a strategy that
	// opens both keeps video working. Hosts no strategy opens (a dead or
	// IP-blocked server) are left out for a while so they cannot keep a
	// search going.
	testHosts := map[string]bool{}
	for _, raw := range z.TestURLs {
		if parsed, err := url.Parse(raw); err == nil {
			testHosts[strings.ToLower(parsed.Hostname())] = true
		}
	}
	ignored := map[string]time.Time{}
	var hosts []zapret.Host
	pickHosts := func() {
		hosts = nil
		now := time.Now()
		for _, host := range d.recent.Pick(zapretRecentHosts, zapretRecentAge, func(name string) bool {
			return testHosts[name] || now.Before(ignored[name])
		}) {
			hosts = append(hosts, zapret.Host{Name: host.Name, Address: host.Addresses[0].String()})
		}
	}
	// passed collects, during a search, the hosts some strategy opened.
	var passed map[string]bool
	probe := func() []zapret.URLResult {
		results := zapret.Probe(ctx, z.TestURLs, netx.MarkZapret)
		if len(hosts) > 0 {
			results = append(results, zapret.ProbeHosts(ctx, hosts, netx.MarkZapret)...)
		}
		if passed != nil {
			for _, result := range results {
				if result.OK {
					passed[result.URL] = true
				}
			}
		}
		d.zapretStatus(func(status *ZapretStatus) {
			status.Results = results
			status.CheckedAt = time.Now().Unix()
			if err := process.LastError(); err != "" {
				status.Error = err
			}
		})
		return results
	}

	if !sleep(ctx, 5*time.Second) {
		return
	}
	for ctx.Err() == nil {
		pickHosts()
		results := probe()
		if !zapret.AllOK(results) && sleep(ctx, zapretRecheckDelay) {
			results = probe()
		}
		if ctx.Err() != nil {
			return
		}
		if zapret.AllOK(results) {
			d.zapretStatus(func(status *ZapretStatus) { status.State = "ok"; status.Error = "" })
		} else {
			d.zapretStatus(func(status *ZapretStatus) { status.State = "failing" })
			network := zapret.Probe(ctx, []string{networkCheckURL}, netx.MarkDirect)
			switch {
			case !zapret.AllOK(network):
				d.zapretStatus(func(status *ZapretStatus) {
					status.Error = "нет доступа в интернет, подбор отложен"
				})
			case z.Strategy != "auto":
				d.zapretStatus(func(status *ZapretStatus) {
					status.Error = "тестовые адреса не открываются; включите автоподбор или смените стратегию"
				})
			default:
				count := 0
				passed = map[string]bool{}
				for _, result := range results {
					if result.OK {
						count++
						passed[result.URL] = true
					}
				}
				next, ok := d.searchZapret(ctx, current, count, start, probe)
				for _, host := range hosts {
					if !passed["tls://"+host.Name] && ctx.Err() == nil {
						ignored[host.Name] = time.Now().Add(zapretIgnoreFor)
						log.Printf("zapret: no strategy opens %s; not testing it for %s", host.Name, zapretIgnoreFor)
					}
				}
				passed = nil
				if ok {
					if next.Name != current.Name {
						_ = os.WriteFile(statePath, []byte(next.Name+"\n"), 0o644)
					}
					current = next
				} else if err := start(current); err != nil {
					log.Printf("zapret: restore %s: %v", current.Name, err)
				}
			}
		}
		if !sleep(ctx, z.CheckInterval) {
			return
		}
	}
}

// searchZapret tries the built-in strategies after current and returns the
// first that opens every test URL, or else the one that opened the most if
// it opens more than current (currentPassed). It reports false when nothing
// beats current, which the caller then restarts.
func (d *Daemon) searchZapret(ctx context.Context, current zapret.Strategy, currentPassed int,
	start func(zapret.Strategy) error, probe func() []zapret.URLResult) (zapret.Strategy, bool) {
	d.zapretStatus(func(status *ZapretStatus) { status.State = "searching" })
	log.Printf("zapret: test URLs fail with %s; searching for a working strategy", current.Name)
	offset := 0
	for index, strategy := range zapret.Strategies {
		if strategy.Name == current.Name {
			offset = index + 1
		}
	}
	best, bestOK := current, currentPassed
	for step := 0; step < len(zapret.Strategies) && ctx.Err() == nil; step++ {
		candidate := zapret.Strategies[(offset+step)%len(zapret.Strategies)]
		if candidate.Name == current.Name {
			continue
		}
		if err := start(candidate); err != nil {
			log.Printf("zapret: %s: %v", candidate.Name, err)
			continue
		}
		if !sleep(ctx, zapretSettleDelay) {
			return current, false
		}
		results := probe()
		passed := 0
		for _, result := range results {
			if result.OK {
				passed++
			}
		}
		log.Printf("zapret: strategy %s opens %d/%d test URLs", candidate.Name, passed, len(results))
		if passed == len(results) {
			d.zapretStatus(func(status *ZapretStatus) {
				status.State = "ok"
				status.Error = ""
				status.Switches++
			})
			log.Printf("zapret: switched to strategy %s", candidate.Name)
			return candidate, true
		}
		if passed > bestOK {
			best, bestOK = candidate, passed
		}
	}
	if best.Name != current.Name {
		if err := start(best); err == nil {
			d.zapretStatus(func(status *ZapretStatus) {
				status.State = "failing"
				status.Error = "ни одна стратегия не открыла все тестовые адреса; выбрана лучшая из найденных"
				status.Switches++
			})
			log.Printf("zapret: no strategy opens every test URL; using %s (%d)", best.Name, bestOK)
			return best, true
		}
	}
	d.zapretStatus(func(status *ZapretStatus) {
		status.State = "failing"
		status.Error = "ни одна стратегия не открыла больше адресов, чем текущая"
	})
	log.Printf("zapret: no strategy beats %s; keeping it", current.Name)
	return current, false
}
