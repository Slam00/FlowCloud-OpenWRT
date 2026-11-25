//go:build linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"flowcloud-openwrt/internal/daemon"
	"flowcloud-openwrt/internal/netx"
	"flowcloud-openwrt/internal/zapret"
)

// diagRoute is one way to reach the target: direct, a tunnel or zapret2.
type diagRoute struct {
	Route   string           `json:"route"`
	Label   string           `json:"label"`
	PingsMs []int64          `json:"pings_ms"` // -1 is a failed TCP connect
	AvgMs   int64            `json:"avg_ms"`
	LossPct int              `json:"loss_pct"`
	Fetch   zapret.URLResult `json:"fetch"`
	mark    uint32
}

type diagReport struct {
	URL       string      `json:"url"`
	Address   string      `json:"address,omitempty"`
	Error     string      `json:"error,omitempty"`
	Routes    []diagRoute `json:"routes"`
	CheckedAt int64       `json:"checked_at"`
}

const (
	diagPings       = 3
	diagPingTimeout = 2 * time.Second
)

// diag measures the target through every route the service has: TCP
// connect time (a ping that works where ICMP is filtered) and a full HTTP
// fetch, the same test zapret2 checks use.
func diag(runDir, target string, asJSON bool) {
	report := diagReport{CheckedAt: time.Now().Unix()}
	rawURL, host, port, err := diagTarget(target)
	report.URL = rawURL
	if err == nil {
		var addresses []net.IP
		resolveContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		addresses, err = net.DefaultResolver.LookupIP(resolveContext, "ip4", host)
		cancel()
		if err == nil && len(addresses) > 0 {
			report.Address = addresses[0].String()
		}
	}
	if err != nil {
		report.Error = err.Error()
	} else {
		report.Routes = diagRoutes(runDir)
		var wait sync.WaitGroup
		for index := range report.Routes {
			wait.Add(1)
			go func(route *diagRoute) {
				defer wait.Done()
				route.ping(net.JoinHostPort(report.Address, port))
				route.Fetch = zapret.Probe(context.Background(), []string{rawURL}, route.mark)[0]
			}(&report.Routes[index])
		}
		wait.Wait()
	}

	if asJSON {
		encoded, _ := json.Marshal(report)
		fmt.Println(string(encoded))
		return
	}
	if report.Error != "" {
		fmt.Fprintln(os.Stderr, report.Error)
		os.Exit(1)
	}
	fmt.Printf("%s (%s)\n", report.URL, report.Address)
	for _, route := range report.Routes {
		fetch := "ok"
		if !route.Fetch.OK {
			fetch = "FAIL " + route.Fetch.Error
		}
		fmt.Printf("  %-18s ping %5d ms  loss %3d%%  fetch %6d ms %8d bytes  %s\n",
			route.Label, route.AvgMs, route.LossPct, route.Fetch.Ms, route.Fetch.Bytes, fetch)
	}
}

// diagTarget accepts a URL, host or host:port and returns the URL to fetch
// with the host and port to ping.
func diagTarget(target string) (string, string, string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", "", "", fmt.Errorf("no target")
	}
	if !strings.Contains(target, "://") {
		target = "https://" + target + "/"
	}
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return "", "", "", fmt.Errorf("invalid target %q", target)
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
		if parsed.Scheme == "http" {
			port = "80"
		}
	}
	return parsed.String(), parsed.Hostname(), port, nil
}

// diagRoutes lists direct, every tunnel that is up and zapret2 when it runs.
func diagRoutes(runDir string) []diagRoute {
	routes := []diagRoute{{Route: "direct", Label: "напрямую", mark: netx.MarkDirect}}
	data, err := os.ReadFile(daemon.StatusPath(runDir))
	if err != nil {
		return routes
	}
	var status daemon.Status
	if json.Unmarshal(data, &status) != nil || !status.Running {
		return routes
	}
	for _, tunnel := range status.Tunnels {
		if tunnel.State == "up" && tunnel.Index > 0 {
			routes = append(routes, diagRoute{Route: "tunnel:" + tunnel.Name, Label: tunnel.Name, mark: netx.TunnelMark(tunnel.Index)})
		}
	}
	if status.Zapret != nil && status.Zapret.Active && status.Zapret.State != "unavailable" && status.Zapret.State != "error" {
		routes = append(routes, diagRoute{Route: "zapret", Label: "zapret2", mark: netx.MarkZapret})
	}
	return routes
}

func (r *diagRoute) ping(address string) {
	var ok []int64
	for attempt := 0; attempt < diagPings; attempt++ {
		if attempt > 0 {
			time.Sleep(300 * time.Millisecond)
		}
		started := time.Now()
		connection, err := netx.MarkedDialer(r.mark, diagPingTimeout).Dial("tcp4", address)
		if err != nil {
			r.PingsMs = append(r.PingsMs, -1)
			continue
		}
		connection.Close()
		ms := time.Since(started).Milliseconds()
		if ms == 0 {
			ms = 1
		}
		r.PingsMs = append(r.PingsMs, ms)
		ok = append(ok, ms)
	}
	r.AvgMs = -1
	if len(ok) > 0 {
		sort.Slice(ok, func(i, j int) bool { return ok[i] < ok[j] })
		var sum int64
		for _, ms := range ok {
			sum += ms
		}
		r.AvgMs = sum / int64(len(ok))
	}
	r.LossPct = (diagPings - len(ok)) * 100 / diagPings
}
