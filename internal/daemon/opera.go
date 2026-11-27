package daemon

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"flowcloud-openwrt/internal/config"
	"flowcloud-openwrt/internal/netx"
	"flowcloud-openwrt/internal/nft"
	"flowcloud-openwrt/internal/opera"
)

// operaRedirects lists the Opera tunnels of active sections for the
// ruleset; the caller holds d.mutex. Their sections' TCP always goes to the
// tunnel's transparent proxy, so while Opera is unreachable those sites fail
// rather than leak to the direct route (where they are geo-blocked anyway).
func (d *Daemon) operaRedirects() []nft.Redirect {
	var redirects []nft.Redirect
	seen := map[string]bool{}
	for _, section := range d.activeSections() {
		if section.Action != config.ActionTunnel || seen[section.Tunnel] {
			continue
		}
		tunnel := d.cfg.Tunnel(section.Tunnel)
		if tunnel == nil || tunnel.Type != config.TunnelOpera {
			continue
		}
		seen[section.Tunnel] = true
		redirects = append(redirects, nft.Redirect{Mark: netx.TunnelMark(tunnel.Index), Port: config.OperaPortBase + tunnel.Index})
	}
	return redirects
}

// runOpera serves an Opera tunnel: the transparent proxy for its sections and
// a session with Opera's proxies, dialed through the tunnel t.Via.
func (d *Daemon) runOpera(ctx context.Context, t *config.Tunnel) {
	d.mutex.Lock()
	via := d.cfg.Tunnel(t.Via)
	d.mutex.Unlock()
	if via == nil {
		d.board.tunnel(t.Name, func(status *TunnelStatus) { status.State = "error"; status.Error = "no tunnel to reach Opera" })
		return
	}
	client := &opera.Client{Country: t.Country, Mark: netx.TunnelMark(via.Index)}
	proxy := &opera.Transparent{Port: config.OperaPortBase + t.Index, Client: client, Name: t.Name}
	go func() {
		if err := proxy.Serve(ctx); err != nil {
			log.Printf("tunnel %s: transparent proxy: %v", t.Name, err)
			d.board.tunnel(t.Name, func(status *TunnelStatus) { status.State = "error"; status.Error = err.Error() })
		}
	}()

	for ctx.Err() == nil {
		d.board.tunnel(t.Name, func(status *TunnelStatus) { status.State = "starting"; status.Error = "" })
		// Without its carrier the dial would go out directly, where Opera
		// is blocked: wait for it (a WARP tunnel comes up within seconds).
		for waited := 0; d.board.tunnelState(via.Name) != "up" && waited < 90; waited++ {
			if !sleep(ctx, time.Second) {
				return
			}
		}
		err := client.Start(ctx)
		var rtt time.Duration
		if err == nil {
			rtt, err = client.Select(ctx, opera.CheckTarget)
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("tunnel %s: %v", t.Name, err)
			d.board.tunnel(t.Name, func(status *TunnelStatus) {
				status.State = "down"
				status.Error = fmt.Sprintf("%v (через %s)", err, via.Name)
				status.PingMs = -1
			})
			if !sleep(ctx, retryDelay) {
				return
			}
			continue
		}
		colo := operaExit(ctx, client)
		log.Printf("tunnel %s: Opera %s proxy %s through %s, exit %s, %s", t.Name, t.Country, client.Endpoint(),
			via.Name, orDash(colo), rtt.Round(time.Millisecond))
		d.board.tunnel(t.Name, func(status *TunnelStatus) {
			status.State = "up"
			status.Endpoint = client.Endpoint()
			status.Profile = "Opera " + t.Country + " через " + via.Name
			status.Colo = colo
			status.PingMs = max(rtt.Milliseconds(), 1)
			status.Error = ""
			status.Switches++
		})
		// Health: refresh the login when due and check the proxy; Select
		// moves to another proxy of the region when the current one fails.
		for ctx.Err() == nil {
			if !sleep(ctx, t.HealthInterval) {
				return
			}
			if err := client.Refresh(ctx); err != nil {
				log.Printf("tunnel %s: %v", t.Name, err)
			}
			rtt, err := client.Select(ctx, opera.CheckTarget)
			if err != nil {
				log.Printf("tunnel %s: %v; starting a new session", t.Name, err)
				break
			}
			d.board.tunnel(t.Name, func(status *TunnelStatus) {
				status.State = "up"
				status.Endpoint = client.Endpoint()
				status.PingMs = max(rtt.Milliseconds(), 1)
				status.CheckedAt = time.Now().Unix()
				status.Error = ""
			})
		}
	}
}

// operaExit reads the Cloudflare location Opera's exit is seen at. Opera's
// proxies open only port 443, so the trace goes over TLS.
func operaExit(ctx context.Context, client *opera.Client) string {
	dialContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := client.DialContext(dialContext, opera.CheckTarget)
	if err != nil {
		return ""
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	connection := tls.Client(raw, &tls.Config{ServerName: "one.one.one.one"})
	if _, err := io.WriteString(connection, "GET /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n"); err != nil {
		return ""
	}
	scanner := bufio.NewScanner(io.LimitReader(connection, 8192))
	for scanner.Scan() {
		if colo, ok := strings.CutPrefix(strings.TrimSpace(scanner.Text()), "colo="); ok {
			return colo
		}
	}
	return ""
}
