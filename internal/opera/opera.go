// Package opera reaches sites through Opera VPN's free proxies (SurfEasy),
// whose exit addresses are abroad (Europe, Americas, Asia): a way past
// geo-blocks (ChatGPT, Gemini, Claude...) without a server of one's own.
//
// The SurfEasy API client and the proxy dialer come from opera-proxy
// (github.com/Snawoot/opera-proxy v1.15.0, MIT, Copyright (c) 2021 Snawoot).
// Opera's proxy addresses are blocked in Russia, so every connection to the
// API and the proxies is dialed through another tunnel (a WARP tunnel) by
// its fwmark; the sites still see Opera's exit address.
package opera

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"crypto/tls"

	"github.com/Snawoot/opera-proxy/dialer"
	se "github.com/Snawoot/opera-proxy/seclient"

	"flowcloud-openwrt/internal/netx"
)

const (
	// The public API credentials of Opera's browser client, as opera-proxy
	// uses them by default.
	apiLogin    = "se0316"
	apiPassword = "SILrMEPBmJuhomxWkfm3JalqHX2Eheg1YhlEZiMh8II"
	proxySuffix = "sec-tunnel.com"

	apiTimeout = 15 * time.Second
	// refreshEvery renews the login and the device password, as opera-proxy
	// does every four hours.
	refreshEvery = 4 * time.Hour
	// CheckTarget answers through a working proxy.
	CheckTarget = "1.1.1.1:443"
)

// Route is where the transparent proxy sends one connection: through Opera,
// or, for a site that is not the tunnel's own, the way it would have gone
// without the tunnel (Mark: a tunnel, zapret2 or direct), or nowhere.
type Route struct {
	Opera bool
	Mark  uint32
	Block bool
}

// Client keeps a session with Opera's proxy service.
type Client struct {
	// Country is EU, AM or AS.
	Country string
	// Mark is the fwmark of the tunnel that carries connections to Opera.
	Mark uint32

	mutex     sync.Mutex
	session   *se.SEClient
	endpoints []se.SEIPEntry
	selected  int
	dialers   []*dialer.ProxyDialer
	refreshed time.Time
}

// carrier dials through the tunnel with c.Mark.
func (c *Client) carrier() *net.Dialer { return netx.MarkedDialer(c.Mark, apiTimeout) }

// Start registers an anonymous device and discovers the proxies of Country.
func (c *Client) Start(ctx context.Context) error {
	carrier := c.carrier()
	// The API answers on its address without SNI and with a self-signed
	// certificate, like opera-proxy dials it; the proxies themselves are
	// verified by the dialer.
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	session, err := se.NewSEClient(apiLogin, apiPassword, &http.Transport{
		DialContext: carrier.DialContext,
		DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			connection, err := carrier.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return tls.Client(connection, tlsConfig), nil
		},
		ForceAttemptHTTP2:   true,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: apiTimeout,
	})
	if err != nil {
		return err
	}
	step := func(name string, call func(context.Context) error) error {
		callContext, cancel := context.WithTimeout(ctx, apiTimeout)
		defer cancel()
		if err := call(callContext); err != nil {
			return fmt.Errorf("opera %s: %w", name, err)
		}
		return nil
	}
	if err := step("registration", session.AnonRegister); err != nil {
		return err
	}
	if err := step("device registration", session.RegisterDevice); err != nil {
		return err
	}
	var endpoints []se.SEIPEntry
	err = step("discover", func(ctx context.Context) error {
		found, err := session.Discover(ctx, fmt.Sprintf("\"%s\",,", c.Country))
		endpoints = found
		return err
	})
	if err != nil {
		return err
	}
	if len(endpoints) == 0 {
		return errors.New("opera discover: no proxies for " + c.Country)
	}
	dialers := make([]*dialer.ProxyDialer, len(endpoints))
	for index, endpoint := range endpoints {
		dialers[index] = dialer.NewProxyDialer(
			dialer.WrapStringToCb(endpoint.NetAddr()),
			dialer.WrapStringToCb(fmt.Sprintf("%s0.%s", c.Country, proxySuffix)),
			dialer.WrapStringToCb(""),
			func() (string, error) { return dialer.BasicAuthHeader(session.GetProxyCredentials()), nil },
			nil,
			carrier)
	}
	c.mutex.Lock()
	c.session, c.endpoints, c.dialers, c.selected = session, endpoints, dialers, 0
	c.refreshed = time.Now()
	c.mutex.Unlock()
	return nil
}

// Refresh renews the login when it is due; the caller runs it periodically.
func (c *Client) Refresh(ctx context.Context) error {
	c.mutex.Lock()
	session, due := c.session, time.Since(c.refreshed) >= refreshEvery
	c.mutex.Unlock()
	if session == nil || !due {
		return nil
	}
	callContext, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	if err := session.Login(callContext); err != nil {
		return fmt.Errorf("opera login: %w", err)
	}
	callContext2, cancel2 := context.WithTimeout(ctx, apiTimeout)
	defer cancel2()
	if err := session.DeviceGeneratePassword(callContext2); err != nil {
		return fmt.Errorf("opera device password: %w", err)
	}
	c.mutex.Lock()
	c.refreshed = time.Now()
	c.mutex.Unlock()
	return nil
}

// Endpoint is the selected proxy's address.
func (c *Client) Endpoint() string {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if len(c.endpoints) == 0 {
		return ""
	}
	return c.endpoints[c.selected].NetAddr()
}

// Select tries the proxies in order from the current one and keeps the first
// that opens target; it returns the round trip of that connection.
func (c *Client) Select(ctx context.Context, target string) (time.Duration, error) {
	c.mutex.Lock()
	dialers, start := c.dialers, c.selected
	c.mutex.Unlock()
	if len(dialers) == 0 {
		return 0, errors.New("opera: not started")
	}
	var lastErr error
	for step := 0; step < len(dialers); step++ {
		index := (start + step) % len(dialers)
		dialContext, cancel := context.WithTimeout(ctx, apiTimeout)
		started := time.Now()
		connection, err := dialers[index].DialContext(dialContext, "tcp", target)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		elapsed := time.Since(started)
		connection.Close()
		c.mutex.Lock()
		c.selected = index
		c.mutex.Unlock()
		return elapsed, nil
	}
	return 0, fmt.Errorf("opera: no proxy answers: %w", lastErr)
}

// DialContext opens address (host:port) through the selected proxy.
func (c *Client) DialContext(ctx context.Context, address string) (net.Conn, error) {
	c.mutex.Lock()
	if len(c.dialers) == 0 {
		c.mutex.Unlock()
		return nil, errors.New("opera: not started")
	}
	proxy := c.dialers[c.selected]
	c.mutex.Unlock()
	return proxy.DialContext(ctx, "tcp", address)
}
