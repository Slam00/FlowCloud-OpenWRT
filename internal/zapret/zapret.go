// Package zapret runs nfqws2 from zapret2 (https://github.com/bol-van/zapret2)
// for sections with the "zapret" action and picks a working DPI-bypass
// strategy automatically.
package zapret

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"flowcloud-openwrt/internal/netx"
)

// Strategy is a TLS desync recipe; QUIC and plain HTTP use fixed profiles.
type Strategy struct {
	Name  string
	Label string
	TLS   string
}

// Strategies are tried in order by the automatic selection. They follow the
// defaults of zapret2's config.default and the families blockcheck2 tests.
var Strategies = []Strategy{
	{"fake_md5_disorder", "fake (tcp_md5) + multidisorder", "--lua-desync=fake:blob=fake_default_tls:tcp_md5:tcp_seq=-10000 --lua-desync=multidisorder:pos=1,midsld"},
	{"fake_rndsni_seqovl", "fake (rnd SNI) + multisplit seqovl", "--lua-desync=fake:blob=fake_default_tls:tcp_md5:tls_mod=rnd,rndsni,dupsid --lua-desync=multisplit:pos=1:seqovl=5"},
	{"seqovl", "multisplit seqovl", "--lua-desync=multisplit:pos=1:seqovl=5"},
	{"disorder", "multidisorder", "--lua-desync=multidisorder:pos=1,midsld"},
	{"fake_badsum_disorder", "fake (badsum) + multidisorder", "--lua-desync=fake:blob=fake_default_tls:badsum --lua-desync=multidisorder:pos=midsld"},
	{"fake_autottl_split", "fake (autottl) + multisplit", "--lua-desync=fake:blob=fake_default_tls:ip_autottl=-2,3-20 --lua-desync=multisplit:pos=midsld"},
	{"fake_ttl4_disorder", "fake (ttl 4) + multidisorder", "--lua-desync=fake:blob=fake_default_tls:ip_ttl=4 --lua-desync=multidisorder:pos=1,midsld"},
	{"double_fake_disorder", "2 fakes (tcp_md5) + multidisorder", "--lua-desync=fake:blob=0x00000000:tcp_md5 --lua-desync=fake:blob=fake_default_tls:tcp_md5:tls_mod=rnd,dupsid --lua-desync=multidisorder:pos=midsld"},
}

const (
	quicProfile = "--filter-udp=443 --filter-l7=quic --payload=quic_initial --lua-desync=fake:blob=fake_default_quic:repeats=6"
	httpProfile = "--filter-tcp=80 --filter-l7=http --payload=http_req --lua-desync=fake:blob=fake_default_http:tcp_md5 --lua-desync=multisplit:pos=method+2"
	tlsFilter   = "--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello"
)

// Lookup returns a built-in strategy.
func Lookup(name string) (Strategy, bool) {
	for _, strategy := range Strategies {
		if strategy.Name == name {
			return strategy, true
		}
	}
	return Strategy{}, false
}

// Args builds the nfqws2 command line for a strategy; custom holds complete
// profile arguments and replaces the built-in profiles.
func Args(binaryDir, luaDir string, queue int, strategy Strategy, custom string) []string {
	args := []string{
		"--qnum=" + strconv.Itoa(queue),
		fmt.Sprintf("--fwmark=0x%x", netx.DesyncMark),
	}
	for _, lua := range []string{"zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua"} {
		args = append(args, "--lua-init=@"+path.Join(luaDir, lua))
	}
	profiles := custom
	if strings.TrimSpace(profiles) == "" {
		profiles = tlsFilter + " " + strategy.TLS + " --new " + quicProfile + " --new " + httpProfile
	}
	return append(args, strings.Fields(profiles)...)
}

// Available reports whether nfqws2 and its Lua libraries are installed.
func Available(binary, luaDir string) error {
	if info, err := os.Stat(binary); err != nil || info.IsDir() {
		return fmt.Errorf("nfqws2 is not installed at %s", binary)
	}
	if _, err := os.Stat(path.Join(luaDir, "zapret-lib.lua")); err != nil {
		return fmt.Errorf("zapret2 Lua libraries are missing in %s", luaDir)
	}
	return nil
}

// Validate runs nfqws2 --dry-run on the arguments.
func Validate(binary string, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, append([]string{"--dry-run"}, args...)...)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		lines := strings.Split(strings.TrimSpace(output.String()), "\n")
		return fmt.Errorf("nfqws2 rejected the strategy: %s", lines[len(lines)-1])
	}
	return nil
}

// Process supervises one nfqws2 instance and restarts it when it exits.
type Process struct {
	Binary string

	mutex   sync.Mutex
	args    []string
	cancel  context.CancelFunc
	done    chan struct{}
	lastErr string
}

// Start replaces the running instance with one using args.
func (p *Process) Start(parent context.Context, args []string) {
	p.Stop()
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	p.mutex.Lock()
	p.args, p.cancel, p.done = args, cancel, done
	p.mutex.Unlock()
	go func() {
		defer close(done)
		for _, arg := range args {
			if strings.HasPrefix(arg, "--qnum=") {
				killStray(p.Binary, arg)
			}
		}
		delay := time.Second
		for ctx.Err() == nil {
			started := time.Now()
			command := exec.CommandContext(ctx, p.Binary, args...)
			var output bytes.Buffer
			command.Stdout = io.Discard
			command.Stderr = &output
			err := command.Run()
			if ctx.Err() != nil {
				return
			}
			message := strings.TrimSpace(output.String())
			if index := strings.LastIndex(message, "\n"); index >= 0 {
				message = message[index+1:]
			}
			p.mutex.Lock()
			p.lastErr = fmt.Sprintf("nfqws2 exited: %v %s", err, message)
			p.mutex.Unlock()
			log.Printf("zapret: %s", p.lastErr)
			if time.Since(started) > time.Minute {
				delay = time.Second
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			if delay < 30*time.Second {
				delay *= 2
			}
		}
	}()
}

// Stop terminates the instance and waits for it.
func (p *Process) Stop() {
	p.mutex.Lock()
	cancel, done := p.cancel, p.done
	p.cancel, p.done = nil, nil
	p.mutex.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

// LastError is the last exit reason, if any.
func (p *Process) LastError() string {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.lastErr
}

// URLResult is the outcome of one test request.
type URLResult struct {
	URL   string `json:"url"`
	OK    bool   `json:"ok"`
	Bytes int64  `json:"bytes"`
	Ms    int64  `json:"ms"`
	Error string `json:"error,omitempty"`
}

const (
	probeTimeout = 12 * time.Second
	// DPI that lets a handshake through often freezes the flow after about
	// 16 KB; a page must deliver at least this much or end on its own.
	probeEnoughBytes = 64 * 1024
)

// Probe requests every URL with sockets carrying mark and reports which
// answered. A URL passes when its response ends normally or delivers
// probeEnoughBytes; the HTTP status does not matter.
func Probe(ctx context.Context, urls []string, mark uint32) []URLResult {
	results := make([]URLResult, len(urls))
	var wait sync.WaitGroup
	for index, url := range urls {
		wait.Add(1)
		go func(index int, url string) {
			defer wait.Done()
			results[index] = probeOne(ctx, url, mark)
		}(index, url)
	}
	wait.Wait()
	return results
}

// shortHello makes a small TLS 1.2 ClientHello of about 200 bytes, like
// Windows schannel and older devices send. Go's default hello is large (TLS
// 1.3 with a post-quantum key share, like current browsers), and some
// strategies (plain disorder, seqovl) pass it but not a short one: a URL
// passes only when both open.
var shortHello = &tls.Config{
	MaxVersion:       tls.VersionTLS12,
	CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
}

// Host is a host LAN devices use, tested by a TLS handshake with its name
// against an address they were given.
type Host struct {
	Name    string
	Address string
}

// ProbeHosts tests each host with both ClientHellos. A host passes when the
// handshake completes with a valid certificate: the DPI acts on the SNI, so a
// completed handshake means the flow got through.
func ProbeHosts(ctx context.Context, hosts []Host, mark uint32) []URLResult {
	results := make([]URLResult, len(hosts))
	var wait sync.WaitGroup
	for index, host := range hosts {
		wait.Add(1)
		go func(index int, host Host) {
			defer wait.Done()
			result := handshake(ctx, host, mark, &tls.Config{ServerName: host.Name})
			if result.OK {
				short := shortHello.Clone()
				short.ServerName = host.Name
				if second := handshake(ctx, host, mark, short); !second.OK {
					second.Error = "TLS 1.2: " + second.Error
					result = second
				}
			}
			results[index] = result
		}(index, host)
	}
	wait.Wait()
	return results
}

func handshake(ctx context.Context, host Host, mark uint32, config *tls.Config) URLResult {
	result := URLResult{URL: "tls://" + host.Name}
	probeContext, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	started := time.Now()
	dialer := &tls.Dialer{NetDialer: netx.MarkedDialer(mark, probeTimeout), Config: config}
	connection, err := dialer.DialContext(probeContext, "tcp", net.JoinHostPort(host.Address, "443"))
	result.Ms = time.Since(started).Milliseconds()
	if err != nil {
		result.Error = shortError(err)
		return result
	}
	connection.Close()
	result.OK = true
	return result
}

func probeOne(ctx context.Context, url string, mark uint32) URLResult {
	result := probeWith(ctx, url, mark, nil)
	if !result.OK || !strings.HasPrefix(url, "https://") {
		return result
	}
	short := probeWith(ctx, url, mark, shortHello)
	if !short.OK {
		short.Error = "TLS 1.2: " + short.Error
		return short
	}
	return result
}

func probeWith(ctx context.Context, url string, mark uint32, tlsConfig *tls.Config) URLResult {
	result := URLResult{URL: url}
	dialer := netx.MarkedDialer(mark, probeTimeout)
	transport := &http.Transport{
		DialContext:         dialer.DialContext,
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: probeTimeout,
		DisableKeepAlives:   true,
		// HTTP/1.1 keeps the request on one TCP flow the DPI can act on.
		ForceAttemptHTTP2: false,
	}
	client := &http.Client{Transport: transport, Timeout: probeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	probeContext, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(probeContext, http.MethodGet, url, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36")
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		result.Error = shortError(err)
		result.Ms = time.Since(started).Milliseconds()
		return result
	}
	defer response.Body.Close()
	read, err := io.CopyN(io.Discard, response.Body, probeEnoughBytes)
	result.Bytes = read
	result.Ms = time.Since(started).Milliseconds()
	switch {
	case err == nil, errors.Is(err, io.EOF):
		result.OK = true
	default:
		result.Error = fmt.Sprintf("stalled after %d bytes: %s", read, shortError(err))
	}
	return result
}

func shortError(err error) string {
	message := err.Error()
	if len(message) > 160 {
		message = message[:160] + "..."
	}
	return message
}

// AllOK reports whether every result passed.
func AllOK(results []URLResult) bool {
	if len(results) == 0 {
		return false
	}
	for _, result := range results {
		if !result.OK {
			return false
		}
	}
	return true
}

// AnyOK reports whether at least one result passed.
func AnyOK(results []URLResult) bool {
	for _, result := range results {
		if result.OK {
			return true
		}
	}
	return false
}
