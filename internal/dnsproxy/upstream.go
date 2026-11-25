package dnsproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"flowcloud-openwrt/internal/netx"
)

// Upstream answers raw DNS messages.
type Upstream interface {
	Exchange(ctx context.Context, query []byte) ([]byte, error)
	String() string
}

// ParseUpstream accepts "https://host/path" (DoH), "tls://" is not supported,
// "udp://ip[:port]", "tcp://ip[:port]" or a bare "ip[:port]" (UDP).
func ParseUpstream(value string) (Upstream, error) {
	value = strings.TrimSpace(value)
	switch {
	case strings.HasPrefix(value, "https://"):
		if _, err := url.Parse(value); err != nil {
			return nil, err
		}
		return newDoH(value), nil
	case strings.HasPrefix(value, "tcp://"):
		address, err := withPort(strings.TrimPrefix(value, "tcp://"))
		if err != nil {
			return nil, err
		}
		return &plain{address: address, tcp: true}, nil
	default:
		address, err := withPort(strings.TrimPrefix(value, "udp://"))
		if err != nil {
			return nil, err
		}
		return &plain{address: address}, nil
	}
}

func withPort(value string) (string, error) {
	if _, _, err := net.SplitHostPort(value); err == nil {
		return value, nil
	}
	if net.ParseIP(strings.Trim(value, "[]")) == nil {
		return "", fmt.Errorf("DNS server %q must be an IP address", value)
	}
	return net.JoinHostPort(strings.Trim(value, "[]"), "53"), nil
}

type plain struct {
	address string
	tcp     bool
}

func (p *plain) String() string {
	if p.tcp {
		return "tcp://" + p.address
	}
	return "udp://" + p.address
}

func (p *plain) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	if !p.tcp {
		response, err := p.exchangeUDP(ctx, query)
		// A truncated UDP answer is retried over TCP.
		if err != nil || len(response) < 3 || response[2]&0x02 == 0 {
			return response, err
		}
	}
	return p.exchangeTCP(ctx, query)
}

func (p *plain) exchangeUDP(ctx context.Context, query []byte) ([]byte, error) {
	connection, err := netx.MarkedDialer(netx.MarkDirect, 5*time.Second).DialContext(ctx, "udp", p.address)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if _, err := connection.Write(query); err != nil {
		return nil, err
	}
	buffer := make([]byte, 65535)
	for {
		count, err := connection.Read(buffer)
		if err != nil {
			return nil, err
		}
		if count >= 12 && buffer[0] == query[0] && buffer[1] == query[1] {
			return append([]byte(nil), buffer[:count]...), nil
		}
	}
}

func (p *plain) exchangeTCP(ctx context.Context, query []byte) ([]byte, error) {
	connection, err := netx.MarkedDialer(netx.MarkDirect, 5*time.Second).DialContext(ctx, "tcp", p.address)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)
	if _, err := connection.Write(frame); err != nil {
		return nil, err
	}
	header := make([]byte, 2)
	if _, err := io.ReadFull(connection, header); err != nil {
		return nil, err
	}
	response := make([]byte, binary.BigEndian.Uint16(header))
	if _, err := io.ReadFull(connection, response); err != nil {
		return nil, err
	}
	return response, nil
}

type doh struct {
	url    string
	client *http.Client
}

func newDoH(endpoint string) *doh {
	return &doh{url: endpoint, client: netx.DirectHTTPClient(8 * time.Second)}
}

func (d *doh) String() string { return d.url }

func (d *doh) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	response, err := d.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", d.url, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65535))
	if err != nil {
		return nil, err
	}
	if len(body) < 12 {
		return nil, errors.New("short DNS-over-HTTPS answer")
	}
	return body, nil
}
