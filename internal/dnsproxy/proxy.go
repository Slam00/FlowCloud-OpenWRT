package dnsproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"flowcloud-openwrt/internal/nft"
)

// Route is what the proxy needs to know about a section.
type Route struct {
	Section string
	// Watch records the section's resolved hosts in Proxy.Recent.
	Watch bool
}

// State is swapped atomically when lists or sections change.
type State struct {
	Matcher *Matcher
	Routes  []Route
}

// Stats are exported for the status page.
type Stats struct {
	Queries  atomic.Uint64
	Matched  atomic.Uint64
	Learned  atomic.Uint64
	Failures atomic.Uint64
}

type Proxy struct {
	Listen     string
	Upstreams  []Upstream
	StripAAAA  bool
	MinTimeout time.Duration
	Adder      interface {
		Add([]nft.Element) error
	}
	Stats Stats
	// Recent collects the hosts of watched sections.
	Recent *Recent

	state atomic.Pointer[State]
}

// SetState replaces the matcher and routes.
func (p *Proxy) SetState(state *State) { p.state.Store(state) }

// Serve listens on UDP and TCP until ctx ends.
func (p *Proxy) Serve(ctx context.Context) error {
	packet, err := net.ListenPacket("udp", p.Listen)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", p.Listen)
	if err != nil {
		packet.Close()
		return err
	}
	go func() {
		<-ctx.Done()
		packet.Close()
		listener.Close()
	}()
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		p.serveTCP(ctx, listener)
	}()
	buffer := make([]byte, 65535)
	for {
		count, address, err := packet.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				wait.Wait()
				return nil
			}
			continue
		}
		query := append([]byte(nil), buffer[:count]...)
		go func() {
			if response := p.Handle(ctx, query); response != nil {
				_, _ = packet.WriteTo(response, address)
			}
		}()
	}
}

func (p *Proxy) serveTCP(ctx context.Context, listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go func() {
			defer connection.Close()
			for {
				_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
				header := make([]byte, 2)
				if _, err := io.ReadFull(connection, header); err != nil {
					return
				}
				query := make([]byte, binary.BigEndian.Uint16(header))
				if _, err := io.ReadFull(connection, query); err != nil {
					return
				}
				response := p.Handle(ctx, query)
				if response == nil {
					return
				}
				frame := make([]byte, 2+len(response))
				binary.BigEndian.PutUint16(frame, uint16(len(response)))
				copy(frame[2:], response)
				if _, err := connection.Write(frame); err != nil {
					return
				}
			}
		}()
	}
}

// Handle answers one query. A query for a routed domain learns its IPv4
// addresses before the answer is released.
func (p *Proxy) Handle(ctx context.Context, query []byte) []byte {
	p.Stats.Queries.Add(1)
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return nil
	}
	question, err := parser.Question()
	if err != nil {
		return p.forward(ctx, query, header)
	}
	state := p.state.Load()
	section, matched := 0, false
	if state != nil {
		section, matched = state.Matcher.Match(question.Name.String())
	}
	if !matched {
		return p.forward(ctx, query, header)
	}
	p.Stats.Matched.Add(1)
	if p.StripAAAA && question.Type == dnsmessage.TypeAAAA {
		// Routing is IPv4: without an AAAA answer the client cannot bypass the
		// tunnel over IPv6.
		return emptyAnswer(header, question)
	}
	response := p.forward(ctx, query, header)
	if response == nil || section >= len(state.Routes) {
		return response
	}
	addresses, ttl := ipv4Answers(response)
	if len(addresses) == 0 {
		return response
	}
	if state.Routes[section].Watch && p.Recent != nil {
		p.Recent.note(question.Name.String(), addresses)
	}
	timeout := time.Duration(ttl) * time.Second
	if timeout < p.MinTimeout {
		timeout = p.MinTimeout
	}
	set := nft.DNSSet(state.Routes[section].Section)
	elements := make([]nft.Element, len(addresses))
	for index, address := range addresses {
		elements[index] = nft.Element{Set: set, Address: address, Timeout: timeout}
	}
	if err := p.Adder.Add(elements); err != nil {
		log.Printf("dns: learn %s: %v", question.Name, err)
	} else {
		p.Stats.Learned.Add(uint64(len(elements)))
	}
	return response
}

func (p *Proxy) forward(ctx context.Context, query []byte, header dnsmessage.Header) []byte {
	var lastErr error
	for _, upstream := range p.Upstreams {
		exchangeContext, cancel := context.WithTimeout(ctx, 4*time.Second)
		response, err := upstream.Exchange(exchangeContext, query)
		cancel()
		if err == nil && len(response) >= 12 && response[0] == query[0] && response[1] == query[1] {
			return response
		}
		if err == nil {
			err = errors.New("mismatched answer")
		}
		lastErr = err
	}
	p.Stats.Failures.Add(1)
	if lastErr != nil {
		log.Printf("dns: all upstreams failed: %v", lastErr)
	}
	return servfail(header, query)
}

// ipv4Answers returns the A records of a response and their smallest TTL.
func ipv4Answers(response []byte) ([]netip.Addr, uint32) {
	var parser dnsmessage.Parser
	if _, err := parser.Start(response); err != nil {
		return nil, 0
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return nil, 0
	}
	var addresses []netip.Addr
	minTTL := uint32(0)
	for {
		header, err := parser.AnswerHeader()
		if err != nil {
			break
		}
		if header.Type != dnsmessage.TypeA {
			_ = parser.SkipAnswer()
			continue
		}
		record, err := parser.AResource()
		if err != nil {
			break
		}
		address := netip.AddrFrom4(record.A)
		if address.IsUnspecified() || address.IsLoopback() || address.IsPrivate() {
			continue
		}
		addresses = append(addresses, address)
		if minTTL == 0 || header.TTL < minTTL {
			minTTL = header.TTL
		}
	}
	return addresses, minTTL
}

func emptyAnswer(header dnsmessage.Header, question dnsmessage.Question) []byte {
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: header.ID, Response: true, RecursionDesired: header.RecursionDesired,
		RecursionAvailable: true, RCode: dnsmessage.RCodeSuccess,
	})
	_ = builder.StartQuestions()
	_ = builder.Question(question)
	message, err := builder.Finish()
	if err != nil {
		return nil
	}
	return message
}

func servfail(header dnsmessage.Header, query []byte) []byte {
	var parser dnsmessage.Parser
	_, _ = parser.Start(query)
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: header.ID, Response: true, RecursionDesired: header.RecursionDesired,
		RecursionAvailable: true, RCode: dnsmessage.RCodeServerFailure,
	})
	_ = builder.StartQuestions()
	if question, err := parser.Question(); err == nil {
		_ = builder.Question(question)
	}
	message, err := builder.Finish()
	if err != nil {
		return nil
	}
	return message
}
