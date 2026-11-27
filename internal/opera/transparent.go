//go:build linux

package opera

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Transparent accepts the TCP connections nftables redirects to Port and
// opens each original destination through the Opera proxy. The destination
// goes by host name when the first bytes carry one (TLS SNI or an HTTP Host
// header), so Opera resolves it near its exit; else by address.
type Transparent struct {
	Port   int
	Client *Client
	Name   string

	active sync.WaitGroup
}

const (
	soOriginalDst = 80 // SO_ORIGINAL_DST
	sniffTimeout  = 3 * time.Second
	sniffBytes    = 4096
)

// Serve listens until ctx ends.
func (t *Transparent) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(t.Port)))
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				t.active.Wait()
				return nil
			}
			continue
		}
		t.active.Add(1)
		go func() {
			defer t.active.Done()
			t.handle(ctx, connection.(*net.TCPConn))
		}()
	}
}

func (t *Transparent) handle(ctx context.Context, client *net.TCPConn) {
	defer client.Close()
	destination, err := originalDestination(client)
	if err != nil {
		return
	}
	// A connection made to the listener itself has no other destination.
	if local, ok := client.LocalAddr().(*net.TCPAddr); ok && local.AddrPort() == destination {
		return
	}
	_ = client.SetReadDeadline(time.Now().Add(sniffTimeout))
	reader := bufio.NewReaderSize(client, sniffBytes)
	peeked, _ := peekInitial(reader)
	_ = client.SetReadDeadline(time.Time{})
	target := destination.String()
	if host := sniffHost(peeked); host != "" {
		target = net.JoinHostPort(host, strconv.Itoa(int(destination.Port())))
	}
	dialContext, cancel := context.WithTimeout(ctx, apiTimeout)
	upstream, err := t.Client.DialContext(dialContext, target)
	cancel()
	if err != nil {
		log.Printf("tunnel %s: %s: %v", t.Name, target, err)
		return
	}
	defer upstream.Close()
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, reader)
		if writer, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = writer.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		_ = client.CloseWrite()
		done <- struct{}{}
	}()
	select {
	case <-done:
	case <-ctx.Done():
		return
	}
	// One direction ended; give the other a bounded time to finish.
	_ = client.SetReadDeadline(time.Now().Add(time.Minute))
	_ = upstream.SetReadDeadline(time.Now().Add(time.Minute))
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// peekInitial waits for the client's first bytes without consuming them.
func peekInitial(reader *bufio.Reader) ([]byte, error) {
	if _, err := reader.Peek(1); err != nil {
		return nil, err
	}
	return reader.Peek(reader.Buffered())
}

// originalDestination reads where a redirected connection was going.
func originalDestination(connection *net.TCPConn) (netip.AddrPort, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var address [16]byte // struct sockaddr_in
	var callErr error
	err = raw.Control(func(fd uintptr) {
		size := uint32(len(address))
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.SOL_IP, soOriginalDst,
			uintptr(unsafe.Pointer(&address[0])), uintptr(unsafe.Pointer(&size)), 0)
		if errno != 0 {
			callErr = errno
		}
	})
	if err == nil {
		err = callErr
	}
	if err != nil {
		return netip.AddrPort{}, err
	}
	port := binary.BigEndian.Uint16(address[2:4])
	ip := netip.AddrFrom4([4]byte{address[4], address[5], address[6], address[7]})
	return netip.AddrPortFrom(ip, port), nil
}
