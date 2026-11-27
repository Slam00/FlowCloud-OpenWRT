package opera

import (
	"crypto/tls"
	"net"
	"testing"
)

func TestSniffHost(t *testing.T) {
	// A real ClientHello from crypto/tls.
	server, client := net.Pipe()
	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: "Gemini.Google.com", InsecureSkipVerify: true}).Handshake()
	}()
	buffer := make([]byte, 4096)
	count, _ := server.Read(buffer)
	server.Close()
	client.Close()
	if host := sniffHost(buffer[:count]); host != "gemini.google.com" {
		t.Fatalf("SNI = %q", host)
	}
	if host := sniffHost([]byte("GET / HTTP/1.1\r\nHost: aistudio.google.com:80\r\nAccept: */*\r\n\r\n")); host != "aistudio.google.com" {
		t.Fatalf("HTTP host = %q", host)
	}
	if host := sniffHost([]byte{0x16, 0x03, 0x01, 0x00}); host != "" {
		t.Fatalf("garbage gave %q", host)
	}
}
