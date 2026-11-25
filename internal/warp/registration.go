package warp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"

	"flowcloud-openwrt/internal/netx"
)

// APIHosts are tried in order: the host WARP clients have always used, then
// the one Cloudflare's current clients use, for networks that filter either.
var APIHosts = []string{"api.cloudflareclient.com", "api.devices.cloudflare.com"}

const (
	apiPath       = "/v0a2158/reg"
	clientVersion = "a-6.10-2158"
	userAgent     = "okhttp/3.12.1"
)

// Account is a registered WARP device. Unlike the game helper, a router keeps
// its device across restarts: it is stored root-only in /etc/flowcloud.
type Account struct {
	ID             string `json:"id"`
	Token          string `json:"token"`
	BaseURL        string `json:"base_url"`
	PrivateKey     string `json:"private_key"`
	PeerPublicKey  string `json:"peer_public_key"`
	AddressV4      string `json:"address_v4"`
	AddressV6      string `json:"address_v6"`
	RegisteredHost string `json:"registered_host,omitempty"`
	RegisteredPort int    `json:"registered_port,omitempty"`
	CreatedAt      int64  `json:"created_at"`
}

// Peer is everything needed to build a tunnel to any WARP endpoint.
type Peer struct {
	PrivateKey     []byte
	PublicKey      []byte
	AddressV4      netip.Addr
	RegisteredHost string
	RegisteredPort int
}

func decodeKey(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) != curve25519.ScalarSize {
		return nil, errors.New("key must be 32-byte base64")
	}
	return decoded, nil
}

// Peer validates the account and returns its tunnel parameters.
func (a *Account) Peer() (*Peer, error) {
	privateKey, err := decodeKey(a.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("WARP private key: %w", err)
	}
	publicKey, err := decodeKey(a.PeerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("WARP peer key: %w", err)
	}
	address, err := netip.ParseAddr(strings.TrimSpace(strings.Split(a.AddressV4, "/")[0]))
	if err != nil || !address.Is4() {
		return nil, fmt.Errorf("WARP interface address %q is not IPv4", a.AddressV4)
	}
	return &Peer{
		PrivateKey:     privateKey,
		PublicKey:      publicKey,
		AddressV4:      address,
		RegisteredHost: a.RegisteredHost,
		RegisteredPort: a.RegisteredPort,
	}, nil
}

// LoadAccount reads a stored account; a missing file returns os.ErrNotExist.
func LoadAccount(path string) (*Account, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var account Account
	if err := json.Unmarshal(data, &account); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if _, err := account.Peer(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &account, nil
}

// SaveAccount writes the account root-only and atomically.
func SaveAccount(path string, account *Account) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(account, "", "  ")
	if err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

type registrationRequest struct {
	FCMToken  string `json:"fcm_token"`
	InstallID string `json:"install_id"`
	Key       string `json:"key"`
	Locale    string `json:"locale"`
	Model     string `json:"model"`
	TOS       string `json:"tos"`
	Type      string `json:"type"`
}

type registrationResponse struct {
	ID     string `json:"id"`
	Token  string `json:"token"`
	Config struct {
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				Host string `json:"host"`
				V4   string `json:"v4"`
			} `json:"endpoint"`
		} `json:"peers"`
	} `json:"config"`
}

// Register creates a WARP device, trying each API host.
func Register(ctx context.Context) (*Account, error) {
	var lastErr error
	for _, host := range APIHosts {
		account, err := registerAt(ctx, host)
		if err == nil {
			return account, nil
		}
		lastErr = fmt.Errorf("%s: %w", host, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

func registerAt(ctx context.Context, host string) (*Account, error) {
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, err
	}
	privateKey[0] &= 248
	privateKey[31] = (privateKey[31] & 127) | 64
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(registrationRequest{
		Key:    base64.StdEncoding.EncodeToString(publicKey),
		Locale: "en_US",
		Model:  "PC",
		TOS:    time.Now().UTC().Format(time.RFC3339Nano),
		Type:   "Android",
	})
	if err != nil {
		return nil, err
	}
	addresses, err := resolveIPv4(ctx, host)
	if err != nil {
		return nil, err
	}
	client := apiClient(host, addresses)
	baseURL := "https://" + host + apiPath
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	setHeaders(request)
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("registration returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var registered registrationResponse
	if err := json.Unmarshal(body, &registered); err != nil {
		return nil, err
	}
	if registered.ID == "" || registered.Token == "" || len(registered.Config.Peers) == 0 {
		return nil, errors.New("registration response is incomplete")
	}
	peer := registered.Config.Peers[0]
	registeredHost, registeredPort, _ := splitRegisteredEndpoint(peer.Endpoint.V4, peer.Endpoint.Host)
	account := &Account{
		ID:             registered.ID,
		Token:          registered.Token,
		BaseURL:        baseURL,
		PrivateKey:     base64.StdEncoding.EncodeToString(privateKey),
		PeerPublicKey:  peer.PublicKey,
		AddressV4:      registered.Config.Interface.Addresses.V4,
		AddressV6:      registered.Config.Interface.Addresses.V6,
		RegisteredHost: registeredHost,
		RegisteredPort: registeredPort,
		CreatedAt:      time.Now().Unix(),
	}
	if _, err := account.Peer(); err != nil {
		return nil, err
	}
	return account, nil
}

func setHeaders(request *http.Request) {
	request.Header.Set("User-Agent", userAgent)
	request.Header.Set("CF-Client-Version", clientVersion)
	request.Header.Set("Content-Type", "application/json")
}

// resolveIPv4 asks dns.google over HTTPS, so a poisoned local resolver cannot
// redirect the registration.
func resolveIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	client := netx.DirectHTTPClient(10 * time.Second)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://dns.google/resolve?name="+url.QueryEscape(host)+"&type=A", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/dns-json")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("resolve %s through DNS-over-HTTPS: %w", host, err)
	}
	defer response.Body.Close()
	var resolved struct {
		Status int `json:"Status"`
		Answer []struct {
			Type uint16 `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&resolved); err != nil {
		return nil, err
	}
	var addresses []netip.Addr
	for _, answer := range resolved.Answer {
		if address, err := netip.ParseAddr(strings.TrimSpace(answer.Data)); err == nil && answer.Type == 1 && address.Is4() {
			addresses = append(addresses, address)
		}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no IPv4 address for %s", host)
	}
	return addresses, nil
}

// apiClient pins the API host to the addresses resolved over DoH and keeps
// TLS validation for the real name.
func apiClient(host string, addresses []netip.Addr) *http.Client {
	dialer := netx.MarkedDialer(netx.MarkDirect, 10*time.Second)
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			name, port, err := net.SplitHostPort(address)
			if err != nil || !strings.EqualFold(name, host) {
				return dialer.DialContext(ctx, network, address)
			}
			var lastErr error
			for _, candidate := range addresses {
				connection, dialErr := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(candidate.String(), port))
				if dialErr == nil {
					return connection, nil
				}
				lastErr = dialErr
			}
			return nil, lastErr
		},
	}
	return &http.Client{Transport: transport, Timeout: 20 * time.Second}
}

// KeyHex returns a key in the hex form the userspace device expects.
func KeyHex(key []byte) string {
	return hex.EncodeToString(key)
}
