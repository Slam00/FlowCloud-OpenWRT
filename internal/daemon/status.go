package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// TunnelStatus is what LuCI shows for one tunnel.
type TunnelStatus struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Device    string `json:"device"`
	State     string `json:"state"` // starting, registering, selecting, up, down, disabled, error
	Endpoint  string `json:"endpoint,omitempty"`
	Profile   string `json:"profile,omitempty"`
	Source    string `json:"source,omitempty"`
	PingMs    int64  `json:"ping_ms"`
	CheckedAt int64  `json:"checked_at,omitempty"`
	Switches  int    `json:"switches"`
	Error     string `json:"error,omitempty"`
}

type SectionStatus struct {
	Name     string   `json:"name"`
	Enabled  bool     `json:"enabled"`
	Action   string   `json:"action"`
	Tunnel   string   `json:"tunnel,omitempty"`
	Domains  int      `json:"domains"`
	Subnets  int      `json:"subnets"`
	Missing  []string `json:"missing,omitempty"`
	Invalid  []string `json:"invalid,omitempty"`
	Learned  int      `json:"learned"`
	Counters int64    `json:"packets,omitempty"`
}

type DNSStatus struct {
	Listen    string   `json:"listen"`
	Upstreams []string `json:"upstreams"`
	Queries   uint64   `json:"queries"`
	Matched   uint64   `json:"matched"`
	Learned   uint64   `json:"learned"`
	Failures  uint64   `json:"failures"`
	Dnsmasq   bool     `json:"dnsmasq_integration"`
}

type Status struct {
	Running      bool            `json:"running"`
	Version      string          `json:"version"`
	StartedAt    int64           `json:"started_at"`
	UpdatedAt    int64           `json:"updated_at"`
	KernelAWG    bool            `json:"kernel_amneziawg"`
	Tunnels      []TunnelStatus  `json:"tunnels"`
	Sections     []SectionStatus `json:"sections"`
	ListsUpdated int64           `json:"lists_updated,omitempty"`
	ListErrors   []string        `json:"list_errors,omitempty"`
	DNS          DNSStatus       `json:"dns"`
	Warnings     []string        `json:"warnings,omitempty"`
	Error        string          `json:"error,omitempty"`
}

// statusBoard guards the status and writes it for `flowcloudd status`.
type statusBoard struct {
	mutex  sync.Mutex
	status Status
	path   string
}

func (b *statusBoard) update(change func(*Status)) {
	b.mutex.Lock()
	change(&b.status)
	b.mutex.Unlock()
}

func (b *statusBoard) tunnel(name string, change func(*TunnelStatus)) {
	b.update(func(status *Status) {
		for index := range status.Tunnels {
			if status.Tunnels[index].Name == name {
				change(&status.Tunnels[index])
				return
			}
		}
	})
}

func (b *statusBoard) write() {
	b.mutex.Lock()
	b.status.UpdatedAt = time.Now().Unix()
	data, err := json.MarshalIndent(b.status, "", "  ")
	b.mutex.Unlock()
	if err != nil || b.path == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(b.path), 0o755)
	temporary := b.path + ".tmp"
	if os.WriteFile(temporary, data, 0o644) == nil {
		_ = os.Rename(temporary, b.path)
	}
}
