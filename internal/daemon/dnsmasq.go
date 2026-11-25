package daemon

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"

	"flowcloud-openwrt/internal/system"
)

const dnsmasqSection = "dhcp.@dnsmasq[0]"

// dnsmasqBackup is what dnsmasq used before FlowCloud took over upstream DNS.
type dnsmasqBackup struct {
	Servers  []string `json:"servers"`
	NoResolv string   `json:"noresolv"`
}

// dnsmasqServer is the server= value pointing at the proxy.
func dnsmasqServer(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	if port == "53" {
		return host
	}
	return host + "#" + port
}

func currentDnsmasq() (dnsmasqBackup, error) {
	var backup dnsmasqBackup
	output, err := system.Run("uci", "-q", "show", dnsmasqSection+".server")
	if err == nil {
		_, raw, _ := strings.Cut(output, "=")
		for _, value := range strings.Fields(raw) {
			backup.Servers = append(backup.Servers, strings.Trim(value, "'"))
		}
	}
	backup.NoResolv, _ = system.Run("uci", "-q", "get", dnsmasqSection+".noresolv")
	return backup, nil
}

// takeOverDnsmasq points dnsmasq at the proxy, saving the previous upstream
// settings once so stopping FlowCloud can restore them.
func takeOverDnsmasq(listen, backupPath string) error {
	server := dnsmasqServer(listen)
	current, err := currentDnsmasq()
	if err != nil {
		return err
	}
	if len(current.Servers) == 1 && current.Servers[0] == server && current.NoResolv == "1" {
		return nil
	}
	if _, statErr := os.Stat(backupPath); errors.Is(statErr, os.ErrNotExist) {
		data, _ := json.Marshal(current)
		if err := os.WriteFile(backupPath, data, 0o600); err != nil {
			return err
		}
	}
	_, _ = system.Run("uci", "-q", "delete", dnsmasqSection+".server")
	if _, err := system.Run("uci", "add_list", dnsmasqSection+".server="+server); err != nil {
		return err
	}
	if _, err := system.Run("uci", "set", dnsmasqSection+".noresolv=1"); err != nil {
		return err
	}
	if _, err := system.Run("uci", "commit", "dhcp"); err != nil {
		return err
	}
	_, err = system.Run("/etc/init.d/dnsmasq", "restart")
	return err
}

// restoreDnsmasq puts back what takeOverDnsmasq saved.
func restoreDnsmasq(listen, backupPath string) error {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return nil
	}
	var backup dnsmasqBackup
	if err := json.Unmarshal(data, &backup); err != nil {
		return err
	}
	current, _ := currentDnsmasq()
	server := dnsmasqServer(listen)
	// Only undo our own change: another service may have taken over since.
	if len(current.Servers) == 1 && current.Servers[0] == server {
		_, _ = system.Run("uci", "-q", "delete", dnsmasqSection+".server")
		for _, value := range backup.Servers {
			_, _ = system.Run("uci", "add_list", dnsmasqSection+".server="+value)
		}
		if backup.NoResolv == "" {
			_, _ = system.Run("uci", "-q", "delete", dnsmasqSection+".noresolv")
		} else {
			_, _ = system.Run("uci", "set", dnsmasqSection+".noresolv="+backup.NoResolv)
		}
		_, _ = system.Run("uci", "commit", "dhcp")
		_, _ = system.Run("/etc/init.d/dnsmasq", "restart")
	}
	return os.Remove(backupPath)
}
