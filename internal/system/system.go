// Package system runs the OpenWrt command-line tools the daemon relies on
// (ip, awg, ubus, uci) and wraps their output.
package system

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Run executes a command and returns its trimmed stdout; stderr goes into the
// error. Arguments are passed directly, never through a shell.
func Run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return "", fmt.Errorf("%s %s: %s", name, strings.Join(redact(args), " "), message)
	}
	return strings.TrimSpace(stdout.String()), nil
}

// redact keeps long values (I1 chains, keys) out of error messages.
func redact(args []string) []string {
	result := make([]string, len(args))
	for index, arg := range args {
		if len(arg) > 64 {
			arg = arg[:16] + "..."
		}
		result[index] = arg
	}
	return result
}

// InterfaceDevice returns the layer-3 device of a netifd interface and
// whether the interface is up.
func InterfaceDevice(name string) (string, bool, error) {
	output, err := Run("ubus", "call", "network.interface."+name, "status")
	if err != nil {
		return "", false, err
	}
	var status struct {
		Up       bool   `json:"up"`
		L3Device string `json:"l3_device"`
		Device   string `json:"device"`
	}
	if err := json.Unmarshal([]byte(output), &status); err != nil {
		return "", false, err
	}
	device := status.L3Device
	if device == "" {
		device = status.Device
	}
	return device, status.Up, nil
}

// LinkExists reports whether a network device exists.
func LinkExists(device string) bool {
	_, err := Run("ip", "link", "show", "dev", device)
	return err == nil
}
