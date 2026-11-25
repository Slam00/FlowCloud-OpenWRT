package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Manual endpoint switches. `flowcloudd warp-switch NAME` leaves a request
// file in the run directory and sends SIGUSR2; the daemon hands each request
// to the WARP tunnel of that name, which selects another endpoint at once.

const switchPrefix = "switch-"

// RequestSwitch writes the request file for tunnel name.
func RequestSwitch(runDir, name string) error {
	if name == "" || strings.ContainsAny(name, "/\\.") {
		return errors.New("invalid tunnel name")
	}
	return os.WriteFile(filepath.Join(runDir, switchPrefix+name), nil, 0o644)
}

// switchChannel registers a running WARP tunnel; the returned function
// unregisters it.
func (d *Daemon) switchChannel(name string) (<-chan struct{}, func()) {
	channel := make(chan struct{}, 1)
	d.mutex.Lock()
	if d.switches == nil {
		d.switches = map[string]chan struct{}{}
	}
	d.switches[name] = channel
	d.mutex.Unlock()
	return channel, func() {
		d.mutex.Lock()
		if d.switches[name] == channel {
			delete(d.switches, name)
		}
		d.mutex.Unlock()
	}
}

// deliverSwitches consumes the request files. A request for a tunnel that is
// not running is dropped: there is no endpoint to move away from.
func (d *Daemon) deliverSwitches() {
	entries, err := os.ReadDir(d.opts.RunDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name, ok := strings.CutPrefix(entry.Name(), switchPrefix)
		if !ok {
			continue
		}
		_ = os.Remove(filepath.Join(d.opts.RunDir, entry.Name()))
		d.mutex.Lock()
		channel := d.switches[name]
		d.mutex.Unlock()
		if channel != nil {
			select {
			case channel <- struct{}{}:
			default:
			}
		}
	}
}
