package daemon

import (
	"context"
	"log"
	"sync"
	"time"

	"flowcloud-openwrt/internal/warp"
)

// A WARP tunnel keeps up to maxBackups tested pairs besides the applied one.
// When the provider cuts the tunnel's flow and a reconnect from a new source
// port does not bring it back, the next backup goes on the device: a second
// or two instead of a selection round (6-30 s), during which Telegram and
// the other sections of the tunnel get nothing.
//
// Backups come from the round that picked the applied pair. The probe device
// re-tests the first one every backupCheckEvery, so a dead backup is dropped
// before it is needed; when none is left, a background round refills the
// list, at most once per backupRefillEvery after a round that found some.
const (
	maxBackups        = 3
	backupCheckFirst  = time.Minute
	backupCheckEvery  = 5 * time.Minute
	backupCheckTime   = 10 * time.Second
	backupRefillEvery = 15 * time.Minute
	// recentCut: a pair cut again this soon after a reconnect is not
	// reconnected once more but replaced by a backup.
	recentCut = 3 * time.Minute
)

type warpBackups struct {
	mutex    sync.Mutex
	list     []warp.Selection
	current  string // the applied endpoint, never a backup
	refilled time.Time
}

// setCurrent records the applied endpoint and removes it from the backups.
func (b *warpBackups) setCurrent(endpoint string) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.current = endpoint
	b.list = withoutEndpoint(b.list, endpoint)
}

// replace makes candidates (best first) the backups.
func (b *warpBackups) replace(candidates []warp.Selection) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.list = b.list[:0]
	seen := map[string]bool{b.current: true}
	for _, candidate := range candidates {
		if len(b.list) == maxBackups {
			break
		}
		if candidate.Endpoint == "" || seen[candidate.Endpoint] {
			continue
		}
		seen[candidate.Endpoint] = true
		candidate.Alternates = nil
		b.list = append(b.list, candidate)
	}
}

// take removes and returns the first backup.
func (b *warpBackups) take() (warp.Selection, bool) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if len(b.list) == 0 {
		return warp.Selection{}, false
	}
	first := b.list[0]
	b.list = b.list[1:]
	return first, true
}

func (b *warpBackups) drop(endpoint string) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.list = withoutEndpoint(b.list, endpoint)
}

func (b *warpBackups) count() int {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return len(b.list)
}

func (b *warpBackups) snapshot() ([]warp.Selection, string) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return append([]warp.Selection(nil), b.list...), b.current
}

func withoutEndpoint(list []warp.Selection, endpoint string) []warp.Selection {
	result := list[:0]
	for _, selection := range list {
		if selection.Endpoint != endpoint {
			result = append(result, selection)
		}
	}
	return result
}

// keepBackupsWarm runs until ctx ends: it re-tests the backups with the probe
// device and refills the list when it runs empty. check tests one pair and
// refill runs a round excluding the current endpoint; both hold the probe
// device for their duration.
func (d *Daemon) keepBackupsWarm(ctx context.Context, name string, backups *warpBackups,
	check func(context.Context, warp.Selection) error, refill func(exclude string) (warp.Selection, error)) {
	d.keepBackupsWarmEvery(ctx, name, backups, check, refill, backupCheckFirst, backupCheckEvery)
}

func (d *Daemon) keepBackupsWarmEvery(ctx context.Context, name string, backups *warpBackups,
	check func(context.Context, warp.Selection) error, refill func(exclude string) (warp.Selection, error),
	first, every time.Duration) {
	delay := first
	for {
		if !sleep(ctx, delay) {
			return
		}
		delay = every
		list, current := backups.snapshot()
		for _, backup := range list {
			checkContext, cancel := context.WithTimeout(ctx, backupCheckTime)
			err := check(checkContext, backup)
			cancel()
			if ctx.Err() != nil {
				return
			}
			if err == nil {
				break
			}
			log.Printf("tunnel %s: backup %s no longer passes traffic: %v", name, backup.Endpoint, err)
			backups.drop(backup.Endpoint)
		}
		list, current = backups.snapshot()
		backups.mutex.Lock()
		due := len(list) == 0 && current != "" && time.Since(backups.refilled) >= backupRefillEvery
		if due {
			backups.refilled = time.Now()
		}
		backups.mutex.Unlock()
		if !due {
			continue
		}
		selection, err := refill(current)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			// Try again at the next check rather than after the full pause.
			backups.mutex.Lock()
			backups.refilled = time.Time{}
			backups.mutex.Unlock()
			log.Printf("tunnel %s: no backups found: %v", name, err)
			continue
		}
		backups.replace(append([]warp.Selection{selection}, selection.Alternates...))
		list, _ = backups.snapshot()
		log.Printf("tunnel %s: %d backups ready", name, len(list))
	}
}
