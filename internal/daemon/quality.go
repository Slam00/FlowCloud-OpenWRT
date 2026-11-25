package daemon

import (
	"fmt"
	"sort"
	"time"
)

const (
	// qualityWindowSize checks are judged together: at the default 15 s
	// interval that is the last two minutes, long enough that one slow answer
	// decides nothing.
	qualityWindowSize = 8
	// qualityCooldown keeps a tunnel from hopping between endpoints: after a
	// quality switch (or a search that found nothing better) the next one may
	// start only this much later.
	qualityCooldown = 10 * time.Minute
	// A candidate must beat the current median by this factor to replace it.
	betterFactor = 0.7
)

// qualityWindow holds the most recent ping results in milliseconds; -1 is a
// failed ping.
type qualityWindow struct {
	samples []int64
}

func (w *qualityWindow) add(ms int64) {
	w.samples = append(w.samples, ms)
	if len(w.samples) > qualityWindowSize {
		w.samples = w.samples[len(w.samples)-qualityWindowSize:]
	}
}

func (w *qualityWindow) full() bool { return len(w.samples) >= qualityWindowSize }

func (w *qualityWindow) reset() { w.samples = w.samples[:0] }

// stats returns the median of successful pings (-1 when none) and the share
// of failed pings in percent.
func (w *qualityWindow) stats() (int64, int) {
	if len(w.samples) == 0 {
		return -1, 0
	}
	var ok []int64
	for _, sample := range w.samples {
		if sample >= 0 {
			ok = append(ok, sample)
		}
	}
	loss := (len(w.samples) - len(ok)) * 100 / len(w.samples)
	if len(ok) == 0 {
		return -1, loss
	}
	sort.Slice(ok, func(i, j int) bool { return ok[i] < ok[j] })
	middle := len(ok) / 2
	if len(ok)%2 == 1 {
		return ok[middle], loss
	}
	return (ok[middle-1] + ok[middle]) / 2, loss
}

// qualityLimits are a tunnel's thresholds; 0 disables a check.
type qualityLimits struct {
	MaxPingMs  int
	MaxLossPct int
}

// poor reports whether a full window breaks a limit, and why.
func (l qualityLimits) poor(median int64, loss int) (bool, string) {
	if l.MaxLossPct > 0 && loss >= l.MaxLossPct {
		return true, fmt.Sprintf("потери %d%% (порог %d%%)", loss, l.MaxLossPct)
	}
	if l.MaxPingMs > 0 && median > int64(l.MaxPingMs) {
		return true, fmt.Sprintf("пинг %d мс (порог %d мс)", median, l.MaxPingMs)
	}
	return false, ""
}

// better decides whether a candidate that passed its probe with rttMs should
// replace an endpoint with this median and loss. Losses alone justify any
// working candidate; a slow endpoint is replaced only by a clearly faster one.
func (l qualityLimits) better(median int64, loss int, rttMs int64) bool {
	if l.MaxLossPct > 0 && loss >= l.MaxLossPct {
		return true
	}
	if median < 0 {
		return true
	}
	return float64(rttMs) <= float64(median)*betterFactor
}
