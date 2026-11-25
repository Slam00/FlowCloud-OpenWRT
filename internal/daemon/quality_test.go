package daemon

import "testing"

func TestQualityWindow(t *testing.T) {
	var window qualityWindow
	for _, sample := range []int64{40, 50, -1, 60, 400, 45, -1, 55, 70} {
		window.add(sample)
	}
	if !window.full() || len(window.samples) != qualityWindowSize {
		t.Fatalf("window keeps %d samples", len(window.samples))
	}
	// Last eight: 50 -1 60 400 45 -1 55 70 -> ok 45 50 55 60 70 400, median 57.
	median, loss := window.stats()
	if median != 57 || loss != 25 {
		t.Fatalf("stats = %d ms, %d%%; want 57 ms, 25%%", median, loss)
	}
	window.reset()
	if window.full() {
		t.Fatal("reset window is full")
	}
}

func TestQualityLimits(t *testing.T) {
	limits := qualityLimits{MaxPingMs: 300, MaxLossPct: 30}
	if poor, _ := limits.poor(120, 10); poor {
		t.Fatal("a healthy endpoint is poor")
	}
	if poor, reason := limits.poor(450, 0); !poor || reason == "" {
		t.Fatal("a slow endpoint is not poor")
	}
	if poor, _ := limits.poor(80, 50); !poor {
		t.Fatal("a lossy endpoint is not poor")
	}
	if poor, _ := (qualityLimits{}).poor(5000, 90); poor {
		t.Fatal("disabled limits must never trigger")
	}

	if !limits.better(450, 0, 200) {
		t.Fatal("200 ms must replace a 450 ms median")
	}
	if limits.better(450, 0, 400) {
		t.Fatal("400 ms is not clearly better than 450 ms")
	}
	if !limits.better(80, 50, 300) {
		t.Fatal("any working candidate must replace a lossy endpoint")
	}
}
