package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"flowcloud-openwrt/internal/warp"
)

func endpoints(list []warp.Selection) []string {
	var result []string
	for _, selection := range list {
		result = append(result, selection.Endpoint)
	}
	return result
}

func TestWarpBackupsSkipCurrentAndCap(t *testing.T) {
	backups := &warpBackups{}
	backups.setCurrent("a:1")
	backups.replace([]warp.Selection{
		{Endpoint: "a:1"}, {Endpoint: "b:1", Alternates: []warp.Selection{{Endpoint: "x:1"}}},
		{Endpoint: "b:1"}, {Endpoint: "c:1"}, {Endpoint: "d:1"}, {Endpoint: "e:1"},
	})
	list, current := backups.snapshot()
	if got := endpoints(list); len(got) != maxBackups || got[0] != "b:1" || got[1] != "c:1" || got[2] != "d:1" || current != "a:1" {
		t.Fatalf("backups %v current %s", got, current)
	}
	if list[0].Alternates != nil {
		t.Fatal("alternates kept on a backup")
	}
	first, ok := backups.take()
	if !ok || first.Endpoint != "b:1" {
		t.Fatalf("take %v %v", first, ok)
	}
	backups.setCurrent("c:1")
	list, _ = backups.snapshot()
	if got := endpoints(list); len(got) != 1 || got[0] != "d:1" {
		t.Fatalf("after setCurrent %v", got)
	}
}

func TestKeepBackupsWarmDropsDeadAndRefills(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backups := &warpBackups{}
	backups.setCurrent("live:1")
	backups.replace([]warp.Selection{{Endpoint: "dead:1"}, {Endpoint: "dead:2"}})
	refilled := make(chan string, 1)
	check := func(context.Context, warp.Selection) error { return errors.New("no data") }
	refill := func(exclude string) (warp.Selection, error) {
		refilled <- exclude
		return warp.Selection{Endpoint: "new:1", Alternates: []warp.Selection{{Endpoint: "live:1"}, {Endpoint: "new:2"}}}, nil
	}
	d := &Daemon{}
	done := make(chan struct{})
	go func() {
		d.keepBackupsWarmEvery(ctx, "warp", backups, check, refill, time.Millisecond, time.Hour)
		close(done)
	}()
	select {
	case exclude := <-refilled:
		if exclude != "live:1" {
			t.Fatalf("refill excluded %q", exclude)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no refill")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		list, _ := backups.snapshot()
		if got := endpoints(list); len(got) == 2 && got[0] == "new:1" && got[1] == "new:2" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("backups %v", endpoints(list))
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}
