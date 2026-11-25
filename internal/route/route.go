// Package route keeps one policy routing table per tunnel: packets carrying a
// tunnel's mark look up its table, whose default route is the tunnel device.
package route

import (
	"fmt"
	"strconv"
	"strings"

	"flowcloud-openwrt/internal/netx"
	"flowcloud-openwrt/internal/system"
)

// RulePriority sits before podkop's rule (105) so the two can coexist.
const RulePriority = 103

// TableID returns the routing table of a tunnel index.
func TableID(index int) int { return 1000 + index }

// Install adds the ip rule for a tunnel (idempotent).
func Install(index int) error {
	mark := netx.TunnelMark(index)
	args := []string{"rule", "add", "fwmark", fmt.Sprintf("0x%x/0x%x", mark, netx.MarkMask),
		"lookup", strconv.Itoa(TableID(index)), "priority", strconv.Itoa(RulePriority)}
	if exists(index) {
		return nil
	}
	_, err := system.Run("ip", args...)
	return err
}

func exists(index int) bool {
	output, err := system.Run("ip", "rule", "show", "priority", strconv.Itoa(RulePriority))
	if err != nil {
		return false
	}
	return strings.Contains(output, "lookup "+strconv.Itoa(TableID(index)))
}

// SetDevice points the tunnel's table at device. With failClosed an
// unreachable route stays behind when the device disappears, so marked
// traffic is dropped instead of leaking to the main table.
func SetDevice(index int, device string, failClosed bool) error {
	table := strconv.Itoa(TableID(index))
	if _, err := system.Run("ip", "route", "replace", "default", "dev", device, "table", table); err != nil {
		return err
	}
	if failClosed {
		_, err := system.Run("ip", "route", "replace", "unreachable", "default", "metric", "32000", "table", table)
		return err
	}
	_, _ = system.Run("ip", "route", "del", "unreachable", "default", "metric", "32000", "table", table)
	return nil
}

// FailClosedOnly leaves only the unreachable route (used while a tunnel is
// down and fails closed).
func FailClosedOnly(index int) error {
	table := strconv.Itoa(TableID(index))
	_, _ = system.Run("ip", "route", "flush", "table", table)
	_, err := system.Run("ip", "route", "replace", "unreachable", "default", "metric", "32000", "table", table)
	return err
}

// Clear empties a tunnel's table, so marked traffic falls back to main.
func Clear(index int) {
	_, _ = system.Run("ip", "route", "flush", "table", strconv.Itoa(TableID(index)))
}

// Cleanup removes every FlowCloud rule and table.
func Cleanup(maxIndex int) {
	for attempt := 0; attempt < 64; attempt++ {
		if _, err := system.Run("ip", "rule", "del", "priority", strconv.Itoa(RulePriority)); err != nil {
			break
		}
	}
	for index := 1; index <= maxIndex; index++ {
		Clear(index)
	}
}
