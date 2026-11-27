package warp

import (
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"strings"
)

// AmneziaWG 3 client-side parameters, after warp-awg-gen
// (https://github.com/Skiro1/warp-awg-gen, MIT), as in FlowCloud for Android.
// Only the ones a Cloudflare WARP server accepts: it is a plain WireGuard
// peer, so S1-S4, H1-H4 and header protection stay at stock values. Checked
// on this router on 2026-11-27 with the probe device against two WARP
// endpoints: every one completed the handshake and carried data.
//
//   - I2-I5: 1-3 short random decoys each, sent after I1 before every
//     handshake.
//   - content padding: 10-100 extra bytes inside encrypted data packets, so
//     their sizes stop looking like WireGuard's.
//   - random trailers: random bytes after handshake packets, so the
//     initiation is no longer exactly 148 bytes.
//   - timings: rekey and keepalive intervals vary; the persistent keepalive
//     becomes a range too.

// awg3Setting is one parameter with its `awg set` and UAPI names.
type awg3Setting struct {
	cli, uapi, value, off string
}

// The kernel's awg tool takes these names with hyphens only, although its
// usage text spells some with underscores.
var awg3Settings = []awg3Setting{
	{"content-padding-addition", "content_padding_addition", "10-100", "0"},
	{"rekey-after-time", "rekey_after_time", "100-120", "0"},
	{"rekey-timeout", "rekey_timeout", "3-7", "0"},
	{"reject-after-time", "reject_after_time", "150-180", "0"},
	{"keepalive-timeout", "keepalive_timeout", "5-15", "0"},
	{"max-handshake-attempts", "max_handshake_attempts", "15-20", "0"},
}

// Keepalive is the persistent keepalive of WARP tunnels: a range with AWG 3.
func Keepalive(awg3 bool) string {
	if awg3 {
		return "25-35"
	}
	return "25"
}

// AWG3Args returns the `awg set` device arguments: the parameters when
// enabled, else values that reset a device that had them (0 means the stock
// WireGuard timing, an empty decoy none).
func AWG3Args(enabled bool, rng *mrand.Rand) []string {
	var args []string
	for index := 2; index <= 5; index++ {
		decoy := ""
		if enabled {
			decoy = randomDecoys(rng)
		}
		args = append(args, fmt.Sprintf("i%d", index), decoy)
	}
	for _, setting := range awg3Settings {
		value := setting.off
		if enabled {
			value = setting.value
		}
		args = append(args, setting.cli, value)
	}
	trailers := "off"
	if enabled {
		trailers = "on"
	}
	return append(args, "random-trailers", trailers)
}

// awg3UAPI returns the same parameters as device-level IpcSet lines for the
// userspace probe devices; nothing when disabled (they are created fresh).
func awg3UAPI(enabled bool, rng *mrand.Rand) []string {
	if !enabled {
		return nil
	}
	var lines []string
	for index := 2; index <= 5; index++ {
		lines = append(lines, fmt.Sprintf("i%d=%s", index, randomDecoys(rng)))
	}
	for _, setting := range awg3Settings {
		lines = append(lines, setting.uapi+"="+setting.value)
	}
	return append(lines, "random_trailers=true")
}

// randomDecoys is 1-3 static-byte tags of 16-63 random bytes each.
func randomDecoys(rng *mrand.Rand) string {
	var builder strings.Builder
	count := rng.Intn(3) + 1
	for index := 0; index < count; index++ {
		buffer := make([]byte, rng.Intn(48)+16)
		_, _ = rand.Read(buffer)
		fmt.Fprintf(&builder, "<b 0x%x>", buffer)
	}
	return builder.String()
}
