// SPDX-License-Identifier: Apache-2.0

package derive

import (
	"slices"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The closed set of gap what=capture reasons (R37). Capture reports only what it failed to see: a
// forwarder bypass is not in this set — it is a net verdict=refused reason=net-not-allowed event from
// enforce, because the forwarder port is the only compiled net.allow entry for that host while
// capture: forwarder is active (R38).
const (
	// GapNoOpenSSL is a process whose maps and own ELF offered no libssl at all (R4), and — because
	// the closed set has no value for it — a /proc read the kernel's ptrace check refused (#31).
	GapNoOpenSSL = "no-openssl"
	// GapStaticTLSNoSymbols is a TLS library that exists but exports none of SSL_write/SSL_read:
	// Bun's BoringSSL, a rustls binary (R1–R3).
	GapStaticTLSNoSymbols = "static-tls-no-symbols"
	// GapH2 is an HTTP/2 connection, known by its preface (R17).
	GapH2 = "h2"
	// GapMalformed is HTTP that did not reassemble, a decode that failed mid-stream, or a request
	// whose response never arrived (R18, §7).
	GapMalformed = "malformed"
	// GapRingBufferDrop is kernel-side loss, with the dropped count set.
	GapRingBufferDrop = "ring-buffer-drop"
	// GapSizeCap is a cap this component set: the scratch map's LRU, the 128 KiB chunk ceiling, the
	// header caps (R5, R6, R13).
	GapSizeCap = "size-cap"
	// GapEmitQueueFull is events the forwarder dropped because its emit queue was full, the run's pipeline having
	// fallen behind; count is set (§3, limits-check-doctor-cli.md R1 (s)).
	GapEmitQueueFull = "emit-queue-full"
	// GapNoModels is capture asked for by a contract that declares no models[] endpoint: the forwarder
	// has nothing to bind a listener for, so it never runs (R19). The gap names the forwarder as its
	// binary. It is a fact about the contract, which is why no-openssl — a fact R4 found about a
	// process — cannot stand in for it.
	GapNoModels = "no-models"
	// GapMechanismUnavailable is a capture mechanism the run wanted that this binary does not carry or
	// could not construct for this run; the binary field names the mechanism (§4). The forwarder also writes it
	// for a listener that stopped serving mid-run, naming that listener's upstream host (R37).
	GapMechanismUnavailable = "mechanism-unavailable"
)

// CaptureWhys is the closed why set of gap what=capture, in R37's order.
var CaptureWhys = []string{
	GapNoOpenSSL, GapStaticTLSNoSymbols, GapH2, GapMalformed, GapRingBufferDrop, GapSizeCap, GapEmitQueueFull,
	GapNoModels, GapMechanismUnavailable,
}

// IsCaptureWhy reports whether why is one of R37's nine values.
func IsCaptureWhy(why string) bool { return slices.Contains(CaptureWhys, why) }

// GapEvent builds one gap what=capture event. count is written only when it means something (the number
// of events a drop or a cap lost); zero leaves the field off, as the payload's omitempty does.
func GapEvent(meta Meta, why string, count int) *record.Event {
	ev := meta.event(record.KindGap)
	// SetPayload cannot fail for this struct: two strings, an int and a string.
	_ = ev.SetPayload(record.GapPayload{
		What:   record.GapCapture,
		Why:    why,
		Binary: meta.Binary,
		Count:  count,
	})
	return ev
}
