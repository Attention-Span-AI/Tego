// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// eventsHReasons reads enum tego_reason_code out of bpf/include/events.h: each TEGO_R_<NAME> = <n>, as the
// kernel programs number it.
func eventsHReasons(t *testing.T) map[string]uint8 {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "bpf", "include", "events.h"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	start := strings.Index(src, "enum tego_reason_code {")
	if start < 0 {
		t.Fatal("events.h has no enum tego_reason_code")
	}
	body := src[start : start+strings.Index(src[start:], "};")]
	out := map[string]uint8{}
	for _, m := range regexp.MustCompile(`TEGO_R_([A-Z_]+)\s*=\s*(\d+)`).FindAllStringSubmatch(body, -1) {
		n, err := strconv.Atoi(m[2])
		if err != nil || n > 255 {
			t.Fatalf("TEGO_R_%s = %s", m[1], m[2])
		}
		out[m[1]] = uint8(n)
	}
	if len(out) < 10 {
		t.Fatalf("read only %d reason codes from events.h: %v", len(out), out)
	}
	return out
}

// TestReasonTableIsEventsH holds ReasonFor to the kernel's own numbering, read from bpf/include/events.h so the two
// cannot drift: every TEGO_R_<NAME> whose name is a v1 reason code (NAME in kebab case) maps to that code, and a
// code that names none (the decision plane's refer, deny-write-ancestor and identity-mismatch, which the plane's
// lines name through plane_reason, observe planeFS) and every number events.h does not define map to nothing.
func TestReasonTableIsEventsH(t *testing.T) {
	kernel := eventsHReasons(t)
	defined := map[uint8]bool{}
	for name, n := range kernel {
		defined[n] = true
		want := record.Reason(strings.ReplaceAll(strings.ToLower(name), "_", "-"))
		got, ok := ReasonFor(n)
		switch {
		case name == "NONE":
			if ok || got != "" {
				t.Errorf("ReasonFor(%d) (TEGO_R_NONE) = %q, %v; want no reason", n, got, ok)
			}
		case want.Valid():
			if !ok || got != want {
				t.Errorf("ReasonFor(%d) = %q, %v; events.h's TEGO_R_%s is %q", n, got, ok, name, want)
			}
		default:
			if ok {
				t.Errorf("ReasonFor(%d) = %q; events.h's TEGO_R_%s names no v1 reason code", n, got, name)
			}
		}
	}
	for n := 0; n < 256; n++ {
		if !defined[uint8(n)] {
			if got, ok := ReasonFor(uint8(n)); ok {
				t.Errorf("ReasonFor(%d) = %q, a number events.h does not define", n, got)
			}
		}
	}
}
