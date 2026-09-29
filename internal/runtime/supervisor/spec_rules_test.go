// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// archAndTag is a build line that requires one tag and the supervisor's architectures.
var archAndTag = regexp.MustCompile(`\n//go:build [a-z0-9_]+ && \(amd64 \|\| arm64\)\n`)

// TestEverySourceFileCarriesTheArchitectureTag is supervisor.md R26: the dispatch tables exist for amd64 and
// arm64 only. Architecture-neutral naming values are shared with the
// observer; every implementation file must retain the architecture constraint.
func TestEverySourceFileCarriesTheArchitectureTag(t *testing.T) {
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, e := range ents {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		if n == "exec_naming.go" || n == "bind_naming.go" || n == "gate_fields.go" {
			continue
		}
		seen++
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		// A test hook's file adds its tag to the same constraint (exec_pin_testhook.go).
		if !strings.Contains(string(b), "\n//go:build amd64 || arm64\n") && !archAndTag.Match(b) {
			t.Errorf("%s lacks //go:build amd64 || arm64, so another GOARCH would build part of the supervisor", n)
		}
	}
	if seen == 0 {
		t.Fatal("no source files found")
	}
}

// TestNonUTF8PathIsRecordedLossily is supervisor.md E13: a path with bytes that are not UTF-8 is recorded
// with U+FFFD in their place, silently and without an error: a known gap, pinned so a change to it is a
// decision.
func TestNonUTF8PathIsRecordedLossily(t *testing.T) {
	f := newFake()
	f.put(0x1000, cstr("/work/\xff\xfe-x"))
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
	l.handle(notifFor(nrFor(t, "openat"), 42, argCWD, 0x1000, 0x241))
	evs := sink.all()
	if len(evs) == 0 {
		t.Fatal("no event recorded for the open")
	}
	var p struct {
		Path   string `json:"path"`
		Target string `json:"target"`
	}
	if err := evs[0].DecodePayload(&p); err != nil {
		t.Fatalf("payload with a non-UTF-8 path does not decode: %v", err)
	}
	got := p.Path
	if got == "" {
		got = p.Target
	}
	if !utf8.ValidString(got) || !strings.Contains(got, "�") {
		t.Errorf("recorded path %q, want valid UTF-8 with U+FFFD for the bad bytes", got)
	}
	if evs[0].Kind == record.KindGap {
		t.Errorf("a non-UTF-8 path made a gap: %+v", evs[0])
	}
}
