// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"context"
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// A write in .dynsym and its read only in .symtab is found whole, not attached write-only (I4).
func TestReadBinaryReadsSymtabForTheMissingHalf(t *testing.T) {
	t.Parallel()
	p := writeELF(t, elfOptions{Dynamic: map[string]uint64{SymWrite: 0x1010}, Static: map[string]uint64{SymRead: 0x1020}})
	b, err := readBinary(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.WriteSymbols()) != 1 || len(b.ReadSymbols()) != 1 {
		t.Errorf("write=%v read=%v, want one of each", b.WriteSymbols(), b.ReadSymbols())
	}
}

// A binary with only one half anywhere is attached, and the half it lacks is a gap, never silent (I4); a
// missing read half is also reported unmetered.
func TestOneSidedAttachIsAGap(t *testing.T) {
	for _, tc := range []struct {
		name      string
		syms      map[string]uint64
		unmetered bool
	}{
		{"writes only", map[string]uint64{SymWrite: 0x1010}, true},
		{"reads only", map[string]uint64{SymRead: 0x1010}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := os.ReadFile(writeELF(t, elfOptions{Dynamic: tc.syms}))
			if err != nil {
				t.Fatal(err)
			}
			tree := newProcTree(t)
			lib := tree.inRoot(t, 81, "usr/lib/x86_64-linux-gnu/libssl.so.3", b)
			tree.process(t, 81, "/usr/bin/python3", []string{lib})
			att := &fakeAttacher{}
			u, _ := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att})
			sink := &meteredSink{}
			if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a"}, sink); err != nil {
				t.Fatalf("Start: %v", err)
			}
			u.OnExec(81, 41, "")
			u.OnOpen(81, 41, lib)
			if err := u.Stop(); err != nil {
				t.Fatalf("Stop: %v", err)
			}
			if att.count() == 0 {
				t.Errorf("attached nothing; the half it has should still be hooked")
			}
			if !hasGap(u.Gaps(), GapNoOpenSSL) {
				t.Errorf("gaps = %+v, want no-openssl", u.Gaps())
			}
			if got := sink.reported() > 0; got != tc.unmetered {
				t.Errorf("unmetered reported = %v (%q), want %v", got, sink.whys, tc.unmetered)
			}
		})
	}
}
