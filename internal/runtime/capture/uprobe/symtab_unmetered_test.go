// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// A pipelined request past R11's depth is refused and its answer passed over unread, so what it spends is
// read by nothing: each is reported unmetered like every other path that gives up on a request (ADR 0037).
func TestRefusedPipelinedModelRequestsAreReportedUnmetered(t *testing.T) {
	const ssl, n = 0x7100, 12
	req, resp := messagesExchange("length")
	sink := r3Metered(t, [][]byte{
		chunkRecord(41, 970, 970, ssl, bpf.SSLWrite, 1_000_000, []byte(strings.Repeat(req, n)), false),
		chunkRecord(41, 970, 970, ssl, bpf.SSLRead, 2_000_000, []byte(strings.Repeat(resp, n)), false),
	})
	if got := sink.reported(); got < 1 {
		t.Fatalf("reported %d (%q): the refused requests' spend is invisible to a budget", got, sink.whys)
	}
}

// An undefined function symbol with a non-zero value (a non-PIE executable that takes SSL_write's address
// carries one whose value is its PLT stub) is a reference into another object, not an export to attach to.
func TestUndefinedSymbolWithPLTValueIsNotAnExport(t *testing.T) {
	path := writeELF(t, elfOptions{Dynamic: map[string]uint64{SymWrite: 0x1100}, Undefined: true})
	if b, err := readBinary(path); !errors.Is(err, ErrNoSymbols) {
		t.Fatalf("readBinary = %+v, %v, want ErrNoSymbols", b, err)
	}
}

// A symbol table just under the old 64 MiB bound cost the launcher about ten times its size in heap; the
// bound is now a few MiB, above any real libssl or static interpreter.
func TestSparseSymtabUnderTheOldBoundIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "libssl.so.3")
	writeSparseSymtabELF(t, path, 24*2_000_000) // 48 MB: under the old bound, over the new
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := readBinary(path)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("readBinary accepted a 48 MB symbol table")
	}
	if a := after.TotalAlloc - before.TotalAlloc; a > 16<<20 {
		t.Errorf("parsing one hostile candidate allocated %d MiB in the launcher", a>>20)
	}
}

// A run attaches at most MaxOpenAttach distinct libraries an agent opened by name; past it, each is a gap
// why=size-cap naming it, and nothing is attached to it.
func TestOpenedLibrariesPastTheBoundAreNotAttached(t *testing.T) {
	const pid = 90
	tree := newProcTree(t)
	so := writeELF(t, elfOptions{Dynamic: map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180}})
	b, err := os.ReadFile(so)
	if err != nil {
		t.Fatal(err)
	}
	tree.process(t, pid, "/usr/bin/python3", nil)
	att := &fakeAttacher{}
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	for i := 0; i < MaxOpenAttach+3; i++ {
		u.OnOpen(pid, 41, tree.inRoot(t, pid, fmt.Sprintf("tmp/d%d/libssl.so.%d", i, i), b))
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := att.count(); got != 3*MaxOpenAttach {
		t.Errorf("%d probes placed, want %d: %d libraries", got, 3*MaxOpenAttach, MaxOpenAttach)
	}
	if !hasGap(u.Gaps(), GapSizeCap) {
		t.Errorf("gaps = %+v, want a size-cap gap for the libraries past the bound", u.Gaps())
	}
}
