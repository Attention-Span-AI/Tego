// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
)

// storeByte writes b at m[i]: a store the compiler keeps even when b is the byte already there.
//
//go:noinline
func storeByte(m []byte, i int, b byte) { m[i] = b }

// TestChainSeesAnEditThroughASharedMapping: the edit TestChainStaleVerdictRecheckedInBackground stands in for, made
// for real. A write through a shared mapping of chain.log takes a page fault, which stamps the file, only on the
// first write to a clean page; a later write to the page it dirtied takes none, so the run's head changes and the
// file keeps its size, mtime and ctime (ext4 on 6.17; the log says whether they were kept). `tego events <run>
// --verify` reads the changed head at once. The dashboard keeps its reading of chain.log by those stamps, so its next
// look may still say verified (the log says what it said); once that reading is ten minutes old, the next look reads
// chain.log again and says broken before the page answers. It used to say verified for good. Had the stamps moved,
// the look would have caught the edit at once, and the test holds the same end.
func TestChainSeesAnEditThroughASharedMapping(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	root, anchor := filepath.Join(dir, "runs"), filepath.Join(dir, "chain.log")
	id := "r-3f9c2a1b-0dllq06ts7417-c4chex"
	chainRun(t, root, anchor, id)
	r := loadedRun(t, root, id)
	if c := VerifyRun(ctx, root, id, anchor, r); !c.Verified() {
		t.Fatalf("chain: %+v", c)
	}
	f, err := os.OpenFile(anchor, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	m, err := syscall.Mmap(int(f.Fd()), 0, int(st.Size()), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Munmap(m) }()
	// The first write dirties the page and stamps the file; it writes the byte that is there.
	storeByte(m, 0, m[0])
	time.Sleep(20 * time.Millisecond)
	// The dashboard reads chain.log again for its new stamps: the same answer, and the verdict stands.
	if c := VerifyRun(ctx, root, id, anchor, r); !c.Verified() {
		t.Fatalf("after a write of the byte that was there: %+v", c)
	}
	before, err := os.Lstat(anchor)
	if err != nil {
		t.Fatal(err)
	}
	// The edit, through the page the first write dirtied: the last hex digit of the run's head.
	i := bytes.LastIndexByte(m, '\n') - 1
	flip := byte('0')
	if m[i] == '0' {
		flip = '1'
	}
	storeByte(m, i, flip)
	after, err := os.Lstat(anchor)
	if err != nil {
		t.Fatal(err)
	}
	rep, verr := ledger.VerifyRunDir(ctx, filepath.Join(root, id), ledger.NewFileChainAnchor(anchor))
	if ledger.VerdictOf(rep, verr) != ledger.Unverified {
		t.Fatalf("test setup: tego events --verify reads %v after the edit, want unverified", verr)
	}
	kept := idOf(before) == idOf(after)
	c := VerifyRun(ctx, root, id, anchor, r)
	t.Logf("the edit kept chain.log's stamps: %v; the dashboard's next look: %s", kept, c.State)
	ageAnchorView(t, anchor)
	if c := VerifyRun(ctx, root, id, anchor, r); !c.Broken() || c.AtLine || !strings.Contains(c.Reason, "anchored head") {
		t.Fatalf("once the dashboard's reading of chain.log was %v old: %+v, want broken on the anchored head, as tego "+
			"events --verify says", chainTTL, c)
	}
}
