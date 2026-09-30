// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestReaderBoundsLineLength holds Verify and State to a memory bound that does not scale with one line of
// events.jsonl. The file is bytes a tamperer can write (E16); the Writer never emits a line past a few hundred
// KiB (R10 splits every field over BlobThreshold), and State runs on every retained run before each `tego
// run`, so a line the size of the file cost that much heap, twice over, before the agent was even launched.
//
// Also pins record-ledger.md E12: a reader refuses a line past MaxLineBytes as corruption.
func TestReaderBoundsLineLength(t *testing.T) {
	dir := filepath.Join(t.TempDir(), testRef.ID)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	const size = 64 << 20
	if err := os.WriteFile(filepath.Join(dir, EventsFile), bytes.Repeat([]byte("a"), size), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	measure := func(name string, f func()) {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		f()
		runtime.ReadMemStats(&after)
		if got := after.TotalAlloc - before.TotalAlloc; got > 16<<20 {
			t.Errorf("%s allocated %d MiB reading a %d MiB line, want under 16 MiB", name, got>>20, size>>20)
		}
	}
	measure("Verify", func() { _, _ = r.Verify(context.Background(), nil) })
	measure("State", func() { _, _ = r.State() })
}

// TestAppendRefusesALineReadersWouldRefuse: a line past MaxLineBytes is corruption to every reader, so the
// Writer must never write one; it refuses the event before any byte reaches the file, and the next line
// still lands.
func TestAppendRefusesALineReadersWouldRefuse(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 1)
	huge := fsEvent(strings.Repeat("a", MaxLineBytes), nil)
	if err := w.Append(huge); !errors.Is(err, record.ErrInvalidEvent) {
		t.Fatalf("Append of a %d-byte line = %v, want ErrInvalidEvent", MaxLineBytes, err)
	}
	if err := w.Append(fsEvent("/work/out/after", nil)); err != nil {
		t.Fatalf("the next Append: %v", err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if _, err := r.Verify(context.Background(), nil); err != nil {
		t.Fatalf("the ledger no longer verifies: %v", err)
	}
}

// TestACorruptLineIsNumberedFromOne: the corrupt line is named as an editor and `events --json` count it,
// from 1; Iter counted from 0.
func TestACorruptLineIsNumberedFromOne(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 1)
	w.release()
	w.closeDirs()
	before, err := os.ReadFile(filepath.Join(dir, EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Count(before, []byte("\n")) + 1 // the line appended below
	f, err := os.OpenFile(filepath.Join(dir, EventsFile), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{\"not\": \"a record\"}\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	for _, err := range r.Iter() {
		if err != nil {
			if want := fmt.Sprintf(" %d:", bad); !errors.Is(err, ErrCorruptLedger) || !strings.Contains(err.Error(), want) {
				t.Fatalf("error %v, want the corrupt ledger at line %d", err, bad)
			}
			return
		}
	}
	t.Fatal("no error for a corrupt line")
}
