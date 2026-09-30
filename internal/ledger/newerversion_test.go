// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// spliceVersionLine rewrites the ledger in dir with a line of record version v (the raw JSON token) inserted
// at index at, correctly chained: its id is the digest of its bytes with the id zeroed, its seq and prev
// follow the line before it, and every v1 line after it is re-sealed with the seq and prev that follow. body
// is spliced after the chain fields. The result is a ledger whose chain is whole.
func spliceVersionLine(t *testing.T, dir string, at int, v, body string) {
	t.Helper()
	path := filepath.Join(dir, EventsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
	var out [][]byte
	prev := ""
	for i := 0; i <= len(lines); i++ {
		seq := uint64(len(out))
		if i == at {
			l := fmt.Sprintf(`{"v":%s,"seq":%d,"id":"%s","prev":"%s",%s}`, v, seq, record.ZeroID, prev, body)
			sum := sha256.Sum256([]byte(l))
			id := hex.EncodeToString(sum[:])
			out = append(out, bytes.Replace([]byte(l), []byte(record.ZeroID), []byte(id), 1))
			prev = id
			seq++
		}
		if i == len(lines) {
			break
		}
		e, err := record.Decode(lines[i])
		if err != nil {
			t.Fatal(err)
		}
		e.Seq, e.Prev = seq, prev
		line, err := e.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, bytes.TrimSuffix(line, []byte("\n")))
		prev = e.ID
	}
	if err := os.WriteFile(path, append(bytes.Join(out, []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// newerRun is a closed run of run_start, two gaps and run_end with a line of version v spliced in at index 2.
func newerRun(t *testing.T, v string) string {
	t.Helper()
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 2)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	spliceVersionLine(t, dir, 2, v, `"run":"`+testRef.ID+`","kind":"hologram","ts":"2031-01-01T00:00:00Z"`)
	return dir
}

// TestNewerVersionLineSkippedByViewsVerifiedByVerify pins limits-check-doctor-cli.md §6 case 20: a line whose
// v is greater than this reader supports is skipped, and counted, by a reader the views set to skip, while
// Verify still links it into the hash chain, which covers its bytes and not its schema. Without the option
// the reader stops at it as corrupt, as every other reader of the ledger (sweep, gc, stop) still does.
func TestNewerVersionLineSkippedByViewsVerifiedByVerify(t *testing.T) {
	dir := newerRun(t, "2")

	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var got error
	for _, err := range r.Iter() {
		if err != nil {
			got = err
			break
		}
	}
	if !errors.Is(got, ErrCorruptLedger) || !errors.Is(got, record.ErrNewerVersion) {
		t.Fatalf("a reader not set to skip: err = %v, want ErrCorruptLedger naming ErrNewerVersion", got)
	}

	r.SkipNewerVersions()
	for pass := 0; pass < 2; pass++ {
		var kinds []record.Kind
		for e, err := range r.Iter() {
			if err != nil {
				t.Fatalf("pass %d: %v", pass, err)
			}
			kinds = append(kinds, e.Kind)
		}
		want := []record.Kind{record.KindRunStart, record.KindGap, record.KindGap, record.KindRunEnd}
		if fmt.Sprint(kinds) != fmt.Sprint(want) {
			t.Fatalf("pass %d yielded %v, want %v", pass, kinds, want)
		}
		if n := r.SkippedNewer(); n != 1 {
			t.Fatalf("pass %d: SkippedNewer = %d, want 1 (a second pass must not count it twice)", pass, n)
		}
	}

	rep, err := r.Verify(context.Background(), nil)
	if err != nil {
		t.Fatalf("Verify of a whole chain with a newer line: %v", err)
	}
	if rep.Lines != 5 || rep.Newer != 1 || !rep.Ended || !rep.Started {
		t.Fatalf("Verify report %+v, want 5 lines, 1 newer, started and ended", rep)
	}
}

// TestNewerVersionLineTamperedFailsVerify: skipping a newer line's schema is not skipping its bytes. One
// changed byte breaks its id, and Verify says so.
func TestNewerVersionLineTamperedFailsVerify(t *testing.T) {
	dir := newerRun(t, "2")
	path := filepath.Join(dir, EventsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.Replace(data, []byte("hologram"), []byte("hologran"), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Verify(context.Background(), nil); !errors.Is(err, ErrUnverified) || !errors.Is(err, record.ErrIDMismatch) {
		t.Fatalf("Verify of a tampered newer line = %v, want ErrUnverified and ErrIDMismatch", err)
	}
}

// TestVersionZeroOrMalformedStaysCorrupt: only a v greater than this reader's is skipped. v 0, a string v and a
// negative v are corrupt to the views and to Verify alike.
func TestVersionZeroOrMalformedStaysCorrupt(t *testing.T) {
	for _, v := range []string{"0", `"2"`, "-1", "2.5"} {
		t.Run(v, func(t *testing.T) {
			dir := newerRun(t, v)
			r, err := OpenReader(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			r.SkipNewerVersions()
			var got error
			for _, err := range r.Iter() {
				if err != nil {
					got = err
					break
				}
			}
			if !errors.Is(got, ErrCorruptLedger) || errors.Is(got, record.ErrNewerVersion) {
				t.Fatalf("v=%s: Iter err = %v, want ErrCorruptLedger and not a newer version", v, got)
			}
			if r.SkippedNewer() != 0 {
				t.Fatalf("v=%s skipped as newer", v)
			}
			if _, err := r.Verify(context.Background(), nil); !errors.Is(err, ErrUnverified) {
				t.Fatalf("v=%s: Verify = %v, want ErrUnverified", v, err)
			}
		})
	}
}

// TestUnterminatedNewerLastLineIsALineNotATornTail: a whole line of a newer version that lost only its "\n"
// (E8) is the same line it is with the terminator: the views yield it, Verify links it into the chain, and
// lastLine finds it instead of dropping it as torn.
func TestUnterminatedNewerLastLineIsALineNotATornTail(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 2)
	_ = w.Abandon()
	spliceVersionLine(t, dir, 3, "2", `"run":"`+testRef.ID+`","kind":"hologram","ts":"2031-01-01T00:00:00Z"`)
	path := filepath.Join(dir, EventsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.TrimSuffix(data, []byte("\n")), 0o600); err != nil {
		t.Fatal(err)
	}

	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	n := 0
	for _, err := range r.Lines() {
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != 4 {
		t.Fatalf("Lines yielded %d lines, want 4 (the newer line included)", n)
	}
	rep, err := r.Verify(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.TornBytes != 0 || rep.Newer != 1 || rep.Lines != 4 {
		t.Fatalf("Verify report %+v, want no torn bytes, 1 newer, 4 lines", rep)
	}
	line, present, err := lastLine(r.f, int64(len(data)-1))
	if err != nil || !present || !bytes.Contains(line, []byte("hologram")) {
		t.Fatalf("lastLine = %q, %v, %v; want the newer line", line, present, err)
	}
}
