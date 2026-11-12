// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// boundPass binds one full pass of Lines over dir and returns what it bound.
func boundPass(t *testing.T, dir string) Bound {
	t.Helper()
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	b := r.Bind()
	for _, err := range r.Lines() {
		if err != nil {
			break
		}
	}
	return b.Bound()
}

// endedTestRun is a closed run of run_start, n gaps and run_end, returning its directory.
func endedTestRun(t *testing.T, n int) string {
	t.Helper()
	w, dir, _ := openTestWriter(t)
	startRun(t, w, n)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func fileSHA256(t *testing.T, path string) (string, int64) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), int64(len(b))
}

// TestBinderAgreesWithVerify: over every fixture ledger and a run this package writes, the binder's run, lines, head,
// end, torn bytes and newer lines are Verify's (with no anchor), and it binds nothing exactly where Verify fails.
func TestBinderAgreesWithVerify(t *testing.T) {
	fixtures, err := filepath.Glob(filepath.Join("..", "..", "spec", "record", "v1", "fixtures", "*.jsonl"))
	if err != nil || len(fixtures) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	dirs := map[string]string{"written": endedTestRun(t, 3)}
	for _, f := range fixtures {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, EventsFile), data, 0o600); err != nil {
			t.Fatal(err)
		}
		dirs[filepath.Base(f)] = dir
	}
	for name, dir := range dirs {
		t.Run(name, func(t *testing.T) {
			bd := boundPass(t, dir)
			r, err := OpenReader(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Close() }()
			rep, verr := r.Verify(context.Background(), nil)
			if (verr == nil) != (bd.Err == nil) {
				t.Fatalf("Verify %v, binder %v", verr, bd.Err)
			}
			if verr != nil {
				return
			}
			if bd.Run != rep.Run || bd.Lines != rep.Lines || bd.Head != rep.Head || bd.Ended != rep.Ended ||
				bd.TornBytes != rep.TornBytes || bd.Newer != rep.Newer {
				t.Errorf("binder %+v\nverify %+v", bd, rep)
			}
			if bd.Head == "" || bd.Lines == 0 {
				t.Errorf("nothing bound: %+v", bd)
			}
		})
	}
}

// TestBinderDigestIsTheFileSha256: for an ended run, sha256 is what sha256sum prints for events.jsonl and bytes its
// size, so a reader with no tego can match the file.
func TestBinderDigestIsTheFileSha256(t *testing.T) {
	dir := endedTestRun(t, 4)
	bd := boundPass(t, dir)
	sum, size := fileSHA256(t, filepath.Join(dir, EventsFile))
	if bd.Err != nil || bd.SHA256 != sum || bd.Bytes != size || !bd.Ended || bd.Lines != 6 {
		t.Errorf("bound %+v, file sha256 %s, %d bytes", bd, sum, size)
	}
}

// TestBinderHashesATornTail: a run its writer left with half a line binds the complete lines, counts the torn tail in
// torn_bytes, and hashes the file as read, torn tail included, so the file and the binding still match byte for byte.
func TestBinderHashesATornTail(t *testing.T) {
	dir := endedTestRun(t, 2)
	path := filepath.Join(dir, EventsFile)
	dropFinalLine(t, path)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	tail := `{"v":1,"seq":4,"id":"ab`
	if _, err := f.WriteString(tail); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	bd := boundPass(t, dir)
	sum, size := fileSHA256(t, path)
	if bd.Err != nil || bd.Ended || bd.Lines != 3 || bd.TornBytes != len(tail) || bd.Bytes != size || bd.SHA256 != sum {
		t.Errorf("bound %+v, want 3 lines, %d torn bytes, file %s of %d bytes", bd, len(tail), sum, size)
	}
}

// TestBinderUnterminatedLastLine (E8): a whole last line that lost only its "\n" is bound, and bytes is the file's size,
// not one past it: the offset Lines keeps adds a "\n" the file does not hold.
func TestBinderUnterminatedLastLine(t *testing.T) {
	dir := endedTestRun(t, 2)
	path := filepath.Join(dir, EventsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.TrimSuffix(data, []byte("\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	bd := boundPass(t, dir)
	sum, size := fileSHA256(t, path)
	if bd.Err != nil || !bd.Ended || bd.Lines != 4 || bd.TornBytes != 0 || bd.Bytes != size || bd.SHA256 != sum {
		t.Errorf("bound %+v, want 4 lines ended, file %s of %d bytes", bd, sum, size)
	}
}

// TestBinderBrokenChainHasNoHead: a line whose bytes no longer hash to its id binds no head, and the error names the
// line.
func TestBinderBrokenChainHasNoHead(t *testing.T) {
	dir := endedTestRun(t, 3)
	path := filepath.Join(dir, EventsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(data, []byte("\n"))
	lines[2] = bytes.Replace(lines[2], []byte(`"kind":"gap"`), []byte(`"kind":"gap" `), 1)
	if err := os.WriteFile(path, bytes.Join(lines, []byte("\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	bd := boundPass(t, dir)
	if bd.Err == nil || bd.Head != "" || bd.SHA256 != "" || !strings.Contains(bd.Err.Error(), "line 2") {
		t.Errorf("bound %+v, want no head and an error naming line 2", bd)
	}
}

// TestBinderSeesNewerLinesUnderSkipNewer: the views skip a newer-version line (SkipNewerVersions) before they decode
// it, and the binder still links and counts it, so a record with one binds whole rather than broken at it.
func TestBinderSeesNewerLinesUnderSkipNewer(t *testing.T) {
	dir := newerRun(t, "2")
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	r.SkipNewerVersions()
	b := r.Bind()
	n := 0
	for _, err := range r.Entries() {
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	bd := b.Bound()
	rep, verr := r.Verify(context.Background(), nil)
	if verr != nil {
		t.Fatal(verr)
	}
	if bd.Err != nil || bd.Newer != 1 || bd.Lines != rep.Lines || bd.Head != rep.Head || uint64(n+1) != bd.Lines {
		t.Errorf("bound %+v after %d entries, verify %+v", bd, n, rep)
	}
}

// TestBinderBindsOnePassWhole: a pass its reader stopped early binds nothing, and the binder holds the one pass after
// Bind, not a later one.
func TestBinderBindsOnePassWhole(t *testing.T) {
	dir := endedTestRun(t, 3)
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	b := r.Bind()
	for range r.Lines() {
		break
	}
	if bd := b.Bound(); bd.Err == nil || bd.Head != "" {
		t.Errorf("a stopped pass bound %+v", bd)
	}
	b = r.Bind()
	for range r.Lines() {
	}
	want := b.Bound()
	for range r.Lines() {
		break
	}
	if got := b.Bound(); got.Err != nil || got != want {
		t.Errorf("a later pass changed the binding: %+v, want %+v", got, want)
	}
}

// dropFinalLine truncates the file at path at the start of its final line.
func dropFinalLine(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.LastIndexByte(bytes.TrimSuffix(b, []byte("\n")), '\n')
	if i < 0 {
		t.Fatalf("%s has no line to drop", path)
	}
	if err := os.WriteFile(path, b[:i+1], 0o600); err != nil {
		t.Fatal(err)
	}
}
