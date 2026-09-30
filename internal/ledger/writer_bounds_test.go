// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestLastLineAtTheWritersBound: Append accepts a line of MaxLineBytes-1 bytes, so lastLine must find it, and
// must still refuse a last line no Writer could have made.
func TestLastLineAtTheWritersBound(t *testing.T) {
	for _, l := range []int{MaxLineBytes - 3, MaxLineBytes - 2, MaxLineBytes - 1} {
		path := filepath.Join(t.TempDir(), "events.jsonl")
		body := "abc\n" + strings.Repeat("x", l) + "\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		line, present, err := lastLine(f, int64(len(body)))
		_ = f.Close()
		if err != nil || !present || len(line) != l {
			t.Fatalf("last line of %d bytes: len %d present %v err %v", l, len(line), present, err)
		}
	}
	path := filepath.Join(t.TempDir(), "events.jsonl")
	body := "abc\n" + strings.Repeat("x", MaxLineBytes) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, _, err := lastLine(f, int64(len(body))); err == nil {
		t.Fatal("a last line no Writer makes was accepted")
	}
}

// TestLastLineStartsSmall: a run_end line is a few hundred bytes, so State must not pull a 64 KiB window for it.
func TestLastLineStartsSmall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	var b bytes.Buffer
	for i := 0; i < 5000; i++ {
		b.WriteString(`{"k":"short line"}` + "\n")
	}
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	c := &countingReaderAt{f: f}
	if _, ok, err := lastLine(c, int64(b.Len())); err != nil || !ok {
		t.Fatalf("lastLine: %v %v", ok, err)
	}
	if c.n > 8<<10 {
		t.Fatalf("read %d bytes for a line of 20", c.n)
	}
}

// TestRunStartSplitsALargeCommand: R10 covers run_start as it covers every event. A 3 MiB argv used to be
// refused as a line past the bound, and one of 1 MiB was written inline.
func TestRunStartSplitsALargeCommand(t *testing.T) {
	for _, size := range []int{1 << 20, 3 << 20} {
		w, dir, _ := openTestWriter(t)
		start := startPayload()
		start.Command = []string{"agent", strings.Repeat("p", size)}
		if err := w.WriteRunStart(start); err != nil {
			t.Fatalf("WriteRunStart with a %d byte argument: %v", size, err)
		}
		if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
			t.Fatal(err)
		}
		r, err := OpenReader(dir)
		if err != nil {
			t.Fatal(err)
		}
		for line, err := range r.Lines() {
			if err != nil {
				t.Fatal(err)
			}
			if len(line) > 4*BlobThreshold {
				t.Fatalf("line 0 is %d bytes: command stayed inline", len(line))
			}
			e, err := record.Decode(line)
			if err != nil {
				t.Fatal(err)
			}
			var p record.RunStartPayload
			if err := e.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if p.CommandBlob == "" || len(p.Command) != 0 {
				t.Fatalf("command %d entries, command_blob %q", len(p.Command), p.CommandBlob)
			}
			rc, err := r.Blob(p.CommandBlob)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(rc)
			_ = rc.Close()
			if !bytes.Contains(got, []byte(start.Command[1])) {
				t.Fatalf("blob holds %d bytes, not the argv", len(got))
			}
			break
		}
	}
}
