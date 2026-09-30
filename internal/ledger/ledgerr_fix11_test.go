// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestStateReadsANewerVersionLastLineAsVerifyDoes: a correctly chained newer line is a link Verify counts, so
// a newer run_end is the run's end for State too, and any other newer last line is a line present (lost, the
// lock being free), not a corrupt ledger.
func TestStateReadsANewerVersionLastLineAsVerifyDoes(t *testing.T) {
	for _, tc := range []struct {
		kind string
		want RunState
	}{{"run_end", StateEnded}, {"gap", StateLost}} {
		t.Run(tc.kind, func(t *testing.T) {
			dir := plainClosedRun(t)
			spliceVersionLine(t, dir, 4, "2", `"run":"`+testRef.ID+`","kind":"`+tc.kind+`","ts":"2031-01-01T00:00:00Z"`)
			// The v1 run_end moved before the newer line; drop it so the newer line is last.
			data, err := os.ReadFile(filepath.Join(dir, EventsFile))
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.SplitAfter(string(data), "\n")
			if len(lines) < 2 || !strings.Contains(lines[len(lines)-2], `"v":2`) {
				t.Skipf("the spliced line is not last: %q", lines)
			}
			r, err := OpenReader(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			got, err := r.State()
			if err != nil || got != tc.want {
				t.Fatalf("State = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// TestSweepLiveKeepsAnEmptyRunWhoseLockAProbeHolds: a status or stop probe holds the lock shared for an
// instant, which makes the sweep's exclusive attempt fail. That is not "nothing to sweep": the entry stays so
// the next sweep kills the scope, and once the probe lets go the hook runs and the entry is cleared.
func TestSweepLiveKeepsAnEmptyRunWhoseLockAProbeHolds(t *testing.T) {
	w, dir, _ := openTestWriter(t, WithContract([]byte("version: 0\nname: early-agent\ncommand: [\"/bin/true\"]\n")))
	w.release()
	w.closeDirs()
	root := filepath.Dir(dir)
	if err := MarkLive(root, testRef.ID); err != nil {
		t.Fatal(err)
	}
	swept := 0
	hook := WithSweepHook(func(context.Context, sys.Lender, record.RunRef) error { swept++; return nil })

	probe, err := os.Open(filepath.Join(dir, LockFile))
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	if rep, err := SweepLive(context.Background(), root, hook); err != nil || len(rep.Errors) != 0 {
		t.Fatalf("SweepLive under a probe: %v %v", err, rep.Errors)
	}
	if swept != 0 || !listed(t, root, testRef.ID) {
		t.Fatalf("under a probe: hook ran %d times, listed %v; want 0 and still listed", swept, listed(t, root, testRef.ID))
	}
	if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if _, err := SweepLive(context.Background(), root, hook); err != nil {
		t.Fatal(err)
	}
	if swept != 1 || listed(t, root, testRef.ID) {
		t.Fatalf("after the probe: hook ran %d times, listed %v; want 1 and cleared", swept, listed(t, root, testRef.ID))
	}
}

// TestBodyRefusesAWholeBlobEditedToTheSameLength: a blob's name is the sha256 of its bytes, so Body checks what
// it read against it as it checks a frame body against body_sha256.
func TestBodyRefusesAWholeBlobEditedToTheSameLength(t *testing.T) {
	w, dir := startedWriter(t)
	body := strings.Repeat("not json ", BlobThreshold/8)
	if err := w.SplitBlobsStage(w.Append)(sslRequest(nil, map[string]any{"body": body, "size": len(body)})); err != nil {
		t.Fatal(err)
	}
	ev := readAll(t, dir)[1]
	var req record.SSLRequestPayload
	if err := ev.DecodePayload(&req); err != nil || req.Blob == "" {
		t.Fatalf("no blob: %v %q", err, req.Blob)
	}
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	path := filepath.Join(dir, BlobsDir, req.Blob)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("y", len(body))), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := r.Body(ev); !errors.Is(err, ErrCorruptBlob) {
		t.Fatalf("an edited blob of the same length: %d bytes, %v; want ErrCorruptBlob", len(got), err)
	}
}
