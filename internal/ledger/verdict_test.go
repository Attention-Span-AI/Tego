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

// TestVerdictAndBrokenLine: VerdictOf reads a Verify result as `tego events --verify` exits on it (verified 0,
// unverified 1, no verdict 125), and a failure that is a line's own names that line (AtLine, BrokenLine), even when the
// line chained and was counted in Lines; a failure found once every line was read names none. closedRun(t, 3) is
// run_start, three gap lines and run_end: lines 0 to 4.
func TestVerdictAndBrokenLine(t *testing.T) {
	edit := func(t *testing.T, dir string, f func(lines [][]byte) [][]byte) {
		t.Helper()
		p := filepath.Join(dir, EventsFile)
		lines := bytes.Split(bytes.TrimSuffix(readFile(t, p), []byte("\n")), []byte("\n"))
		if err := os.WriteFile(p, append(bytes.Join(f(lines), []byte("\n")), '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name    string
		damage  func(t *testing.T, dir string, anchor *memAnchor) ChainAnchor
		verdict Verdict
		atLine  bool
		line    uint64
	}{
		{"intact", func(_ *testing.T, _ string, a *memAnchor) ChainAnchor { return a }, Verified, false, 0},
		{"a byte changed in line 2", func(t *testing.T, dir string, a *memAnchor) ChainAnchor {
			edit(t, dir, func(l [][]byte) [][]byte {
				l[2] = bytes.Replace(l[2], []byte(`"why":"e1"`), []byte(`"why":"e9"`), 1)
				return l
			})
			return a
		}, Unverified, true, 2},
		{"run_end chains but fails validation", func(t *testing.T, dir string, a *memAnchor) ChainAnchor {
			edit(t, dir, func(l [][]byte) [][]byte {
				l[4] = resealed(t, bytes.Replace(l[4], []byte(`"reason":"exit"`), []byte(`"reason":"exiz"`), 1))
				return l
			})
			return a
		}, Unverified, true, 4},
		{"a line after run_end", func(t *testing.T, dir string, a *memAnchor) ChainAnchor {
			edit(t, dir, func(l [][]byte) [][]byte { return append(l, []byte("{}")) })
			return a
		}, Unverified, true, 5},
		{"run_end dropped (the anchored head)", func(t *testing.T, dir string, a *memAnchor) ChainAnchor {
			edit(t, dir, func(l [][]byte) [][]byte { return l[:4] })
			return a
		}, Unverified, false, 0},
		{"no anchor line for an ended run", func(*testing.T, string, *memAnchor) ChainAnchor { return &memAnchor{} },
			Unverified, false, 0},
		{"an anchor that cannot be read", func(t *testing.T, _ string, _ *memAnchor) ChainAnchor {
			p := filepath.Join(t.TempDir(), ChainLogFile)
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
			return NewFileChainAnchor(p)
		}, NoVerdict, false, 0},
		{"no run_start", func(t *testing.T, dir string, _ *memAnchor) ChainAnchor {
			if err := os.WriteFile(filepath.Join(dir, EventsFile), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return &memAnchor{}
		}, NoVerdict, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, anchor := closedRun(t, 3)
			a := tc.damage(t, dir, anchor)
			rep, err := VerifyRunDir(context.Background(), dir, a)
			if got := VerdictOf(rep, err); got != tc.verdict {
				t.Fatalf("VerdictOf = %d, want %d (%+v, %v)", got, tc.verdict, rep, err)
			}
			if rep.AtLine != tc.atLine || rep.BrokenLine != tc.line {
				t.Fatalf("at line %v #%d, want %v #%d (%v)", rep.AtLine, rep.BrokenLine, tc.atLine, tc.line, err)
			}
		})
	}
	if VerdictOf(VerifyReport{}, nil) != NoVerdict || Verdict(0) != NoVerdict {
		t.Fatal("a report with nothing in it, or a zero Verdict, reads as a verdict")
	}
}

// resealed gives line the id its bytes hash to (R2), so a line edited past its schema still chains.
func resealed(t *testing.T, line []byte) []byte {
	t.Helper()
	const key = `,"id":"`
	i := bytes.Index(line, []byte(key))
	if i < 0 {
		t.Fatalf("no id in %s", line)
	}
	off := i + len(key)
	out := bytes.Clone(line)
	copy(out[off:off+record.IDLen], strings.Repeat("0", record.IDLen))
	sum := sha256.Sum256(out)
	copy(out[off:off+record.IDLen], hex.EncodeToString(sum[:]))
	if _, err := record.VerifyLine(out); err != nil {
		t.Fatalf("the resealed line does not verify: %v", err)
	}
	return out
}
