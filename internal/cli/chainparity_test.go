// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestChainVerdictParity: `tego events <run> --verify` and the dashboard's chain check (ledgerview.VerifyRun) give one
// verdict on the same run against the same chain.log, over intact, broken and unanchored ledgers: exit 0 is verified,
// exit 1 broken and exit 125 not checked. Both read ledger.VerifyRunDir's result through ledger.VerdictOf; the dashboard
// used to copy the CLI's reading by hand, and said where a chain broke from the error's text. A broken chain names the
// line the walk stopped on (#0 is run_start) when the failure is that line's own, and breaks after the last line when
// it is the anchor's: a run_end that fails validation is line 1 (the copy said 2, a line the run does not have), and a
// chain.log with two heads for the run or a malformed line breaks after the last line (the copy said at line 2). The
// line it breaks after is the last one the run has, #1 here, or #0 once run_end is gone, never the count of its lines,
// which names a line it does not have (the dashboard said "after #2" for a two-line run).
//
// One difference is the dashboard's on purpose (docs/DASHBOARD.md): with no chain.log at all it says not checked where
// the CLI fails an ended run for its missing anchor line (E29), as a dashboard pointed at another user's ledger root
// sees none. It never says verified where the CLI does not.
//
// This file is one of the internal/cli tests allowed to import the dashboard (.golangci.yml
// engine-never-imports-control): the parity it checks spans both binaries.
func TestChainVerdictParity(t *testing.T) {
	cases := []struct {
		name   string
		damage func(t *testing.T, dir, anchor, id string)
		code   int    // tego events <run> --verify's exit
		state  string // the dashboard's chain state
		atLine bool   // a broken chain: the walk stopped on a line
		line   uint64 // that line, or without atLine the last line, after which the chain broke
	}{
		{"intact", func(*testing.T, string, string, string) {}, identity.ExitOK, ledgerview.ChainVerified, false, 0},
		{"a changed byte in run_start", func(t *testing.T, dir, _, _ string) {
			editEvents(t, dir, func(lines [][]byte) { lines[0] = bytes.Replace(lines[0], []byte(`"cwd":"/"`), []byte(`"cwd":"~"`), 1) })
		}, identity.ExitFinding, ledgerview.ChainBroken, true, 0},
		{"run_end chains but fails validation", func(t *testing.T, dir, _, _ string) {
			editEvents(t, dir, func(lines [][]byte) {
				last := len(lines) - 1
				lines[last] = reseal(t, bytes.Replace(lines[last], []byte(`"reason":"exit"`), []byte(`"reason":"exiz"`), 1))
			})
		}, identity.ExitFinding, ledgerview.ChainBroken, true, 1},
		{"run_end removed", func(t *testing.T, dir, _, _ string) {
			dropLastLine(t, filepath.Join(dir, ledger.EventsFile))
		}, identity.ExitFinding, ledgerview.ChainBroken, false, 0},
		{"no anchor line for the run", func(t *testing.T, _, anchor, _ string) {
			writeAnchor(t, anchor, "r-00000000-000000000000a-orphan "+strings.Repeat("ab", 32)+"\n")
		}, identity.ExitFinding, ledgerview.ChainBroken, false, 1},
		{"the anchored head rewritten in place", func(t *testing.T, _, anchor, id string) {
			editAnchorHead(t, anchor, id)
		}, identity.ExitFinding, ledgerview.ChainBroken, false, 1},
		{"two heads for the run", func(t *testing.T, _, anchor, id string) {
			appendAnchor(t, anchor, id+" "+strings.Repeat("cd", 32)+"\n")
		}, identity.ExitFinding, ledgerview.ChainBroken, false, 1},
		{"a malformed line in chain.log", func(t *testing.T, _, anchor, _ string) {
			appendAnchor(t, anchor, "not an anchor line\n")
		}, identity.ExitFinding, ledgerview.ChainBroken, false, 1},
		{"no chain.log (the dashboard does not judge)", func(t *testing.T, _, anchor, _ string) {
			if err := os.Remove(anchor); err != nil {
				t.Fatal(err)
			}
		}, identity.ExitFinding, ledgerview.ChainUnchecked, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := gcRoot(t)
			id := endedRun(t, root, time.Now()) // anchored at the ledger's default, beside the root
			dir := filepath.Join(root, id)
			anchor := ledger.DefaultAnchorPath(dir)
			useAnchor(t, anchor)
			tc.damage(t, dir, anchor, id)
			assertChainParity(t, root, id, anchor, tc.code, tc.state, tc.atLine, tc.line)
		})
	}

	// A run directory whose ledger holds no run_start and that no anchor line names: nothing to check either way.
	t.Run("no run_start", func(t *testing.T) {
		root := gcRoot(t)
		id, err := identity.NewRunID([32]byte{}, time.Now(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(root, string(id))
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		anchor := ledger.DefaultAnchorPath(dir)
		writeAnchor(t, anchor, "")
		useAnchor(t, anchor)
		assertChainParity(t, root, string(id), anchor, identity.ExitError, ledgerview.ChainUnchecked, false, 0)
	})
}

// assertChainParity checks run id under root against anchor both ways: `tego events <id> --verify` exits code, and
// the dashboard's check reads state (broken at line, or after it when atLine is false).
func assertChainParity(t *testing.T, root, id, anchor string, code int, state string, atLine bool, line uint64) {
	t.Helper()
	got, out, errs := run(t, "events", id, "--verify")
	if got != code {
		t.Errorf("tego events --verify: exit %d, want %d\nstdout %s\nstderr %s", got, code, out, errs)
	}
	r, err := ledgerview.LoadRun(root, id)
	if err != nil {
		r = nil // a run the read model cannot summarize (no run_start) is checked without one
	}
	c := ledgerview.VerifyRun(context.Background(), root, id, anchor, r)
	if c.State != state {
		t.Fatalf("dashboard: %+v, want %s (the CLI exits %d)", c, state, got)
	}
	if c.Broken() && (c.AtLine != atLine || c.Line != line) {
		t.Errorf("dashboard: broken at line %v #%d, want at line %v #%d (%s)", c.AtLine, c.Line, atLine, line, c.Reason)
	}
}

// editEvents rewrites the run's events file with edit applied to its lines.
func editEvents(t *testing.T, dir string, edit func(lines [][]byte)) {
	t.Helper()
	p := filepath.Join(dir, ledger.EventsFile)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n"))
	edit(lines)
	if err := os.WriteFile(p, append(bytes.Join(lines, []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// reseal gives line the id its bytes hash to (R2), so a line edited past its schema still chains.
func reseal(t *testing.T, line []byte) []byte {
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
		t.Fatalf("resealed line does not verify: %v", err)
	}
	return out
}

// editAnchorHead flips the last hex digit of run id's head in the chain.log at anchor, in place: the same file, the
// same size.
func editAnchorHead(t *testing.T, anchor, id string) {
	t.Helper()
	b, err := os.ReadFile(anchor)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(b, []byte(id+" "))
	if i < 0 {
		t.Fatalf("no line for %s in %s", id, b)
	}
	at := i + len(id) + 1 + record.IDLen - 1
	if b[at] == '0' {
		b[at] = '1'
	} else {
		b[at] = '0'
	}
	f, err := os.OpenFile(anchor, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(b[at:at+1], int64(at)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// writeAnchor makes the chain.log at anchor hold body.
func writeAnchor(t *testing.T, anchor, body string) {
	t.Helper()
	if err := os.WriteFile(anchor, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// appendAnchor appends line to the chain.log at anchor.
func appendAnchor(t *testing.T, anchor, line string) {
	t.Helper()
	f, err := os.OpenFile(anchor, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(line); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
