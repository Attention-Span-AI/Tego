// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// modeGateReadWrite runs the target under a write entry on the harness directory, a worktree at <dir>/work and the
// filter of a run whose gate scores fs.read only, under record: summary (gate.md R1, amended 2026-10-16).
const modeGateReadWrite = "gaterdwr"

// gateReadWriteRuleTable is the harness's rule table for modeGateReadWrite: the whole harness directory writable, so
// that only the gate can refuse an open.
func gateReadWriteRuleTable(dir string) *agent.RuleTable {
	return &agent.RuleTable{
		FS:      []agent.FSRule{{Path: dir, Kind: agent.FSWrite, Resolved: dir}},
		Workdir: filepath.Join(dir, "work"),
		Record:  agent.RecordSummary, Tier: backend.TierLandlock, Contract: &agent.Contract{},
	}
}

// gateReadWritePrepare makes the secret work/a.env and an unmatched work/b.txt.
func gateReadWritePrepare(t *testing.T) func(dir string) {
	return func(dir string) {
		if err := os.MkdirAll(filepath.Join(dir, "work"), 0o755); err != nil {
			t.Fatal(err)
		}
		for name, body := range map[string]string{"work/a.env": "SECRET=1", "work/b.txt": "plain"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// gateReadWriteChecks opens the secret and the unmatched file in each access mode. Each check's Out is what a read
// of the descriptor returned ("" for a write-only one, which cannot be read).
func gateReadWriteChecks() []checkResult {
	dir := os.Getenv(helperDir)
	secret, plain := filepath.Join(dir, "work/a.env"), filepath.Join(dir, "work/b.txt")
	var out []checkResult
	open := func(name, path string, flags int) {
		fd, err := unix.Open(path, flags|unix.O_CLOEXEC, 0o600)
		got := ""
		if err == nil {
			if flags&unix.O_ACCMODE != unix.O_WRONLY {
				buf := make([]byte, 64)
				if n, rerr := unix.Read(fd, buf); rerr == nil {
					got = string(buf[:n])
				}
			}
			_ = unix.Close(fd)
		}
		out = append(out, checkResult{Name: name, Err: errText(err), Out: got})
	}
	open("secret_rdonly", secret, unix.O_RDONLY)
	open("secret_rdwr", secret, unix.O_RDWR)
	open("secret_rdonly_creat", secret, unix.O_RDONLY|unix.O_CREAT)
	open("secret_wronly", secret, unix.O_WRONLY|unix.O_APPEND)
	open("plain_rdwr", plain, unix.O_RDWR)
	return out
}

// TestGateReadRefusesAReadWriteOpen is gate.md R1's 2026-10-16 amendment end
// to end on a real kernel, real filter and real Loop: under a gate `fs.read matches "*.env": 90` alone, an O_RDWR
// open of a.env, and an O_RDONLY|O_CREAT one, are refused with R10's errno and a refused fs-gate line, as the
// read-only open is, and read nothing. Before, both were scored as writes only and continued, and the O_RDWR
// descriptor read SECRET=1. An O_WRONLY open of the secret reads nothing and is continued, and so is an O_RDWR open
// of a name the gate does not match.
func TestGateReadRefusesAReadWriteOpen(t *testing.T) {
	g, err := gate.New([]gate.Rule{{Predicate: gate.ReadMatches, Argument: "*.env", Score: 90}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	h := startHarnessWith(t, harnessOpts{mode: modeGateReadWrite, prepare: gateReadWritePrepare(t), gate: g})
	h.stop(t)
	for _, name := range []string{"secret_rdonly", "secret_rdwr", "secret_rdonly_creat"} {
		if c := h.check(t, name); !isErrno(c.Err, refusalErrno) || c.Out != "" {
			t.Errorf("%s = %+v, want R10's errno and nothing read", name, c)
		}
	}
	if c := h.check(t, "secret_wronly"); c.Err != "" {
		t.Errorf("secret_wronly = %+v, want it continued", c)
	}
	if c := h.check(t, "plain_rdwr"); c.Err != "" || c.Out != "plain" {
		t.Errorf("plain_rdwr = %+v, want it continued and read", c)
	}
	secret := filepath.Join(h.dir, "work/a.env")
	refused := 0
	for _, ev := range h.sink.all() {
		if ev.Kind != record.KindFS || ev.Verdict != record.VerdictRefused {
			continue
		}
		var p record.FSPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if p.Op != record.FSOpen || p.Path != secret || ev.Authority != record.AuthorityGate || ev.Reason != record.ReasonFSGate {
			t.Errorf("refused line %s %q: authority %s reason %s, want open %q under the gate (%s)", p.Op, p.Path,
				ev.Authority, ev.Reason, secret, record.ReasonFSGate)
		}
		refused++
	}
	if refused != 3 {
		t.Errorf("%d refused open lines, want 3 (read-only, read-write and read-only creating opens of the secret)", refused)
	}
}
