// SPDX-License-Identifier: Apache-2.0

//go:build integration && linux

package runtime

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// truncateProbe tries each way an agent empties a file, first against a file no rule lets it write, then, once the test
// has put a live block on a folder of the run's own write entry, against a file in the folder; every answer is the errno
// the call got. The descriptor early is opened for writing before the block, as a program that keeps a file open does.
// The order is held by two words outside the folder, never by timing: the probe makes ready once early is open and its
// rule-phase calls are answered, and the test puts the block on only then (a block already in force refuses the open of
// early itself, and the probe dies before it writes a result); the test makes go once the block is in force, and the
// probe makes its block-phase calls only then. The probe's wait ends at a deadline, so a test that died leaves nothing.
const truncateProbe = `import errno, json, os, sys, time
victim, folder, go, out, ready = sys.argv[1:6]
res = {}

def attempt(name, fn):
    try:
        fn()
        res[name] = "ok"
    except OSError as e:
        res[name] = errno.errorcode.get(e.errno, str(e.errno))

def opens(path, flags):
    def f():
        os.close(os.open(path, flags))
    return f

early = os.open(os.path.join(folder, "early.txt"), os.O_WRONLY)
reader = os.open(victim, os.O_RDONLY)
attempt("rule.truncate", lambda: os.truncate(victim, 0))
attempt("rule.open_wronly_trunc", opens(victim, os.O_WRONLY | os.O_TRUNC))
attempt("rule.open_rdonly_trunc", opens(victim, os.O_RDONLY | os.O_TRUNC))
attempt("rule.ftruncate_on_a_read_descriptor", lambda: os.ftruncate(reader, 0))
open(ready, "w").close()
limit = time.time() + 120
while not os.path.exists(go):
    if time.time() > limit:
        sys.exit("the test never said go")
    time.sleep(0.02)
a = os.path.join(folder, "a.txt")
attempt("block.truncate", lambda: os.truncate(a, 0))
attempt("block.open_wronly_trunc", opens(a, os.O_WRONLY | os.O_TRUNC))
attempt("block.open_rdonly_trunc", opens(a, os.O_RDONLY | os.O_TRUNC))
attempt("block.ftruncate_early", lambda: os.ftruncate(early, 0))
json.dump(res, open(out, "w"))
`

// TestIntegrationTruncateRefusalsAreRecorded is the record of an agent's truncate(2), ftruncate(2) and O_TRUNC open on
// the real kernel, at tier landlock, under a rule that forbids the write and under a live block. On a kernel whose
// Landlock has no truncate right (ABI below 3: Amazon Linux 2023's 6.1) the filter once answered truncate(2) and an
// O_RDONLY|O_TRUNC open with EPERM itself and the ledger held no line for either; the supervisor answers them now, the
// same EPERM, with a refused line under the rule landlock-no-truncate. From ABI 3 Landlock's own right refuses them with
// EACCES, and the line is the contract's or the live block's. Whatever the kernel, no refused call emptied the file, and
// each has a refused line that names its path. ftruncate(2) of a descriptor opened for writing before the block is
// neither refused nor recorded at tier landlock (no filter arm sees it): its answer is reported, not required.
func TestIntegrationTruncateRefusalsAreRecorded(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	abi, err := sys.LandlockABI()
	if err != nil {
		t.Skipf("the Landlock ABI of this machine: %v", err)
	}
	f := newFixture(t, contractFor("itruncaterecord", []string{python}, []string{python, resolved}))
	const content = "keep me\n"
	data := filepath.Join(f.dir, "data")
	folder := filepath.Join(f.out, "blk")
	for _, d := range []string{data, folder} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	victim, a, early := filepath.Join(data, "victim.txt"), filepath.Join(folder, "a.txt"), filepath.Join(folder, "early.txt")
	for _, p := range []string{victim, a, early} {
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	script := filepath.Join(f.dir, "probe.py")
	if err := os.WriteFile(script, []byte(truncateProbe), 0o644); err != nil {
		t.Fatal(err)
	}
	agentReaches(t, data)
	agentOwns(t, data, folder, victim, a, early, script)
	word, ready, out := filepath.Join(f.out, "go"), filepath.Join(f.out, "ready"), filepath.Join(f.out, "result.json")

	ran := make(chan error, 1)
	go func() {
		_, err := Run(context.Background(), f.rt, []string{python, script, victim, folder, word, out, ready}, f.deps(t, nil))
		ran <- err
	}()
	deadline := time.Now().Add(60 * time.Second)
	dir := liveRunDir(t, f.root, ran, deadline, 10*time.Millisecond)
	// The block goes on only once the probe holds early open: a block in force first refuses that open.
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		select {
		case err := <-ran:
			t.Fatalf("the run ended before the probe was ready (%v)", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the probe never said ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	value, err := liveblock.Normalize(liveblock.KindWrite, folder)
	if err != nil {
		t.Fatal(err)
	}
	updateOverlay(t, dir, filepath.Base(dir), func(o *liveblock.Overlay) error {
		_, _, err := o.Add(liveblock.KindWrite, value, "t", time.Now())
		return err
	})
	for inForce := false; !inForce; {
		raw, _ := os.ReadFile(filepath.Join(dir, "events.jsonl"))
		if inForce = strings.Contains(string(raw), "live-block-added"); !inForce {
			select {
			case err := <-ran:
				t.Fatalf("the block never came into force: the run ended first (%v)", err)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatal("the block never came into force")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	touch(t, word)
	if err := <-ran; err != nil {
		t.Fatalf("Run: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the probe wrote nothing: %v", err)
	}
	got := map[string]string{}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	t.Logf("Landlock ABI %d; what each call got: %v", abi, got)

	for _, p := range []string{victim, a} {
		if b, err := os.ReadFile(p); err != nil || string(b) != content {
			t.Errorf("%s = %q (%v), want it untouched: a refused call emptied it", p, b, err)
		}
	}
	lines := events(t, dir)
	type want struct {
		call, path, op string
		trunc          bool   // the filter's arm answers it below ABI 3
		errno          string // above ABI 3; "" where this test does not pin it
		liveRule       bool
	}
	blockRule := liveblock.Rule(liveblock.KindWrite, value)
	for _, w := range []want{
		{"rule.truncate", victim, record.FSTruncate, true, "EACCES", false},
		{"rule.open_wronly_trunc", victim, record.FSOpen, false, "EACCES", false},
		{"rule.open_rdonly_trunc", victim, record.FSOpen, true, "", false},
		{"block.truncate", a, record.FSTruncate, true, "EACCES", true},
		{"block.open_wronly_trunc", a, record.FSOpen, false, "EACCES", true},
		{"block.open_rdonly_trunc", a, record.FSOpen, true, "", true},
	} {
		belowABI3 := abi < 3 && w.trunc
		wantErrno := w.errno
		if belowABI3 {
			wantErrno = "EPERM"
		}
		if got[w.call] == "ok" || got[w.call] == "" || (wantErrno != "" && got[w.call] != wantErrno) {
			t.Errorf("%s: got %q, want %s (ABI %d)", w.call, got[w.call], orAny(wantErrno), abi)
		}
		var found *record.Event
		for _, e := range lines {
			var p record.FSPayload
			if e.Kind != record.KindFS || e.DecodePayload(&p) != nil || p.Op != w.op || p.Path != w.path ||
				e.Verdict != record.VerdictRefused {
				continue
			}
			if w.op == record.FSOpen && p.Flags&unix.O_TRUNC == 0 {
				continue
			}
			wrOnly := p.Flags&unix.O_ACCMODE == unix.O_WRONLY
			if w.op == record.FSOpen && wrOnly != strings.Contains(w.call, "wronly") {
				continue
			}
			found = e
		}
		switch {
		case found == nil:
			t.Errorf("%s: the ledger has no refused %s line for %s (ABI %d)", w.call, w.op, w.path, abi)
		case belowABI3 && found.Rule != "landlock-no-truncate":
			t.Errorf("%s: refused under %q, want landlock-no-truncate below ABI 3", w.call, found.Rule)
		case !belowABI3 && w.liveRule && found.Rule != blockRule:
			t.Errorf("%s: refused under %q, want the live block's %q", w.call, found.Rule, blockRule)
		}
	}
	// What the early descriptor's ftruncate got is the stated residual: tier landlock decides no ftruncate.
	t.Logf("ftruncate of a descriptor opened for writing before the block: %s (no line is written for it at this tier)", got["block.ftruncate_early"])
}

func orAny(s string) string {
	if s == "" {
		return "a refusal"
	}
	return s
}
