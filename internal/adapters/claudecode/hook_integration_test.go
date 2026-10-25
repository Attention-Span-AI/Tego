// SPDX-License-Identifier: Apache-2.0

//go:build integration

package claudecode

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/reason"
)

// buildTego builds cmd/tego with tegotesthooks (its chain anchor and own log go where testutil.TegoEnv says).
func buildTego(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "tego")
	cmd := exec.Command("go", "build", "-tags", "tegotesthooks", "-o", bin, "github.com/attention-span-ai/tego/cmd/tego")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, out)
	}
	return bin
}

// TestHookUnderTegoRunIsRefusedNothing is acceptance (7): the built hook, run as the agent of a tier-landlock run
// with record: full and a contract that grants it nothing but hook-state (and the run's own out/), answers its events
// and adds no refusal: it touches only its executable, /proc/self, the reason file and hook-state (and the Go
// runtime's start-up reads; the whole set, bpf(2) included, is TestHookMakesOnlyItsDocumentedSyscalls's, since a
// tier-landlock run mediates no bpf(2) call). One deliberate refused write after the hooks proves the run records
// refusals at all, and it is the only refused line.
//
// It runs the hook in two homes. In the first, HOME's .tego is the run's own read-denied tego directory (the
// launcher's chain anchor is there, and so are the machine config, which TEGO_CONFIG names to the hook too, and the
// ledger root, which TEGO_LEDGER names): a hook that read ~/.tego, the machine config or the ledger would leave a
// refused line there, which is the trap the package names, a refusal on every tool call. In the second HOME is a
// directory nobody may read, and the hook still works: it reads no home at all. A home whose .tego the run does not
// deny would hide a read of it behind DAC.
//
// The hook finds the reason file through TEGO_REASON alone, with no XDG_RUNTIME_DIR in its environment, as under a
// contract whose env.pass leaves that variable out. The reason files and hook-state are the test's, in runtime
// directories of a run named for the test under bases of their own, since the launcher of this build makes no
// hook-state yet (the harness files step makes and grants it); the hook's own system calls are the same either way.
func TestHookUnderTegoRunIsRefusedNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the agent runs as the invoking user, who cannot reach the test's 0700 directories; the hook's calls are the same")
	}
	bin := buildTego(t)
	w := t.TempDir()
	if err := os.Chmod(w, 0o700); err != nil { // the machine config's directory must not be group-writable (umask 002)
		t.Fatal(err)
	}
	home := filepath.Join(w, "home")
	own := filepath.Join(home, ".tego")
	ledger := filepath.Join(own, "runs")
	if err := os.MkdirAll(ledger, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(own, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(own, "machine.yaml")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\n", ledger)), 0o600); err != nil {
		t.Fatal(err)
	}
	env := testutil.TegoEnv(t, w, "TEGO_CONFIG="+cfg, "TEGO_TEST_CHAIN_ANCHOR="+filepath.Join(own, "chain.log"), "HOME="+home)
	doctor := exec.Command(bin, "doctor", "--require", "landlock")
	doctor.Env = env
	testutil.RequireTier(t, doctor, "landlock")

	fixtureAt := func(xdg string) *fixture {
		f := &fixture{xdg: xdg, dir: filepath.Join(xdg, runtimeDirName, testRun)}
		f.reasonFile = filepath.Join(f.dir, reason.FileName)
		if err := os.MkdirAll(filepath.Join(f.dir, StateDirName), 0o700); err != nil {
			t.Fatal(err)
		}
		f.refusals(t, 3)
		return f
	}
	inHome, inNoHome := fixtureAt(filepath.Join(w, "xa")), fixtureAt(filepath.Join(w, "xb"))
	nohome := filepath.Join(w, "nohome")
	if err := os.Mkdir(nohome, 0); err != nil {
		t.Fatal(err)
	}
	pay, err := filepath.Abs(filepath.Join("testdata", "payloads", "post-tool-use-write.json"))
	if err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(w, "proj")
	if err := os.MkdirAll(filepath.Join(proj, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	forbidden := filepath.Join(w, "forbidden")
	script := `#!/bin/sh
# $1 the hook, $2 the payload, $3 the machine config, $4 HOME and $5 the reason file of each half in turn, then
# $6 the nobody-may-read home and $7 its reason file, $8 the path of the deliberate refused write.
unset XDG_RUNTIME_DIR
hook() { # name HOME TEGO_REASON
  HOME="$2" TEGO_CONFIG="$CFG" TEGO_REASON="$3" "$BIN" hook claude-code <"$PAY" >out/$1.out 2>out/$1.err
  echo $? >out/$1.rc
}
BIN=$1 PAY=$2 CFG=$3
hook home1 "$4" "$5"
hook home2 "$4" "$5"
hook nohome1 "$6" "$7"
hook nohome2 "$6" "$7"
echo x >"$8" 2>/dev/null
exit 0
`
	if err := os.WriteFile(filepath.Join(proj, "probe.sh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	contract := fmt.Sprintf(`version: 0
name: hookprobe
command: ["/bin/sh", "./probe.sh"]
tier: landlock
record: full
fs:
  write: ["./out/", %q, %q]
exec:
  allow: ["/bin/sh", "/usr/bin/sh", %q]
env:
  pass: ["PATH"]
limits:
  pids: 64
`, filepath.Join(inHome.dir, StateDirName)+"/", filepath.Join(inNoHome.dir, StateDirName)+"/", bin)
	if err := os.WriteFile(filepath.Join(proj, "agent.yaml"), []byte(contract), 0o600); err != nil {
		t.Fatal(err)
	}
	run := exec.Command(bin, "run", "agent.yaml", "--", "/bin/sh", "./probe.sh", bin, pay, cfg,
		home, inHome.reasonFile, nohome, inNoHome.reasonFile, forbidden)
	run.Dir, run.Env = proj, env
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("tego run: %v\n%s", err, out)
	}

	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(proj, "out", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	want := reason.Render([]reason.Entry{entry(t, 0), entry(t, 1), entry(t, 2)}, 0)
	for _, half := range []struct {
		name string
		f    *fixture
	}{{"home", inHome}, {"nohome", inNoHome}} {
		if rc, e := read(half.name+"1.rc"), read(half.name+"1.err"); strings.TrimSpace(rc) != "0" || e != "" {
			t.Errorf("%s, first hook: exit %s, stderr %q", half.name, rc, e)
		} else if got := context(t, read(half.name+"1.out"), EventPostToolUse); got != want {
			t.Errorf("%s, first hook told:\n%s\nwant\n%s", half.name, got, want)
		}
		if rc, o, e := read(half.name+"2.rc"), read(half.name+"2.out"), read(half.name+"2.err"); strings.TrimSpace(rc) != "0" || o != "" || e != "" {
			t.Errorf("%s, second hook, nothing new: exit %s, stdout %q, stderr %q", half.name, rc, o, e)
		}
		if s := half.f.state(t); s.Cursor != refusalAt(2).Seq || s.Deliveries != 1 {
			t.Errorf("%s: state %+v", half.name, s)
		}
	}

	runs, err := filepath.Glob(filepath.Join(ledger, "*", "events.jsonl"))
	if err != nil || len(runs) != 1 {
		t.Fatalf("ledger runs %v (%v), want one", runs, err)
	}
	// The deliberate write is an action line with verdict refused and its kind: refused line; nothing else is.
	refused := refusedLines(t, runs[0])
	for _, l := range refused {
		if !strings.Contains(l, forbidden) {
			t.Errorf("a refusal the hook caused: %s", l)
		}
	}
	if len(refused) == 0 {
		t.Errorf("no refused line at all, not even the deliberate write to %s: the run recorded no refusals", forbidden)
	}
}

// refusedLines is every line of a run's ledger that records a refusal.
func refusedLines(t *testing.T, path string) []string {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	var out []string
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 1<<16), 4<<20)
	for sc.Scan() {
		var l struct {
			Kind    string `json:"kind"`
			Verdict string `json:"verdict"`
		}
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if l.Kind == "refused" || l.Verdict == "refused" {
			out = append(out, sc.Text())
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
