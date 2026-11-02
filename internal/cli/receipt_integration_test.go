// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// receiptStep is one step of TestIntegrationReceiptOfAScriptedRunAtTierLandlock's agent, in the script format of the
// conformance suite's actor (test/conformance/cmd/actor's Action): the actor makes each step's syscall itself and
// prints its result as a JSON line.
type receiptStep struct {
	ID   string `json:"id"`
	Op   string `json:"op"`
	Path string `json:"path"`
	Dest string `json:"dest,omitempty"`
}

// receiptContract is that agent's contract, with the paths of the actor and of the program it may run to fill in:
// writes in out/, writes in held/ once a person approves each, those two the only programs, no network, and a hold
// that outlasts the test's wait for it.
const receiptContract = `version: 0
name: ireceipt
command: [%q]
tier: landlock
fs:
  write: ["./out/"]
  ask: ["./held/"]
exec:
  allow: [%q, %q]
net: {}
env:
  pass: ["PATH", "HOME"]
ask:
  timeout: 120s
limits:
  pids: 64
record: summary
`

// TestIntegrationReceiptOfAScriptedRunAtTierLandlock is the receipt end to end (L2-RECEIPT accept 9), unprivileged at
// tier landlock, in a world of its own (ledger_root, chain anchor, own log, runtime directory and HOME all under the
// test's directory): a real `tego run` of a scripted agent, whose held write the test approves as a person does (`tego
// ask`, then `tego approve`), then `tego receipt --json` as a reader runs it afterwards. The receipt must show what the
// agent did and nothing else: the files it wrote, the approved one among them, the one it deleted and the one it
// renamed; one refusal, the unlisted program, under its rule and reason, counted once although the ledger records it
// twice (the exec line and the refused line that mirrors it, measure R19); the programs that ran, the listed one among
// them and the refused one missing; and the one ask, approved by this test's uid. tego run's end summary must give the
// same numbers, and `tego receipt --verify` must verify the chain against the test's anchor. The other receipt tests
// read hand-built ledgers or the record fixtures, so only this one holds the receipt to what the seccomp supervisor and
// the ask broker write.
//
// The agent is the conformance actor, a static program that makes each step's syscall itself, never a shell script:
// a shell's own start depends on the host, and the receipt counts all of it. Where /bin/sh is bash (Fedora, RHEL,
// Amazon Linux, Arch) it opens /dev/tty for writing and looks the user up for $SHELL, refused before its first step
// (three refusals with Ubuntu's glibc: the open and two connects to nscd's socket). And GNU mv (9.5) tries renameat2
// with RENAME_NOREPLACE first, then renameat where the filesystem refuses the flag (NFS, 9p, FUSE without rename2):
// this tier continues an allowed call, so its line carries no result and the receipt lists both. The actor's rename
// is one rename(2).
func TestIntegrationReceiptOfAScriptedRunAtTierLandlock(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the agent runs as the invoking user, who cannot reach the test's 0700 directories; the unprivileged run covers the receipt")
	}
	bin := buildTegoBinary(t)
	// Resolved: the ledger records the paths the agent's calls resolve to, and the test compares the receipt with them.
	w, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(w, 0o700); err != nil { // the machine config's directory must not be group-writable (umask 002)
		t.Fatal(err)
	}
	home := filepath.Join(w, "home")
	own := filepath.Join(home, ".tego")
	root := filepath.Join(own, "runs")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(own, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg, anchor := filepath.Join(own, "machine.yaml"), filepath.Join(own, "chain.log")
	if err := os.WriteFile(cfg, []byte("version: 0\nledger_root: "+root+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := testutil.TegoEnv(t, w, "TEGO_CONFIG="+cfg, "TEGO_TEST_CHAIN_ANCHOR="+anchor, "HOME="+home)
	tego := func(args ...string) *exec.Cmd {
		cmd := exec.Command(bin, args...)
		cmd.Env = env
		return cmd
	}
	testutil.RequireTier(t, tego("doctor", "--require", "landlock"), "landlock")

	proj, progs := filepath.Join(w, "proj"), filepath.Join(w, "bin")
	out, held := filepath.Join(proj, "out"), filepath.Join(proj, "held", "config")
	for _, d := range []string{out, filepath.Dir(held), progs} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The agent, a program its contract lists and one it does not: three copies of the actor, so three inodes, as the
	// Landlock tier grants an exec by its file's inode.
	actor, listed, unlisted := filepath.Join(progs, "actor"), filepath.Join(progs, "listed"), filepath.Join(proj, "unlisted")
	actorBytes, err := os.ReadFile(buildActorBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	// A child the actor starts with argv [path, "noop"] exits 0 at once; one its contract does not list never starts.
	steps := []receiptStep{
		{ID: "new", Op: "create", Path: "out/new.txt"},
		{ID: "listed", Op: "exec", Path: listed},
		{ID: "unlisted", Op: "exec", Path: unlisted},
		{ID: "gone", Op: "create", Path: "out/gone.txt"},
		{ID: "delete", Op: "unlink", Path: "out/gone.txt"},
		{ID: "old", Op: "create", Path: "out/old.txt"},
		{ID: "rename", Op: "rename", Path: "out/old.txt", Dest: "out/moved.txt"},
		{ID: "held", Op: "open-trunc", Path: "held/config"},
	}
	script, err := json.Marshal(steps)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{held, []byte("ORIGINAL\n"), 0o644},
		{actor, actorBytes, 0o755},
		{listed, actorBytes, 0o755},
		{unlisted, actorBytes, 0o755},
		{filepath.Join(proj, "script.json"), script, 0o600},
		{filepath.Join(proj, "agent.yaml"), []byte(fmt.Sprintf(receiptContract, actor, actor, listed)), 0o600},
	} {
		if err := os.WriteFile(f.path, f.data, f.mode); err != nil {
			t.Fatal(err)
		}
	}

	run := tego("run", "agent.yaml", "--", actor, "run", "script.json")
	run.Dir = proj
	// The agent's stdout is the actor's results; tego run writes its own lines to stderr.
	met, said := &lockedBuffer{}, &lockedBuffer{}
	run.Stdout, run.Stderr = met, said
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	ended := make(chan struct{})
	var runErr error
	go func() { runErr = run.Wait(); close(ended) }()
	t.Cleanup(func() {
		select {
		case <-ended:
		default:
			_ = run.Process.Kill() // the test failed with the agent held: nothing else would end the run
			<-ended
		}
		if t.Failed() {
			t.Logf("the agent printed:\n%s\ntego run said:\n%s", met.String(), said.String())
		}
	})
	runID, askID := heldAsk(t, tego, ended)
	if ans, err := tego("approve", askID).CombinedOutput(); err != nil || !strings.Contains(string(ans), askID+": approved") {
		t.Fatalf("tego approve %s: %v\n%s", askID, err, ans)
	}
	select {
	case <-ended:
	case <-time.After(time.Minute):
		t.Fatal("tego run did not end within a minute of the approval")
	}
	if runErr != nil {
		t.Fatalf("tego run: %v", runErr)
	}
	// What the agent met, step by step: each one done but the unlisted program's exec, refused EACCES, the held open
	// done once approved.
	type result struct {
		ID    string `json:"id"`
		OK    bool   `json:"ok"`
		Errno int    `json:"errno"`
	}
	var results, expected []result
	for _, s := range steps {
		r := result{ID: s.ID, OK: true}
		if s.ID == "unlisted" {
			r = result{ID: s.ID, Errno: int(syscall.EACCES)}
		}
		expected = append(expected, r)
	}
	for _, line := range strings.Split(strings.TrimSpace(met.String()), "\n") {
		var r result
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("the agent printed %q, not a step's result: %v", line, err)
		}
		results = append(results, r)
	}
	if !slices.Equal(results, expected) {
		t.Errorf("the steps' results: %+v; want %+v", results, expected)
	}
	// On disk: the new files, the delete and the rename landed, and the approved open truncated the held file.
	for name, want := range map[string]string{"out/new.txt": "", "out/moved.txt": "", "held/config": ""} {
		if got, err := os.ReadFile(filepath.Join(proj, name)); err != nil || string(got) != want {
			t.Errorf("%s holds %q (%v), want %q", name, got, err, want)
		}
	}
	for _, name := range []string{"out/gone.txt", "out/old.txt"} {
		if _, err := os.Lstat(filepath.Join(proj, name)); err == nil {
			t.Errorf("%s is still there", name)
		}
	}

	type rcRule struct {
		Rule   string `json:"rule"`
		Reason string `json:"reason"`
		Count  int    `json:"count"`
	}
	type rcRefusal struct {
		Kind   string `json:"kind"`
		Op     string `json:"op"`
		Target string `json:"target"`
		Rule   string `json:"rule"`
		Reason string `json:"reason"`
	}
	type rcRename struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	type rcProgram struct {
		Path  string `json:"path"`
		Count int    `json:"count"`
	}
	// The keys a reader of the JSON reads (receipt_v 1, whose keys only grow), not the builder's Go type, so a renamed
	// key fails here.
	var rc struct {
		V        int    `json:"receipt_v"`
		Run      string `json:"run"`
		Agent    string `json:"agent"`
		Tier     string `json:"tier"`
		Ended    bool   `json:"ended"`
		ExitCode *int   `json:"exit_code"`
		Files    struct {
			Recorded bool       `json:"recorded"`
			Written  []string   `json:"written"`
			Deleted  []string   `json:"deleted"`
			Renamed  []rcRename `json:"renamed"`
		} `json:"files"`
		Programs []rcProgram `json:"programs"`
		Refusals struct {
			Total  int         `json:"total"`
			ByRule []rcRule    `json:"by_rule"`
			List   []rcRefusal `json:"list"`
		} `json:"refusals"`
		Asks struct {
			Asked      int `json:"asked"`
			Approved   int `json:"approved"`
			Denied     int `json:"denied"`
			Unanswered int `json:"unanswered"`
			List       []struct {
				AskID  string `json:"ask_id"`
				Op     string `json:"op"`
				Target string `json:"target"`
				Rule   string `json:"rule"`
				Answer string `json:"answer"`
				By     string `json:"by"`
			} `json:"list"`
		} `json:"asks"`
	}
	// No run named: the newest run under the ledger root, as `tego receipt --last` after a run reads it.
	var js, errs bytes.Buffer
	asJSON := tego("receipt", "--json")
	asJSON.Stdout, asJSON.Stderr = &js, &errs
	if err := asJSON.Run(); err != nil {
		t.Fatalf("tego receipt --json: %v\n%s", err, errs.String())
	}
	if err := json.Unmarshal(js.Bytes(), &rc); err != nil {
		t.Fatalf("tego receipt --json: %v\n%s", err, js.String())
	}
	if rc.V != 1 || rc.Run != runID || rc.Agent != "ireceipt" || rc.Tier != "landlock" || !rc.Ended || rc.ExitCode == nil ||
		*rc.ExitCode != 0 {
		t.Errorf("the receipt's run: %s", js.String())
	}
	// At tier landlock the seccomp supervisor records each allowed write-open, unlink and rename (files.recorded follows
	// run_start's record.exec_open_connect): every file the agent opened for writing, the held one the person approved
	// among them, and nothing else. No fs line at this tier carries `created` (only tier 2's kernel record sets it), so
	// the new files are listed as written and files.created stays empty: a limit of the record, which this test does
	// not pin. Nor does a line of a call this tier continued carry its result, so a call the kernel then failed would
	// be listed too; every step here succeeds, which the actor's results above say.
	written := []string{filepath.Join(out, "new.txt"), filepath.Join(out, "gone.txt"), filepath.Join(out, "old.txt"), held}
	slices.Sort(written)
	renamed := []rcRename{{From: filepath.Join(out, "old.txt"), To: filepath.Join(out, "moved.txt")}}
	if f := rc.Files; !f.Recorded || !slices.Equal(slices.Sorted(slices.Values(f.Written)), written) ||
		!slices.Equal(f.Deleted, []string{filepath.Join(out, "gone.txt")}) || !slices.Equal(f.Renamed, renamed) {
		t.Errorf("files: %+v; want recorded, written %q, deleted out/gone.txt, renamed %+v", f, written, renamed)
	}
	refused := rcRefusal{Kind: "exec", Op: "exec", Target: unlisted, Rule: "unmatched", Reason: "exec-not-allowed"}
	if rf := rc.Refusals; rf.Total != 1 || !slices.Equal(rf.ByRule, []rcRule{{"unmatched", "exec-not-allowed", 1}}) ||
		!slices.Equal(rf.List, []rcRefusal{refused}) {
		t.Errorf("refusals: %+v; want the one refused exec of %s, counted once", rf, unlisted)
	}
	// The agent and the listed program, each once; the unlisted program is not among them: a refused exec never ran.
	programs := slices.SortedFunc(slices.Values(rc.Programs), func(a, b rcProgram) int { return strings.Compare(a.Path, b.Path) })
	if want := []rcProgram{{actor, 1}, {listed, 1}}; !slices.Equal(programs, want) {
		t.Errorf("programs run: %+v; want %+v", programs, want)
	}
	if a := rc.Asks; a.Asked != 1 || a.Approved != 1 || a.Denied != 0 || a.Unanswered != 0 || len(a.List) != 1 ||
		a.List[0].AskID != askID || a.List[0].Op != "open" || a.List[0].Target != held || a.List[0].Rule != "fs.ask[./held/]" ||
		a.List[0].Answer != "approved" || !strings.HasPrefix(a.List[0].By, fmt.Sprintf("uid:%d ", os.Getuid())) {
		t.Errorf("asks: %+v; want ask %s, the write-open of %s, approved by uid %d", a, askID, held, os.Getuid())
	}

	// tego run's end summary is the same builder's (runsummary.go), over the same ledger.
	for _, want := range []string{
		fmt.Sprintf("tego run: %s ended (exited with code 0) · tier landlock · refused 1 (", runID),
		fmt.Sprintf(" · asked 1 (1 approved, 0 denied) · wrote %d files · chain verified\n", len(written)),
		"  more: tego receipt " + runID + "\n",
	} {
		if !strings.Contains(said.String(), want) {
			t.Errorf("tego run's end summary has no %q", want)
		}
	}
	verify, err := tego("receipt", runID, "--verify").CombinedOutput()
	if err != nil || !strings.Contains(string(verify), "Chain: "+runID+": verified") ||
		!strings.Contains(string(verify), "anchored in "+anchor) {
		t.Errorf("tego receipt %s --verify: %v\n%s", runID, err, verify)
	}
}

// buildActorBinary builds the conformance suite's actor (test/conformance/cmd/actor) CGO off, as that suite builds it:
// a static program, so the contract grants it no loader, and its own start makes no call a contract decides.
func buildActorBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "actor")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/attention-span-ai/tego/test/conformance/cmd/actor")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build actor: %v: %s", err, out)
	}
	return bin
}

// heldAsk waits for the one request the run holds, found as a person finds it: `tego ask --json` with no run lists
// every running run's pending asks. It returns the run's id and the ask's, and fails at once when tego run ends first.
func heldAsk(t *testing.T, tego func(...string) *exec.Cmd, ended <-chan struct{}) (runID, askID string) {
	t.Helper()
	var last string
	for deadline := time.Now().Add(time.Minute); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		select {
		case <-ended:
			t.Fatalf("tego run ended before its agent's write into held/ was held (tego ask said %s)", last)
		default:
		}
		out, err := tego("ask", "--json").Output()
		last = fmt.Sprintf("%q (%v)", out, err)
		var all struct {
			Runs []struct {
				Run     string `json:"run"`
				Pending []struct {
					AskID string `json:"ask_id"`
					Op    string `json:"op"`
					Rule  string `json:"rule"`
				} `json:"pending"`
			} `json:"runs"`
		}
		if err != nil || json.Unmarshal(out, &all) != nil || len(all.Runs) != 1 || len(all.Runs[0].Pending) != 1 {
			continue
		}
		// The list cuts a target past askproto.MaxSummaryTarget bytes, so the receipt's ask is what names it whole.
		p := all.Runs[0].Pending[0]
		if p.Op != "open" || p.Rule != "fs.ask[./held/]" {
			t.Fatalf("the held request %+v: want the write-open under fs.ask[./held/]", p)
		}
		return all.Runs[0].Run, p.AskID
	}
	t.Fatalf("no request was held within a minute (tego ask said %s)", last)
	return "", ""
}
