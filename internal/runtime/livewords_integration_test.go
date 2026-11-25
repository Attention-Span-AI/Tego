// SPDX-License-Identifier: Apache-2.0

//go:build integration && linux

package runtime

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ADR 0171 on the real kernel, as root: a live block on a command's words, placed through the run's overlay as `tego
// block` places it, refuses the next such command of a running agent at every tier a root launcher runs (landlock, and the
// decision plane's cgroup and bpflsm tiers in each mode this machine offers), the same program with other words keeps
// running, and lifting the block runs the command again.

// wordsProbe waits for each phase's word in out/, runs each command line with the program named git (a copy of true(1) the
// test puts first on PATH, which the matcher's rows know as git) and writes what each came to, as an errno name or "ok", to
// out/phase<N>.json, with under "_why" the file each refusal named (an exec's refusal names git; a refusal of anything else
// the launch of a command needs, such as a file opened to write, names that file). Its commands' output goes to pipes,
// never to /dev/null: the contract grants no write there, and subprocess opening it for write is refused EACCES in the
// agent before any command is started, which reads in the result like the exec's refusal and is not.
const wordsProbe = `import errno, json, os, subprocess, time
P = os.path.join(os.getcwd(), "out")
CMDS = [("push", ["git", "push"]), ("push_origin_main", ["git", "push", "origin", "main"]), ("dash_C_push", ["git", "-C", ".", "push"]),
        ("status", ["git", "status"]), ("stash_push", ["git", "stash", "push"])]
def wait(word):
    while not os.path.exists(os.path.join(P, word)):
        time.sleep(0.02)
def phase(n):
    wait("go" + n)
    res = {"_why": {}}
    for name, argv in CMDS:
        try:
            r = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            res[name] = "ok" if r.returncode == 0 else "exit %d" % r.returncode
        except OSError as e:
            res[name] = errno.errorcode.get(e.errno, str(e.errno))
            res["_why"][name] = str(e.filename)
    tmp = os.path.join(P, "phase" + n + ".tmp")
    with open(tmp, "w") as f:
        json.dump(res, f)
    os.rename(tmp, os.path.join(P, "phase" + n + ".json"))
open(os.path.join(P, "ready"), "w").close()
for n in "123":
    phase(n)
`

// wordsHold is the agent of the older-launcher test: it makes out/ready and waits for out/stop.
const wordsHold = `import os, time
P = os.path.join(os.getcwd(), "out")
open(os.path.join(P, "ready"), "w").close()
while not os.path.exists(os.path.join(P, "stop")):
    time.sleep(0.02)
`

// The ways a scene's contract grants the program git (newWordsScene): by the command entries `git push` and `git status`
// (the run has command rules, which turn the plane's exec handover off by themselves), or bare, with no entry that names
// words: by the path of the git copy, or by the folder that holds it (compile then builds no command rules for git, so
// only a block on a command's words keeps the supervisor deciding every exec).
const (
	grantWords  = "words"
	grantPath   = "path"
	grantFolder = "folder"
)

// newWordsScene is a root run of probe at tier (and plane, "" for none) under bin: fs.write on ./out/ and nothing else.
// grant says how its contract allows the program git: grantWords by the command entries `git push` and `git status` (so
// a command of the probe that is neither is refused by the contract itself), grantPath by the path of the git copy and
// grantFolder by its folder (every command of git is then allowed). The git copy is first on the test's PATH (wordsToolDir).
func newWordsScene(t *testing.T, bin, tier, plane, grant, python, resolved, probe, body string) *askReadScene {
	t.Helper()
	if _, _, ok := agentUID(t); !ok {
		t.Skip("needs SUDO_UID naming the invoking user, as `sudo go test` and test/vm/root-suites.sh give")
	}
	q := func(ss ...string) string {
		out := make([]string, 0, len(ss))
		for _, s := range ss {
			out = append(out, fmt.Sprintf("%q", s))
		}
		return "[" + strings.Join(out, ", ") + "]"
	}
	gitAllow := []string{"git push", "git status"}
	if grant != grantWords {
		gitPath, err := exec.LookPath("git")
		if err != nil || !filepath.IsAbs(gitPath) {
			t.Fatalf("the git copy is not first on PATH: %q, %v", gitPath, err)
		}
		gitAllow = []string{gitPath}
		if grant == grantFolder {
			gitAllow = []string{filepath.Dir(gitPath) + "/"}
		}
	}
	contract := fmt.Sprintf(`version: 0
name: rootwords
command: %s
tier: landlock
fs:
  write: ["./out/"]
exec:
  allow: %s
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 64
record: summary
`, q(python), q(append([]string{python, resolved}, gitAllow...)...))
	s := &askReadScene{bin: bin}
	s.f = newFixture(t, contract)
	pinned := strings.Replace(contract, "tier: landlock\n", "tier: "+tier+"\n", 1)
	if err := os.WriteFile(filepath.Join(s.f.dir, "agent.yaml"), []byte(pinned), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(s.f.dir, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.f.dir, probe), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	agentOwnsTree(t, filepath.Join(s.f.dir, "out"))
	agentOwns(t, filepath.Join(s.f.dir, "agent.yaml"), filepath.Join(s.f.dir, probe))
	s.env = isolatedEnv(t, s.f)
	if plane != "" {
		s.env = append(s.env, "TEGO_TEST_PLANE="+plane)
	}
	return s
}

// wordsToolDir makes a folder, readable and searchable by the agent, holding a copy of true(1) named git, and puts it first
// on this process's PATH for the test: the contract's entry `git push` resolves git there when the run is compiled, and the
// agent finds it there.
func wordsToolDir(t *testing.T) {
	t.Helper()
	truePath, err := exec.LookPath("true")
	if err != nil {
		t.Skipf("no true(1) to copy: %v", err)
	}
	b, err := os.ReadFile(truePath)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "tego-words-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "git"), b, 0o755); err != nil { //nolint:gosec // an executable fixture
		t.Fatal(err)
	}
	// The file's mode is the umask's as made; the agent runs as the invoking user, so the file and every folder above it
	// up to this package's temporary parent must be searchable and executable by that user.
	git := filepath.Join(dir, "git")
	if err := os.Chmod(git, 0o755); err != nil { //nolint:gosec // an executable fixture
		t.Fatal(err)
	}
	agentReaches(t, git)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}

// wordsPython is the python3 the agent runs and its resolved path, both named by the contract's exec entries.
func wordsPython(t *testing.T) (python, resolved string) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err = filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	return python, resolved
}

// startWordsRun starts the scene's run of probe and returns its directory, its id and the channel its end is sent on.
func startWordsRun(t *testing.T, s *askReadScene, python, probe string) (dir, id string, ended chan error, out *strings.Builder) {
	t.Helper()
	cmd := s.tego(t, "run", filepath.Join(s.f.dir, "agent.yaml"), "--", python, probe)
	cmd.Dir = s.f.dir
	out = &strings.Builder{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ended = make(chan error, 1)
	go func() { ended <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() }) // a no-op once the run has ended
	dir = liveRunDir(t, s.f.root, ended, time.Now().Add(30*time.Second), 10*time.Millisecond)
	return dir, filepath.Base(dir), ended, out
}

// TestRootLiveBlockOnCommandWords, for each tier and for each way the contract grants git (grantWords, grantPath,
// grantFolder). With the contract allowing `git push` and `git status` (grantWords), a probe runs five command lines in
// each of three phases. Phase 1 (no block): push, push origin main, -C . push and status run, stash push is refused by the
// contract itself (EACCES). A block on the command `git push` is placed through the overlay (the launcher's words mark is
// there, its live-block-added line is in): phase 2 refuses the three push lines EACCES and runs status, stash push staying
// the contract's refusal, so a refusal that is the block's is told from the contract's by the counts below. The block is
// removed: phase 3 is phase 1. The ledger holds three refused exec lines under live.block[exec:git push], and the
// contract's own refusals name the contract's rule.
//
// With git granted bare (grantPath, grantFolder) the contract has no command rule, so at a plane tier the kernel's exec
// handover is on unless the block itself turns it off: phase 1 runs all five lines, phase 2 refuses the three push lines
// and runs status and stash push (a different command from `git push`), phase 3 is phase 1, the ledger holds three
// refused lines under the block and none under the contract's own rules. These rows show the supervisor deciding the
// exec on a real plane because a block on words stands, and that status and stash push, which a plane
// that handed the exec over would run, are run for the right reason: they reach the supervisor, which finds no rule.
func TestRootLiveBlockOnCommandWords(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the root launcher at tiers landlock, cgroup and bpflsm")
	}
	bin := tegoBPFBinary(t)
	python, resolved := wordsPython(t)
	wordsToolDir(t)
	planes := append([]struct{ tier, plane string }{{"landlock", ""}}, strictPlanes...)
	type scene struct{ tier, plane, grant string }
	var scenes []scene
	for _, tc := range planes {
		for _, grant := range []string{grantWords, grantPath, grantFolder} {
			scenes = append(scenes, scene{tc.tier, tc.plane, grant})
		}
	}
	for _, tc := range scenes {
		name := tc.tier + "/" + tc.plane + "/" + tc.grant
		if tc.plane == "" {
			name = tc.tier + "/no-plane/" + tc.grant
		}
		t.Run(name, func(t *testing.T) {
			s := newWordsScene(t, bin, tc.tier, tc.plane, tc.grant, python, resolved, "probe.py", wordsProbe)
			requireStrictPlane(t, s, tc.tier, tc.plane)
			dir, id, ended, out := startWordsRun(t, s, python, "probe.py")
			awaitFile(t, filepath.Join(s.f.out, "ready"), ended, out)
			if !liveblock.TakesWords(dir) {
				t.Fatalf("the launcher made no %s mark in %s: a writer would refuse the run", liveblock.WordsName, dir)
			}
			phase := func(n string) map[string]any {
				if err := os.WriteFile(filepath.Join(s.f.out, "go"+n), nil, 0o644); err != nil {
					t.Fatal(err)
				}
				return awaitJSON(t, filepath.Join(s.f.out, "phase"+n+".json"), ended, out)
			}
			want := func(label string, got map[string]any, wantErr map[string]string) bool {
				t.Helper()
				ok := true
				for _, k := range []string{"push", "push_origin_main", "dash_C_push", "status", "stash_push"} {
					w := wantErr[k]
					if w == "" {
						w = "ok"
					}
					if got[k] != w {
						ok = false
						t.Errorf("%s: %s = %v, want %s (all: %v)", label, k, got[k], w, got)
					}
				}
				return ok
			}
			contractOnly := map[string]string{"stash_push": "EACCES"}
			blocked := map[string]string{"push": "EACCES", "push_origin_main": "EACCES", "dash_C_push": "EACCES", "stash_push": "EACCES"}
			if tc.grant != grantWords {
				contractOnly = map[string]string{} // a bare grant: the contract refuses none of the five
				blocked = map[string]string{"push": "EACCES", "push_origin_main": "EACCES", "dash_C_push": "EACCES"}
			}
			// Phase 1 is the scene's own control: nothing is blocked, so every command line must come to what the contract
			// alone says. When it does not, the scene is broken (the agent cannot run its git stand-in at all), and phases 2
			// and 3 would prove nothing: stop here, and say what the ledger refused.
			if !want("phase 1, no block", phase("1"), contractOnly) {
				t.Fatalf("the scene itself is broken, not the block: with no block in force the commands of phase 1 do not come to what the contract alone gives (above), so phases 2 and 3 prove nothing. Look at \"_why\" in the result for the file a refusal named, at the refused lines of the run's ledger below (a refusal of a file the agent needs, such as a write to /dev/null or the stand-in's folder, is the scene's), and at whether the agent's uid can search every folder down to %s and execute it.\n%s", filepath.Dir(wordsGitPath(t)), sceneRefusals(t, dir))
			}

			block := func(add bool) {
				updateOverlay(t, dir, id, func(o *liveblock.Overlay) error {
					var err error
					if add {
						_, _, err = o.Add(liveblock.KindExec, "git push", "uid:0 pid:1 cli", time.Now())
					} else {
						_, _, err = o.Remove(liveblock.KindExec, "git push", "uid:0 pid:1 cli", time.Now())
					}
					return err
				})
			}
			block(true)
			awaitGap(t, dir, record.GapLiveBlockAdded, 1, ended)
			want("phase 2, blocked", phase("2"), blocked)
			block(false)
			awaitGap(t, dir, record.GapLiveBlockRemoved, 1, ended)
			want("phase 3, block removed", phase("3"), contractOnly)

			select {
			case err := <-ended:
				if code := exitCodeOf(t, err); code != 0 {
					t.Fatalf("tego run exited %d:\n%s", code, out.String())
				}
			case <-time.After(60 * time.Second):
				t.Fatalf("tego run did not end:\n%s", out.String())
			}
			evs := events(t, dir)
			if tc.plane != "" {
				if got := runPlane(t, evs); got != tc.plane {
					t.Fatalf("the run's decision plane is %q, want %q", got, tc.plane)
				}
			}
			live, contract := 0, 0
			for _, e := range evs {
				if e.Kind != record.KindExec || e.Verdict != record.VerdictRefused {
					continue
				}
				switch {
				case e.Rule == "live.block[exec:git push]":
					live++
				case strings.HasPrefix(e.Rule, "exec."):
					contract++
				}
			}
			if live != 3 {
				t.Errorf("%d exec lines refused under live.block[exec:git push], want 3 (the push, push origin main and -C . push of phase 2)", live)
			}
			wantContract := 3
			if tc.grant != grantWords {
				wantContract = 0
			}
			if contract != wantContract {
				t.Errorf("%d exec lines refused under the contract's own rules, want %d (stash push in each phase when the contract has command rules, none for a bare grant): the block must not take them over", contract, wantContract)
			}
		})
	}
}

// wordsGitPath is where the agent's PATH finds git: the stand-in wordsToolDir put first.
func wordsGitPath(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("no git on PATH: %v", err)
	}
	return p
}

// sceneRefusals is the refused exec and file lines of the run so far, one per line with their rule and payload, for the
// message of a scene that is broken.
func sceneRefusals(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	n := 0
	for _, e := range events(t, dir) {
		if (e.Kind != record.KindExec && e.Kind != record.KindFS) || e.Verdict != record.VerdictRefused {
			continue
		}
		if n++; n > 12 {
			b.WriteString("  ...\n")
			break
		}
		fmt.Fprintf(&b, "  %s refused under %q: %s\n", e.Kind, e.Rule, e.Payload)
	}
	if n == 0 {
		return "the ledger holds no refused exec or file line: the refusal came from outside the run's rules (a file mode, an unreachable folder, a missing program)"
	}
	return b.String()
}

// olderTegoPath is where a row stages a tego built from the revision before command blocks (the test's own file name for it,
// TEGO_OLDER_TEGO naming another): test/vm/root-suites.sh puts VM_FIXTURE_ROOT's files at the guest's root.
const olderTegoPath = "/older-tego/tego"

// TestRootOlderLauncherRefusesACommandBlock: a run launched by a tego from before command blocks makes no words mark,
// so the current `tego block` refuses it in words ([launcher-too-old], exit 1) and writes nothing; a version 6 overlay forced
// into its folder is refused by that launcher whole (it writes live-block-unreadable once a block was in force, here a
// program block placed first, which stays in force) and the agent runs on.
func TestRootOlderLauncherRefusesACommandBlock(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the root launcher")
	}
	old := os.Getenv("TEGO_OLDER_TEGO")
	if old == "" {
		old = olderTegoPath
	}
	if _, err := os.Stat(old); err != nil {
		t.Skipf("no older tego at %s (a row stages one built from the revision before command blocks): %v", old, err)
	}
	bin := tegoBPFBinary(t)
	python, resolved := wordsPython(t)
	wordsToolDir(t)
	s := newWordsScene(t, old, "landlock", "", grantWords, python, resolved, "hold.py", wordsHold)
	dir, id, ended, out := startWordsRun(t, s, python, "hold.py")
	awaitFile(t, filepath.Join(s.f.out, "ready"), ended, out)
	if liveblock.TakesWords(dir) || !liveblock.TakesLink(dir) {
		t.Fatalf("the older launcher's marks: words %v (want false), link %v (want true: it is a launcher that makes marks)", liveblock.TakesWords(dir), liveblock.TakesLink(dir))
	}
	// A program block, which the older launcher reads: the live blocks it holds when the forced file comes.
	updateOverlay(t, dir, id, func(o *liveblock.Overlay) error {
		_, _, err := o.Add(liveblock.KindExec, "curl", "uid:0 pid:1 cli", time.Now())
		return err
	})
	awaitGap(t, dir, record.GapLiveBlockAdded, 1, ended)
	cur := *s
	cur.bin = bin
	cmd := cur.tego(t, "block", id, "exec", "git push")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if code := exitCodeOf(t, err); code != 1 || !strings.Contains(stderr.String(), "[launcher-too-old]") ||
		!strings.Contains(stderr.String(), "does not say it reads a block on a command's words") {
		t.Fatalf("tego block on the older launcher's run: exit %d, stderr %q; want exit 1, [launcher-too-old] and its words", code, stderr.String())
	}
	if o, err := liveblock.Read(dir, id); err != nil || o.V >= liveblock.VersionWords || len(o.Blocks) != 1 {
		t.Fatalf("overlay after the refused block: %+v, %v; want the version 1 file with the one program block", o, err)
	}
	// The file the writer refused to write, written anyway: the older launcher refuses it whole by its version.
	updateOverlay(t, dir, id, func(o *liveblock.Overlay) error {
		_, _, err := o.Add(liveblock.KindExec, "git push", "uid:0 pid:1 cli", time.Now())
		return err
	})
	if o, err := liveblock.Read(dir, id); err != nil || o.V != liveblock.VersionWords {
		t.Fatalf("the forced overlay: %+v, %v; want version %d", o, err, liveblock.VersionWords)
	}
	awaitGap(t, dir, record.GapLiveBlockUnreadable, 1, ended)
	select {
	case err := <-ended:
		t.Fatalf("the older launcher ended the run on a file it cannot read: %v\n%s", err, out.String())
	default:
	}
	if err := os.WriteFile(filepath.Join(s.f.out, "stop"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-ended:
		if code := exitCodeOf(t, err); code != 0 {
			t.Fatalf("the older tego's run exited %d:\n%s", code, out.String())
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("the older tego's run did not end:\n%s", out.String())
	}
	// The gap's words are in its payload, which an event does not marshal (its Payload is json:"-"): read them by
	// decoding, as awaitGap's raw file read finds them.
	unreadable := 0
	for _, e := range events(t, dir) {
		var p record.GapPayload
		if e.Kind == record.KindGap && e.DecodePayload(&p) == nil && p.Why == record.GapLiveBlockUnreadable {
			unreadable++
		}
	}
	if unreadable == 0 {
		t.Error("the run's record has no live-block-unreadable line")
	}
}
