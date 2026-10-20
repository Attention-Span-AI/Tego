// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/realtego"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// initialLogindRoot is logindRuntimeRoot as a product build holds it, taken before any test points it elsewhere
// (fakeLogind).
var initialLogindRoot = logindRuntimeRoot

// TestTheTestGuardNamesTheRuntimeParentsAsARunDoes: internal/realtego spells the runtime parent's names for the test
// guard (testutil.GuardRealTego), since a product package imports nothing of it: the directory under an
// XDG_RUNTIME_DIR, the lock file the sweep tests, the prefix of a directory made and not yet locked, and the logind
// root are this package's own (identity-config.md R27 clause b4).
func TestTheTestGuardNamesTheRuntimeParentsAsARunDoes(t *testing.T) {
	for _, c := range [][2]string{
		{realtego.RuntimeDirName, agent.RuntimeDirName},
		{realtego.RuntimeLockFile, runtimeLockFile},
		{realtego.RuntimeDirPending, runtimeDirPending},
		{realtego.LogindRoot, initialLogindRoot},
	} {
		if c[0] != c[1] {
			t.Errorf("internal/realtego names %q where a run uses %q", c[0], c[1])
		}
	}
}

// TestTheGuardsSweepableEntriesAreWhatASweepRemoves: the test guard reports an entry gone from a watched runtime
// parent only where a launch's sweep would have removed it (testutil.SweepableRuntimeEntries). Over every shape of
// entry the guard tells apart (a dead run's directory, a live run's, a launch's pending one, one with no lock file,
// a linked lock, one others can write, a file, a link, a name that is not a run id), that set is exactly the one
// sweepRuntimeParent removes, so the guard's predicate cannot drift from the sweep's (identity-config.md R27 clause
// b4).
func TestTheGuardsSweepableEntriesAreWhatASweepRemoves(t *testing.T) {
	p := filepath.Join(t.TempDir(), agent.RuntimeDirName)
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, shape := range testutil.RuntimeEntryShapes {
		testutil.PlantRuntimeEntry(t, p, shape)
	}
	want := testutil.SweepableRuntimeEntries(p)
	if len(want) == 0 {
		t.Fatal("the guard counts no planted entry as sweepable; the shapes lost the dead run's directory")
	}
	names := func() map[string]bool {
		ents, err := os.ReadDir(p)
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]bool{}
		for _, e := range ents {
			m[e.Name()] = true
		}
		return m
	}
	before := names()
	sweepRuntimeParent(p, slog.New(slog.DiscardHandler))
	after := names()
	var gone []string
	for n := range before {
		if !after[n] {
			gone = append(gone, n)
		}
	}
	slices.Sort(gone)
	slices.Sort(want)
	if !slices.Equal(gone, want) {
		t.Errorf("a sweep removed %v; the guard counts %v as what a sweep removes", gone, want)
	}
}

// runtimeDirHolderArg makes the test binary a launcher that holds a run's runtime directory: it makes the
// directory as a run does (createRuntimeDir), writes a key where Codex keeps it, says where, and waits to be killed.
const runtimeDirHolderArg = "__tego_test_runtime_dir_holder"

// runtimeDirHolderHelper is TestMain's hook for runtimeDirHolderArg; it returns at once for any other argv.
func runtimeDirHolderHelper() {
	if len(os.Args) != 3 || os.Args[1] != runtimeDirHolderArg {
		return
	}
	r := codexRunner(&agent.RuleTable{})
	r.id = identity.RunID(os.Args[2])
	if err := r.createRuntimeDir(); err != nil {
		fmt.Fprintf(os.Stderr, "createRuntimeDir: %v\n", err)
		os.Exit(9)
	}
	if err := os.WriteFile(filepath.Join(r.runtimeDir, codexHomeName, "auth.json"), []byte(`{"OPENAI_API_KEY":"sk-typed"}`), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "auth.json: %v\n", err)
		os.Exit(9)
	}
	fmt.Println("ready", r.runtimeDir)
	for {
		time.Sleep(time.Hour) // until the test kills it
	}
}

// startRuntimeDirHolder starts a launcher holding run id's runtime directory under the test's XDG_RUNTIME_DIR and
// returns it with that directory.
func startRuntimeDirHolder(t *testing.T, id string) (*exec.Cmd, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], runtimeDirHolderArg, id)
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line, err := bufio.NewReader(out).ReadString('\n')
	dir, ok := strings.CutPrefix(strings.TrimSpace(line), "ready ")
	if err != nil || !ok {
		t.Fatalf("holder %s: %q %v", id, line, err)
	}
	return cmd, dir
}

// TestAKilledLaunchersRuntimeDirIsRemovedByTheNextLaunch: a launcher killed before its shutdown
// left the run's directory under $XDG_RUNTIME_DIR/tego, its CODEX_HOME with the typed key in auth.json included,
// until logout, and nothing removed it. A run's launcher now holds a lock in its directory for the run's life, and
// the next launch under the same parent removes each run's directory whose lock nobody holds. A live run's directory
// stays, as do a directory with no lock (an older tego's, which says nothing about whether its run is live), a
// directory being made (its .new- name is no run id) and a link, which is never followed.
func TestAKilledLaunchersRuntimeDirIsRemovedByTheNextLaunch(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root launcher makes no runtime directory")
	}
	xdg := privateTempDir(t)
	t.Setenv("XDG_RUNTIME_DIR", xdg)
	parent := filepath.Join(xdg, agent.RuntimeDirName)
	const killed, live, next = "r-00000000-000000000000k-kkkkkk", "r-00000000-000000000000l-llllll", "r-00000000-000000000000n-nnnnnn"
	k, killedDir := startRuntimeDirHolder(t, killed)
	_, liveDir := startRuntimeDirHolder(t, live)
	if err := k.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = k.Wait()
	if _, err := os.Stat(filepath.Join(killedDir, codexHomeName, "auth.json")); err != nil {
		t.Fatalf("the killed launcher's auth.json: %v, want it left behind until a sweep", err)
	}
	lockless := filepath.Join(parent, "r-00000000-000000000000o-oooooo")
	making := filepath.Join(parent, ".new-r-00000000-000000000000m-mmmmmm")
	elsewhere := t.TempDir()
	link := filepath.Join(parent, "r-00000000-000000000000s-ssssss")
	for _, d := range []string{lockless, making} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(elsewhere, runtimeLockFile), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Fatal(err)
	}

	r := codexRunner(&agent.RuleTable{})
	r.id = next
	if err := r.createRuntimeDir(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.closeRuntimeLock)
	if _, err := os.Lstat(killedDir); !os.IsNotExist(err) {
		t.Errorf("the killed launcher's directory %s: %v, want it removed by the next launch", killedDir, err)
	}
	for _, d := range []string{liveDir, lockless, making, link, filepath.Join(elsewhere, runtimeLockFile), r.runtimeDir} {
		if _, err := os.Lstat(d); err != nil {
			t.Errorf("%s: %v, want it kept", d, err)
		}
	}
	if r.runtimeDir != filepath.Join(parent, next) {
		t.Errorf("runtime dir %q, want %s", r.runtimeDir, filepath.Join(parent, next))
	}
	// The new run's own directory is locked for its life, so a launch beside it leaves it alone.
	r2 := codexRunner(&agent.RuleTable{})
	r2.id = "r-00000000-000000000000p-pppppp"
	if err := r2.createRuntimeDir(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r2.closeRuntimeLock)
	if _, err := os.Lstat(r.runtimeDir); err != nil {
		t.Errorf("a live run's directory after a launch beside it: %v", err)
	}
	if _, err := os.Lstat(making); err != nil {
		t.Errorf("%s: %v", making, err)
	}
	if ents, _ := os.ReadDir(parent); len(ents) != 6 {
		t.Errorf("%d entries under %s, want 6", len(ents), parent)
	}
}
