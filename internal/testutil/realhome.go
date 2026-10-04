// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/realtego"
)

// RealTegoDirs are the ~/.tego directories of the accounts a test process could reach through the passwd
// database: the effective uid's and, under sudo, SUDO_UID's, and $HOME/.tego as $HOME is at the call when one of
// them has no passwd home, where tego then keeps its files (internal/realtego, which the test build of tego
// shares). GuardRealTego takes them before the tests run, so a t.Setenv of HOME moves nothing it watches.
func RealTegoDirs() []string { return realtego.Dirs() }

// RealRuntimeDirs are the runtime parents a test process could reach (internal/realtego RuntimeDirs):
// /run/user/<uid>/tego for the effective uid and SUDO_UID, and <XDG_RUNTIME_DIR>/tego for the XDG_RUNTIME_DIR the
// binary started with, before any TestMain pointed it at the tests' own directory (PrivateRuntimeDir).
func RealRuntimeDirs() []string { return realtego.RuntimeDirs() }

// UnderRealTego reports whether path is one of RealTegoDirs or inside one.
func UnderRealTego(path string) bool { return realtego.UnderReal(path) }

// shellHistory is the history file bash saves an interactive shell's commands to when it exits, under the home
// HISTFILE is not set to /dev/null in: a shell a harness starts on a pseudo-terminal or with -i (tools/isocheck
// SH-2, SH-3) appends there.
const shellHistory = ".bash_history"

// RealShellHistories are the ~/.bash_history files beside RealTegoDirs: the same homes, found through the passwd
// database, and $HOME only where RealTegoDirs falls back to it.
func RealShellHistories() []string {
	var files []string
	for _, d := range RealTegoDirs() {
		files = append(files, filepath.Join(filepath.Dir(d), shellHistory))
	}
	return files
}

// entryState is what GuardRealTego compares of one directory entry: its own mode, size and mtime and, for a
// symbolic link, what it names and its target's (a ~/.bash_history that a dotfiles manager links elsewhere is
// written through the link, which keeps the link's own state).
type entryState struct {
	mode  fs.FileMode
	size  int64
	mtime int64 // UnixNano
	link  string
	to    fileState // the link's target; zero for an entry that is not a link, or a dangling one
}

// fileState is the mode, size and mtime of the file a symbolic link names.
type fileState struct {
	mode  fs.FileMode
	size  int64
	mtime int64 // UnixNano
}

// snapshotTego records every directory in dirs, its entries, the entries of its runs/ (the built-in ledger
// root) and the entries of each directory there (a run's events.jsonl, contract, lock and blobs/), the entries of its
// gov/ and gov/blobs/ (the governance ledger's segments, lock and blobs), and every file
// in files: name, mode, size and mtime, and for a symbolic link what it names and its target's mode, size and mtime.
// A path that does not exist is recorded as absent.
func snapshotTego(dirs, files []string) map[string]entryState {
	snap := map[string]entryState{}
	record := func(p string) {
		st, err := os.Lstat(p)
		if err != nil {
			return
		}
		e := entryState{mode: st.Mode(), size: st.Size(), mtime: st.ModTime().UnixNano()}
		if st.Mode()&fs.ModeSymlink != 0 {
			e.link, _ = os.Readlink(p)
			if to, err := os.Stat(p); err == nil {
				e.to = fileState{mode: to.Mode(), size: to.Size(), mtime: to.ModTime().UnixNano()}
			}
		}
		snap[p] = e
	}
	// list records dir's entries and returns the directories among them (not followed through a symbolic link).
	list := func(dir string) []string {
		ents, err := os.ReadDir(dir)
		if err != nil {
			return nil
		}
		var subdirs []string
		for _, e := range ents {
			p := filepath.Join(dir, e.Name())
			record(p)
			if e.IsDir() {
				subdirs = append(subdirs, p)
			}
		}
		return subdirs
	}
	for _, d := range dirs {
		record(d)
		list(d)
		runs := filepath.Join(d, "runs")
		record(runs)
		for _, run := range list(runs) {
			list(run)
		}
		// The governance ledger (ADR 0100 (5)): its segments, lock and blobs/, and each blob.
		gov := filepath.Join(d, "gov")
		list(gov)
		list(filepath.Join(gov, "blobs"))
	}
	for _, f := range files {
		record(f)
	}
	return snap
}

// GuardRealTego records the invoking user's real ~/.tego (RealTegoDirs) and ~/.bash_history
// (RealShellHistories) and returns a check that reports what changed there since: an entry made, removed or
// written, the chain anchor and the own log included. Every package whose tests start a run, a sweep, a gc, a
// reaper or the tego binary, in-process or as a subprocess, runs its tests through GuardedMain or
// GuardedLeakCheckMain, which take the snapshot before the tests and fail the binary on the check's error after
// them (tools/isocheck GO-4), so a test that reaches the developer's own ledger root, anchor, log or shell history
// is caught the run it does, not when they next read their tego.log. It watches the directory, runs/ and each run
// directory's own entries (a new ~/.tego, a changed chain.log or tego.log, a new or removed run directory, an
// events.jsonl appended to or chmodded in place, a governance segment appended to, a governance blob made) and the
// history file, through a symbolic link too (the link and
// its target).
//
// Out of its reach: a write inside a run's blobs/, which is watched as one entry, that keeps that directory's
// mtime; a write by a process the tests left running that happens after the check, when the tests have
// returned (a subprocess a test started and never waited for, or one reparented when its parent exited); and, in
// a binary that runs its tests in its own process (one not started as go test starts it, see GuardedMain), a
// write by tests that then end the process from inside m.Run: a panic, the -test.timeout alarm, an os.Exit or a
// fatal signal, after which no check runs. The test build's refusal of the real ~/.tego (identity-config.md
// R27) is what keeps such a process of tego out.
//
// It records the runtime parents (RealRuntimeDirs) too, where a run keeps its CODEX_HOME and last-refusal mirror
// and where every launch sweeps the directories of runs whose launcher is gone: a test run that inherited the
// developer's XDG_RUNTIME_DIR made the parent, left a directory there or removed one of theirs. It reports a parent
// made, removed or replaced, a directory made there whose run's lock is not held at the check, and a directory
// whose run's lock was free at the snapshot (a crashed run's) gone at the check: what a sweep removes. A directory
// whose lock is held is a live run, the developer's, and is never reported, nor is the parent's own mtime, which
// each of their runs changes (identity-config.md R27 clause b4).
//
// A tego the developer runs by hand while the tests run changes the same files and is reported as well, and
// so does a shell of theirs that saves its history meanwhile; the message says to rerun.
func GuardRealTego() func() error {
	dirs, files := guardPaths()
	home, run := guardTego(dirs, files), guardRuntime(guardRuntimeParents())
	return func() error { return errors.Join(home(), run()) }
}

// GuardedMain runs a package's tests (m.Run) under GuardRealTego and returns the code its TestMain exits with:
// the tests' own, or non-zero, with the guard's FAIL line on stderr, when the invoking user's real ~/.tego or
// ~/.bash_history changed while they ran. A package whose tests can start a run, a sweep, a gc, a reaper or the
// tego binary ends its TestMain with os.Exit(testutil.GuardedMain(m)), or holds the code in a name that os.Exit
// takes after its cleanup (tools/isocheck GO-4 holds that shape and no other).
//
// Started as go test starts a test binary (with -test.paniconexit0, which go test always passes and a test's
// re-exec of its own binary as a helper does not), the binary takes the snapshot, runs the tests in a child (the
// same executable, the arguments and environment the binary started with and its descriptors, with
// TEGO_TESTUTIL_GUARD_PARENT naming this process) and checks after the child ended, however it ended: a panic,
// the -test.timeout alarm, an os.Exit, a signal. It forwards SIGINT, SIGTERM, SIGHUP and SIGQUIT (go test's signal
// to a test that outlived its -timeout) to the child, which dies with it (PR_SET_PDEATHSIG), and exits with the
// child's code, 128 plus the signal's number for a child a signal ended. The child runs the tests and nothing else:
// the variable is honoured only when it names the child's own parent and that parent runs the same executable, so
// set by mistake it weakens nothing, and it is removed before the tests run, so their own re-execs of the binary
// guard themselves. Any other start (a helper's re-exec, a binary run by hand or by test/vm/root-suites.sh, the
// variable set by mistake, a child that cannot be started) runs the tests in this process between the snapshot and
// the check.
func GuardedMain(m *testing.M) int {
	switch guardRole {
	case roleGuardedChild:
		return m.Run()
	case roleGuardParent:
		return guardedRun(func() int {
			code, err := runGuardedChild(os.Stderr)
			if err == nil {
				return code
			}
			_, _ = fmt.Fprintf(os.Stderr, "testutil: the guard runs the tests in its own process, so a panic or the "+
				"test timeout ends them before its check (starting them in a child: %v)\n", err)
			return m.Run()
		}, os.Stderr)
	case roleInProcess:
	}
	return guardedRun(m.Run, os.Stderr)
}

// guardParentEnv names, in the environment of the child GuardedMain runs the tests in, the pid of the process that
// took the snapshot and checks after the child ends.
const guardParentEnv = "TEGO_TESTUTIL_GUARD_PARENT"

// role is what GuardedMain does in this process.
type role int

const (
	roleInProcess    role = iota // snapshot, m.Run, check, in this process
	roleGuardParent              // snapshot, the tests in a child, check
	roleGuardedChild             // m.Run only: the parent checks
)

// startArgs, startEnv and guardRole are taken when this package is initialized, before any TestMain can change
// the arguments or the environment: the child is started as the binary was.
var startArgs, startEnv, guardRole = startState()

// startState removes guardParentEnv from the environment (the tests' own re-execs of the binary never inherit it)
// and decides the role: a guarded child when the variable names this process's parent and that parent runs the
// same executable; a guard parent when the binary was started as go test starts it and the variable was not set; in
// process otherwise, the variable set by mistake included (never a parent then: that could only re-execute again).
func startState() ([]string, []string, role) {
	v, set := os.LookupEnv(guardParentEnv)
	if set {
		_ = os.Unsetenv(guardParentEnv)
	}
	args, env := slices.Clone(os.Args), os.Environ()
	switch {
	case set && isGuardParent(v):
		return args, env, roleGuardedChild
	case !set && len(args) > 1 && startedByGoTest(args[1:]):
		return args, env, roleGuardParent
	}
	return args, env, roleInProcess
}

// startedByGoTest reports whether args hold -test.paniconexit0 (true), which go test gives every test binary it
// starts, and not -test.fuzzworker, which marks a fuzzing worker that a guarded binary started.
func startedByGoTest(args []string) bool {
	flag := func(name string) bool {
		for _, a := range args {
			if a == "--" {
				break
			}
			n, v, hasValue := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-"), "=")
			if !strings.HasPrefix(a, "-") || n != name {
				continue
			}
			if !hasValue {
				return true
			}
			b, err := strconv.ParseBool(v)
			return err == nil && b
		}
		return false
	}
	return flag("test.paniconexit0") && !flag("test.fuzzworker")
}

// GuardedLeakCheckMain is GuardedMain followed by LeakCheckMain's goroutine check: the binary also fails on a
// goroutine the tests leaked. It runs
// GuardedMain itself, so this package's own TestMain, which exits with its code, exercises both helpers
// (TestGuardedMainsFailTheBinary).
func GuardedLeakCheckMain(m *testing.M) int {
	return leakCheckAfter(func() int { return GuardedMain(m) })
}

// guardedRun takes GuardRealTego's snapshot, runs the tests and returns their code, or 1 (theirs when it is already
// non-zero) when the check reports a change, which it writes to stderr.
func guardedRun(run func() int, stderr io.Writer) int {
	check := GuardRealTego()
	code := run()
	if err := check(); err != nil {
		_, _ = fmt.Fprintf(stderr, "FAIL: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

// guardPaths names the directories and files GuardRealTego watches: RealTegoDirs and RealShellHistories. Only
// this package's own tests replace it, to show the guard reads what it names (never an environment variable, which a
// harness could set by mistake: identity-config.md R27 (b3)).
var guardPaths = func() (dirs, files []string) { return RealTegoDirs(), RealShellHistories() }

// guardTego is GuardRealTego over the given ~/.tego directories and history files.
func guardTego(dirs, files []string) func() error {
	before := snapshotTego(dirs, files)
	return func() error {
		after := snapshotTego(dirs, files)
		var changed []string
		for p, a := range after {
			if b, ok := before[p]; !ok {
				changed = append(changed, p+" (made)")
			} else if a != b {
				changed = append(changed, p+" (written)")
			}
		}
		for p := range before {
			if _, ok := after[p]; !ok {
				changed = append(changed, p+" (removed)")
			}
		}
		if len(changed) == 0 {
			return nil
		}
		slices.Sort(changed)
		return fmt.Errorf("these tests touched the invoking user's real ~/.tego or ~/.bash_history (a tego run by "+
			"hand meanwhile does too, and so does a shell of theirs that saved its history; rerun to tell): %s",
			strings.Join(changed, ", "))
	}
}
