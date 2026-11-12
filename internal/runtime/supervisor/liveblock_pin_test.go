// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// pinContract is a run's compiled contract under exec.allow paths, resolved now as New resolves it when the run
// starts (resolveExecEntries): a path ending in "/" is a folder entry.
func pinContract(paths ...string) *compiled {
	pol := testPolicy(nil, nil, nil)
	for _, p := range paths {
		r := agent.ExecRule{Raw: p, Path: p, Basename: filepath.Base(p), Source: agent.ExecSourceAllow}
		if p[len(p)-1] == '/' {
			r.IsDir, r.Basename = true, ""
		}
		pol.Rules.Exec = append(pol.Rules.Exec, r)
	}
	l := &Loop{k: sysKernel{}}
	return l.resolveExecEntries(&compiled{pol: pol})
}

// pinDecide is an exec's decision as handleExec makes it, the contract's floor and then the live blocks set holds:
// spelled is the pathname the task passed ("" runs the descriptor itself, /proc/self/fd/N), open what the walk opens.
func pinDecide(t *testing.T, c *compiled, set *liveblock.Set, spelled, open string) execDecision {
	t.Helper()
	fd, err := unix.Open(open, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd) //nolint:errcheck // a test descriptor
	img, err := describeImage(fd)
	if err != nil {
		t.Fatal(err)
	}
	name := spelled
	if spelled == "" {
		name = "/proc/self/fd/" + strconv.Itoa(fd)
	}
	c.live = func() *liveblock.Set { return set }
	d := c.decideExec(name, name, img, nil, ruleUnmatched)
	return c.liveExec(d, name, []string{name, name, name, img.link}, img, true, ruleUnmatched)
}

// placeLink is the Set of a run's overlay holding the block "Also apply now" places when value leaves exec.allow.
func placeLink(t *testing.T, value string) *liveblock.Set {
	t.Helper()
	o := liveblock.New("r-test")
	if _, _, err := o.AddLink(liveblock.KindExec, value, "uid:1 pid:2 dashboard", time.Now()); err != nil {
		t.Fatal(err)
	}
	return linkSet(t, o)
}

// repoint makes the symbolic link at name lead to target, as an agent that writes the folder can at any time.
func repoint(t *testing.T, name, target string) {
	t.Helper()
	if err := os.Remove(name); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Symlink(target, name); err != nil {
		t.Fatal(err)
	}
}

// TestLiveLinkBlockKeepsToTheRunsOwnGrant: the block "Also apply now" places refuses what the running contract grants
// under the removed entry, which is fixed when the run starts (the file and the path its value resolved to then),
// whatever the value leads to when the block is placed. An agent that writes a folder an exec.allow entry passes
// through can repoint a link there during the run; the block must still refuse every exec the next run's contract
// refuses and the running one allowed under that entry: by its name, by its descriptor, and by the name the entry
// leads to now. Each case compares the running contract with the block against the next run's contract alone.
func TestLiveLinkBlockKeepsToTheRunsOwnGrant(t *testing.T) {
	type exec struct{ name, spelled, open string }
	check := func(t *testing.T, running, next *compiled, set *liveblock.Set, value string, execs []exec) {
		t.Helper()
		for _, x := range execs {
			want := pinDecide(t, next, nil, x.spelled, x.open)
			got := pinDecide(t, running, set, x.spelled, x.open)
			if got.verdict != want.verdict {
				t.Errorf("%s: with the block %s (%s); the next run's contract %s (%s)", x.name, got.verdict, got.rule, want.verdict, want.rule)
			}
			alone := pinDecide(t, running, nil, x.spelled, x.open)
			if alone.verdict != record.VerdictRefused && got.verdict == record.VerdictRefused && got.rule != "live.block[exec:"+value+"]" {
				t.Errorf("%s: refused under %s, want the block's rule", x.name, got.rule)
			}
		}
	}

	t.Run("an entry repointed at another name of the same file", func(t *testing.T) {
		m := newLinkLayout(t)
		tool := filepath.Join(m.w, "tool")
		repoint(t, tool, m.ls)
		running := pinContract(tool, m.sleep) // tool led to ls when the run started
		repoint(t, tool, m.sleep)             // the agent points it at sleep before the change
		next := pinContract(m.sleep)
		check(t, running, next, placeLink(t, tool), tool, []exec{
			{"ls by its name", m.ls, m.ls},
			{"/proc/self/fd/N of ls", "", m.ls},
			{"the entry by its name, now sleep", tool, tool},
			{"sleep by its name", m.sleep, m.sleep},
		})
	})
	t.Run("an entry repointed at another file", func(t *testing.T) {
		m := newLinkLayout(t)
		other := filepath.Join(m.w, "other")
		if err := os.WriteFile(other, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // an executable fixture
			t.Fatal(err)
		}
		tool := filepath.Join(m.w, "tool")
		repoint(t, tool, m.ls)
		running := pinContract(tool, m.sleep)
		repoint(t, tool, other)
		next := pinContract(m.sleep)
		check(t, running, next, placeLink(t, tool), tool, []exec{
			{"ls by its name", m.ls, m.ls},
			{"the entry by its name, now another file", tool, tool},
			{"sleep by its name", m.sleep, m.sleep},
		})
	})
	t.Run("a folder in the entry's path repointed", func(t *testing.T) {
		m := newLinkLayout(t)
		d1, d2 := filepath.Join(m.w, "d1"), filepath.Join(m.w, "d2")
		for _, d := range []string{d1, d2} {
			if err := os.Mkdir(d, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(m.box, filepath.Join(d, "ls")); err != nil {
				t.Fatal(err)
			}
		}
		bin := filepath.Join(m.w, "bin")
		repoint(t, bin, d1)
		value := filepath.Join(bin, "ls")
		running := pinContract(value, m.sleep)
		repoint(t, bin, d2)
		next := pinContract(m.sleep)
		check(t, running, next, placeLink(t, value), value, []exec{
			{"d1/ls, where the entry led when the run started", filepath.Join(d1, "ls"), filepath.Join(d1, "ls")},
			{"/proc/self/fd/N of d1/ls", "", filepath.Join(d1, "ls")},
			{"the entry by its name, now d2/ls", value, value},
			{"sleep by its name", m.sleep, m.sleep},
		})
	})
}

// TestLiveLinkBlockOnNamesOfOnePath: where two exec.allow entries lead to one file at one path (busybox's applets,
// each a symbolic link to /bin/busybox; /bin/ls beside /usr/bin/ls on a merged /usr), the contract grants that file
// there under both, and the block on one of them refuses what that entry grants: the file at that path, under every
// name that reaches it there, the kept entry's too. The next run's contract would run it under the kept entry; the
// running one cannot tell a kept entry from one removed without a block, so it refuses, fail closed, as the whole-file
// block did. A hard link of the file elsewhere (another path) is the contract's, as before.
func TestLiveLinkBlockOnNamesOfOnePath(t *testing.T) {
	m := newLinkLayout(t)
	bbLs, bbSleep := filepath.Join(m.w, "bb-ls"), filepath.Join(m.w, "bb-sleep")
	repoint(t, bbLs, m.box)
	repoint(t, bbSleep, m.box)
	running := pinContract(bbLs, bbSleep, m.sleep)
	set := placeLink(t, bbLs)
	for _, x := range []struct {
		name, spelled, open string
		refused             bool
	}{
		{"the removed name", bbLs, bbLs, true},
		{"the kept name of the same path", bbSleep, bbSleep, true},
		{"/proc/self/fd/N of the file at that path", "", m.box, true},
		{"another hard link of the file, granted by its own entry", m.sleep, m.sleep, false},
	} {
		got := pinDecide(t, running, set, x.spelled, x.open)
		if refused := got.verdict == record.VerdictRefused; refused != x.refused {
			t.Errorf("%s: %s (%s), want refused %v", x.name, got.verdict, got.rule, x.refused)
		}
	}
}
