// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// modeDenyWrite runs the target under a write entry on the harness directory whose built-in deny_write set
// names .git/hooks and .git/config inside it (R15c); modeDenyWriteOff is the same under record: off.
const (
	modeDenyWrite    = "denywrite"
	modeDenyWriteOff = "denywrite-off"
)

// denyWriteRuleTable is the harness's rule table for the deny_write modes. The targets are made by the
// parent before the target starts (denyWritePrepare), since creating them under the filter is itself a
// modification of a target.
func denyWriteRuleTable(dir, mode string) *agent.RuleTable {
	target := func(p string) agent.FSRule {
		return agent.FSRule{Path: p, Kind: agent.FSDenyWrite, BuiltIn: true, Unenforced: true, Resolved: p}
	}
	rt := &agent.RuleTable{
		FS:        []agent.FSRule{{Path: dir, Kind: agent.FSWrite, Resolved: dir}},
		DenyWrite: []agent.FSRule{target(filepath.Join(dir, ".git/hooks")), target(filepath.Join(dir, ".git/config"))},
		Record:    agent.RecordSummary, Tier: backend.TierLandlock, Contract: &agent.Contract{},
	}
	if mode == modeDenyWriteOff {
		rt.Record = agent.RecordOff
	}
	return rt
}

// denyWritePrepare makes the worktree's .git/hooks and .git/config.
func denyWritePrepare(t *testing.T) func(dir string) {
	return func(dir string) {
		if err := os.MkdirAll(filepath.Join(dir, ".git/hooks"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".git/config"), []byte("[core]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// denyWriteChecks are the target's ways into the deny_write set: an O_TMPFILE written in the worktree and
// linked into the hooks directory by descriptor (linkat's AT_EMPTY_PATH form) and through its /proc link, a
// second name for the git config by descriptor, a hook written directly, the git config opened for writing through a
// symlink whose body passes through the target's own /proc/self/task/<pid>, and a regular file and a FIFO made
// as hooks by mknod(2). Then two writes that reach no
// target: an ordinary file, and an O_TMPFILE linked into the worktree by descriptor. Last, a hook and an
// ordinary file written after the target made itself non-dumpable, which denies an unprivileged supervisor
// every read of its memory.
func denyWriteChecks() []checkResult {
	dir := os.Getenv(helperDir)
	var out []checkResult
	add := func(name string, err error) {
		out = append(out, checkResult{Name: name, Err: errText(err)})
	}
	tmpfile := func() (int, error) {
		fd, err := unix.Open(dir, unix.O_TMPFILE|unix.O_WRONLY|unix.O_CLOEXEC, 0o755)
		if err == nil {
			_, err = unix.Write(fd, []byte("#!/bin/sh\necho owned\n"))
		}
		return fd, err
	}
	hook := filepath.Join(dir, ".git/hooks")

	fd, err := tmpfile()
	perr := err
	if err == nil {
		err = unix.Linkat(fd, "", unix.AT_FDCWD, filepath.Join(hook, "pre-commit"), unix.AT_EMPTY_PATH)
		// The /proc route to the same file, which needs no capability on any kernel.
		perr = unix.Linkat(unix.AT_FDCWD, "/proc/self/fd/"+strconv.Itoa(fd), unix.AT_FDCWD,
			filepath.Join(hook, "pre-push"), unix.AT_SYMLINK_FOLLOW)
		_ = unix.Close(fd)
	}
	add("tmpfile_link_empty_path", err)
	add("tmpfile_link_proc_fd", perr)

	fd, err = unix.Open(filepath.Join(dir, ".git/config"), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err == nil {
		err = unix.Linkat(fd, "", unix.AT_FDCWD, filepath.Join(dir, "cfg"), unix.AT_EMPTY_PATH)
		_ = unix.Close(fd)
	}
	add("config_link_empty_path", err)

	fd, err = unix.Open(filepath.Join(hook, "post-checkout"), unix.O_WRONLY|unix.O_CREAT|unix.O_CLOEXEC, 0o755)
	if err == nil {
		_ = unix.Close(fd)
	}
	add("hook_write", err)

	// The git config opened for writing, with no O_CREAT, through a symlink whose body goes through procfs's "self" to
	// this process's own task directory and climbs back out to it. The supervisor's one-call lookup reads "self" as the
	// supervisor and misses (this pid is no thread of its own); it answered the link's own name, which no deny_write
	// names, and the kernel opened the config for the target.
	self := filepath.Join(dir, "cfg-self")
	add("config_self_link", unix.Symlink("/proc/self/task/"+strconv.Itoa(os.Getpid())+"/../../../.."+filepath.Join(dir, ".git/config"), self))
	fd, err = unix.Open(self, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err == nil {
		_ = unix.Close(fd)
	}
	add("config_write_through_proc_self", err)

	// mknod(2) makes a name without an open: an empty executable hook, and a FIFO a later git hook run would
	// block on. Landlock grants MAKE_REG and MAKE_FIFO over the write entry, so only the loop can refuse them.
	add("hook_mknod_reg", unix.Mknod(filepath.Join(hook, "pre-rebase"), unix.S_IFREG|0o755, 0))
	add("hook_mknod_fifo", unix.Mknod(filepath.Join(hook, "pre-applypatch"), unix.S_IFIFO|0o644, 0))

	fd, err = unix.Open(filepath.Join(dir, "main.go"), unix.O_WRONLY|unix.O_CREAT|unix.O_CLOEXEC, 0o644)
	if err == nil {
		_ = unix.Close(fd)
	}
	add("ordinary_write", err)

	fd, err = tmpfile()
	if err == nil {
		err = unix.Linkat(fd, "", unix.AT_FDCWD, filepath.Join(dir, "out.bin"), unix.AT_EMPTY_PATH)
		_ = unix.Close(fd)
	}
	add("ordinary_tmpfile_link", err)

	// Last, because it holds for the whole process until it is undone: process_vm_readv's ptrace check
	// refuses a non-dumpable target to a reader without CAP_SYS_PTRACE, so no pathname passed now can be
	// read by an unprivileged supervisor, and before R15c failed closed on that the hook write went through.
	err = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
	add("undumpable", err)
	if err == nil {
		fd, err = unix.Open(filepath.Join(hook, "post-merge"), unix.O_WRONLY|unix.O_CREAT|unix.O_CLOEXEC, 0o755)
		if err == nil {
			_ = unix.Close(fd)
		}
		add("undumpable_hook_write", err)
		fd, err = unix.Open(filepath.Join(dir, "undumpable.txt"), unix.O_WRONLY|unix.O_CREAT|unix.O_CLOEXEC, 0o644)
		if err == nil {
			_ = unix.Close(fd)
		}
		add("undumpable_ordinary_write", err)
		_ = unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0)
	}
	return out
}

// isCoverData reports whether name is a file a -cover build of the target writes as it exits: its counters
// and metadata, in the GOCOVERDIR it inherits from this test binary. Those writes are the instrumentation's,
// outside the harness's write entry, so the supervisor refuses them like any other write there; under
// scripts/coverage.sh they read as unexpected refusals. An uninstrumented target
// writes nothing there, so the exception is off unless this binary was built with -cover.
func isCoverData(name string) bool {
	dir := os.Getenv("GOCOVERDIR")
	if testing.CoverMode() == "" || dir == "" || name == "" {
		return false
	}
	return strings.HasPrefix(filepath.Clean(name), filepath.Clean(dir)+string(filepath.Separator))
}

// TestIntegrationDenyWrite is R15c on a real kernel, under record: summary and record: off: every way into
// the deny_write set is answered with R10's errno and recorded refused under the target's rule, the
// AT_EMPTY_PATH links included, and nothing lands in the hooks directory. Before the old end of linkat was
// read from its descriptor, the O_TMPFILE link was refused on its new name but recorded observed under
// args-unreadable, and under record: off not recorded at all. A non-dumpable target's hook write is refused
// too: under the target's rule where this process may read its memory (root, CAP_SYS_PTRACE), and under
// args-unreadable where it may not, with its ordinary write refused beside it — the fail-closed cost.
func TestIntegrationDenyWrite(t *testing.T) {
	for _, mode := range []string{modeDenyWrite, modeDenyWriteOff} {
		t.Run(mode, func(t *testing.T) {
			h := startHarnessWith(t, harnessOpts{mode: mode, prepare: denyWritePrepare(t)})
			h.stop(t)
			for _, name := range []string{"tmpfile_link_empty_path", "tmpfile_link_proc_fd", "config_link_empty_path", "hook_write",
				"config_write_through_proc_self", "hook_mknod_reg", "hook_mknod_fifo"} {
				if c := h.check(t, name); !isErrno(c.Err, refusalErrno) {
					t.Errorf("%s = %+v, want R10's errno", name, c)
				}
			}
			if c := h.check(t, "ordinary_write"); c.Err != "" {
				t.Errorf("ordinary_write = %+v, want it to succeed", c)
			}
			// The link itself is made in the worktree: its body is no end, so only the open through it is refused.
			if c := h.check(t, "config_self_link"); c.Err != "" {
				t.Errorf("config_self_link = %+v, want the symlink made", c)
			}
			// Unprivileged, this process cannot read a non-dumpable target at all; as root it can.
			readsUndumpable := os.Geteuid() == 0
			if c := h.check(t, "undumpable"); c.Err != "" {
				t.Fatalf("prctl(PR_SET_DUMPABLE, 0) = %+v, want it to succeed", c)
			}
			if c := h.check(t, "undumpable_hook_write"); !isErrno(c.Err, refusalErrno) {
				t.Errorf("undumpable_hook_write = %+v, want R10's errno", c)
			}
			if c := h.check(t, "undumpable_ordinary_write"); readsUndumpable && c.Err != "" {
				t.Errorf("undumpable_ordinary_write = %+v, want it to succeed where this process reads the target", c)
			} else if !readsUndumpable && !isErrno(c.Err, refusalErrno) {
				t.Errorf("undumpable_ordinary_write = %+v, want R10's errno: its path cannot be read", c)
			}
			// Unprivileged AT_EMPTY_PATH links need 6.10 or later; before that the kernel's own answer is
			// ENOENT, which the continued syscall returns.
			if c := h.check(t, "ordinary_tmpfile_link"); c.Err != "" && !isErrno(c.Err, unix.ENOENT) {
				t.Errorf("ordinary_tmpfile_link = %+v, want it continued: success, or the kernel's own ENOENT", c)
			}
			entries, err := os.ReadDir(filepath.Join(h.dir, ".git/hooks"))
			if err != nil || len(entries) != 0 {
				t.Errorf("hooks directory holds %v (%v), want nothing", entries, err)
			}
			hooks, config := "fs.deny_write["+filepath.Join(h.dir, ".git/hooks")+"]", "fs.deny_write["+filepath.Join(h.dir, ".git/config")+"]"
			want := map[string]string{ // the refused line's path2 (a link's new name) or path, and its rule
				filepath.Join(h.dir, ".git/hooks/pre-commit"):     hooks,
				filepath.Join(h.dir, ".git/hooks/pre-push"):       hooks,
				filepath.Join(h.dir, "cfg"):                       config,
				filepath.Join(h.dir, "cfg-self"):                  config,
				filepath.Join(h.dir, ".git/hooks/post-checkout"):  hooks,
				filepath.Join(h.dir, ".git/hooks/pre-rebase"):     hooks,
				filepath.Join(h.dir, ".git/hooks/pre-applypatch"): hooks,
			}
			if readsUndumpable {
				want[filepath.Join(h.dir, ".git/hooks/post-merge")] = hooks
			}
			unread := 0 // refused opens whose path could not be read: the non-dumpable target's two writes
			for _, ev := range h.sink.all() {
				if ev.Kind != record.KindFS {
					continue
				}
				var p record.FSPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				name := p.Path2
				if p.Op != record.FSLink {
					name = p.Path
				}
				if name == "" && p.Op == record.FSOpen && ev.Verdict == record.VerdictRefused && ev.Rule == ruleArgsUnreadable {
					unread++
					continue
				}
				if isCoverData(name) {
					continue
				}
				// Every wanted line is a refused end; the making of cfg-self, which the open through it is wanted under,
				// goes with the lines nothing wants.
				rule, ok := want[name]
				if !ok || p.Op == record.FSSymlink {
					if ev.Verdict == record.VerdictRefused {
						t.Errorf("unexpected refusal %s/%s %s %q", ev.Verdict, ev.Rule, p.Op, name)
					}
					if mode == modeDenyWriteOff {
						t.Errorf("record: off wrote a %s line for %s %q", ev.Verdict, p.Op, name)
					}
					continue
				}
				delete(want, name)
				if ev.Verdict != record.VerdictRefused || ev.Rule != rule || ev.Reason != record.ReasonWriteOutsideContract {
					t.Errorf("%s %q: %s/%s/%s, want refused/%s/%s", p.Op, name, ev.Verdict, ev.Rule, ev.Reason, rule, record.ReasonWriteOutsideContract)
				}
				if p.Op == record.FSLink && p.Path == "" {
					t.Errorf("%s %q: the old end is unnamed, want the file its descriptor holds", p.Op, name)
				}
			}
			for name := range want {
				t.Errorf("no line for %q", name)
			}
			if wantUnread := map[bool]int{true: 0, false: 2}[readsUndumpable]; unread != wantUnread {
				t.Errorf("%d refused %s lines, want %d", unread, ruleArgsUnreadable, wantUnread)
			}
		})
	}
}
