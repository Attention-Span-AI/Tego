// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"fmt"
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

// modeWatch runs the target under an enforcing run's filter with its watch arm (enforce-landlock R11e), and a table
// whose one entry is a deny_read the Landlock ruleset enforces (R36).
const modeWatch = "watch"

// watchRuleTable is the harness's table for modeWatch: the deny_read target secret/ beside the directories the target
// may watch, at tier landlock, where nothing but the target is withheld.
func watchRuleTable(dir string) *agent.RuleTable {
	secret := filepath.Join(dir, "secret")
	return &agent.RuleTable{
		FS:     []agent.FSRule{{Path: secret, Kind: agent.FSDenyRead, Resolved: secret}},
		Record: agent.RecordSummary, Tier: backend.TierLandlock, Contract: &agent.Contract{},
	}
}

// watchPrepare makes the target, a file in it, a directory beside it, a symlink to it and a directory a ".." climbs
// out of, before the target starts.
func watchPrepare(t *testing.T) func(dir string) {
	return func(dir string) {
		for _, d := range []string{"secret", "ok", "up"} {
			if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "secret", "key"), []byte("k"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(dir, "secret"), filepath.Join(dir, "lnk")); err != nil {
			t.Fatal(err)
		}
	}
}

// watchChecks are the target's watches, made under the filter: inotify on the target, a file in it, the target through
// a symlink, a ".." and its own /proc/self/fd link to an O_PATH descriptor of it, the symlink itself (IN_DONT_FOLLOW),
// the directory beside it and the directory that holds it; then dnotify (fcntl F_NOTIFY) on a descriptor of the
// target, its removal there, and dnotify on the directory beside it; then, where this kernel lets an unprivileged
// process make a fanotify group, an inode mark on the target by path and by descriptor, one on the directory beside
// it, a mount mark there, and the removal of a mark on the target, which adds none. The inotify watch through
// /proc/self/fd reports its descriptor's number in Out. dnotify and the fanotify mark by descriptor open the target as
// a directory to list, which a tier-1 ruleset lets through on the READ_DIR it inherits (SEMANTICS §1): neither takes
// an O_PATH descriptor (EBADF).
func watchChecks() []checkResult {
	dir := os.Getenv(helperDir)
	secret, ok := filepath.Join(dir, "secret"), filepath.Join(dir, "ok")
	var out []checkResult
	add := func(name string, err error) { out = append(out, checkResult{Name: name, Err: errText(err)}) }
	in, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	add("inotify_init", err)
	if err == nil {
		watch := func(name, path string, mask uint32) {
			_, err := unix.InotifyAddWatch(in, path, mask)
			add(name, err)
		}
		watch("inotify_target", secret, unix.IN_ALL_EVENTS)
		watch("inotify_target_file", filepath.Join(secret, "key"), unix.IN_OPEN|unix.IN_MODIFY)
		watch("inotify_link", filepath.Join(dir, "lnk"), unix.IN_ALL_EVENTS)
		watch("inotify_dotdot", filepath.Join(dir, "up")+"/../secret", unix.IN_ALL_EVENTS)
		if fd, err := unix.Open(secret, unix.O_PATH|unix.O_CLOEXEC, 0); err == nil {
			watch("inotify_proc_fd", "/proc/self/fd/"+strconv.Itoa(fd), unix.IN_ALL_EVENTS)
			out[len(out)-1].Out = strconv.Itoa(fd)
			_ = unix.Close(fd)
		} else {
			add("inotify_proc_fd", err)
		}
		watch("inotify_link_nofollow", filepath.Join(dir, "lnk"), unix.IN_ALL_EVENTS|unix.IN_DONT_FOLLOW)
		watch("inotify_beside", ok, unix.IN_ALL_EVENTS)
		watch("inotify_parent", dir, unix.IN_ALL_EVENTS)
		_ = unix.Close(in)
	}
	// dnotify: each descriptor is closed at once, which drops its watch, so no event is ever sent to this process.
	dnotify := func(name, path string, mask int) {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			add(name, fmt.Errorf("open to list: %w", err))
			return
		}
		_, err = unix.FcntlInt(uintptr(fd), unix.F_NOTIFY, mask)
		add(name, err)
		_ = unix.Close(fd)
	}
	dnotify("dnotify_target", secret, dnAccess|dnModify|dnMultishot)
	dnotify("dnotify_remove", secret, 0)
	dnotify("dnotify_beside", ok, dnAccess|dnModify|dnMultishot)
	fan, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_REPORT_FID|unix.FAN_CLOEXEC, unix.O_RDONLY)
	add("fanotify_init", err)
	if err == nil {
		mark := func(name string, flags uint, dirfd int, path string) {
			add(name, unix.FanotifyMark(fan, flags, unix.FAN_OPEN|unix.FAN_MODIFY|unix.FAN_EVENT_ON_CHILD, dirfd, path))
		}
		mark("fanotify_target", unix.FAN_MARK_ADD, unix.AT_FDCWD, secret)
		if fd, err := unix.Open(secret, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err == nil {
			mark("fanotify_target_fd", unix.FAN_MARK_ADD, fd, "") // a NULL pathname: the descriptor's own file
			_ = unix.Close(fd)
		} else {
			add("fanotify_target_fd", err)
		}
		mark("fanotify_beside", unix.FAN_MARK_ADD, unix.AT_FDCWD, ok)
		mark("fanotify_mount", unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, unix.AT_FDCWD, ok)
		mark("fanotify_remove", unix.FAN_MARK_REMOVE, unix.AT_FDCWD, secret)
		_ = unix.Close(fan)
	}
	return out
}

// TestIntegrationWatchBeneathADenyReadTarget is supervisor R36 on the real kernel at tier landlock (GAPS A10): every
// watch of the deny_read target, of a file in it, and of it reached through a symlink, a ".." or a /proc/self/fd
// link, is refused EACCES with a refused line under the target's rule, op the syscall, reason read-denied; the symlink
// watched itself, the directory beside the target and the directory that holds it are watched. A dnotify watch
// (fcntl F_NOTIFY) of a descriptor of the target, which the ruleset lets the target open to list, is refused the same
// way, op fcntl, and its removal there, which adds none, and one beside it are made. A fanotify inode mark on the
// target, by path or by descriptor, is refused the same way, a mount mark anywhere is refused EPERM under
// deny-read-watch (the kernel's own answer to an unprivileged one, so its line is what tells this loop's refusal
// apart), and a removal is continued to the kernel, which finds no mark (ENOENT). Without the arm and its handler
// every one of those watches but the mount mark succeeded (no Landlock or plane hook sees one), so a run learned
// which of the target's files were opened and changed.
func TestIntegrationWatchBeneathADenyReadTarget(t *testing.T) {
	h := startHarnessWith(t, harnessOpts{mode: modeWatch, prepare: watchPrepare(t)})
	h.stop(t)
	if c := h.check(t, "inotify_init"); c.Err != "" {
		t.Fatalf("inotify_init1 = %+v", c)
	}
	refused := []string{"inotify_target", "inotify_target_file", "inotify_link", "inotify_dotdot", "inotify_proc_fd",
		"dnotify_target"}
	watched := []string{"inotify_link_nofollow", "inotify_beside", "inotify_parent", "dnotify_remove", "dnotify_beside"}
	fanotify := h.check(t, "fanotify_init").Err == ""
	if fanotify {
		// The refusals come before the kernel reads the filesystem, so they hold on any; a mark the kernel itself
		// places needs one that reports file handles (FAN_REPORT_FID), which this process asks of the harness's own.
		refused = append(refused, "fanotify_target", "fanotify_target_fd")
		if c := h.check(t, "fanotify_mount"); !isErrno(c.Err, unix.EPERM) {
			t.Errorf("fanotify_mount = %+v, want EPERM: a whole-mount mark is refused", c)
		}
		if err := fidMarkable(filepath.Join(h.dir, "ok")); err != nil {
			t.Logf("no file-handle mark on this filesystem (%v): the marks the kernel would place are not checked", err)
		} else {
			watched = append(watched, "fanotify_beside")
			if c := h.check(t, "fanotify_remove"); !isErrno(c.Err, unix.ENOENT) {
				t.Errorf("fanotify_remove = %+v, want the kernel's ENOENT: a removal is continued", c)
			}
		}
	} else {
		t.Logf("no unprivileged fanotify group here (%s): the fanotify cases are not run", h.check(t, "fanotify_init").Err)
	}
	for _, name := range refused {
		if c := h.check(t, name); !isErrno(c.Err, unix.EACCES) {
			t.Errorf("%s = %+v, want EACCES: it watches the deny_read target", name, c)
		}
	}
	for _, name := range watched {
		if c := h.check(t, name); c.Err != "" {
			t.Errorf("%s = %+v, want the watch made: it is not beneath the target", name, c)
		}
	}
	secret := filepath.Join(h.dir, "secret")
	rule := agent.FSRule{Path: secret, Kind: agent.FSDenyRead}.RuleName()
	want := map[string]string{ // op and target of each refused line, to its rule
		"inotify_add_watch " + secret:                                          rule,
		"inotify_add_watch " + filepath.Join(secret, "key"):                    rule,
		"inotify_add_watch " + filepath.Join(h.dir, "lnk"):                     rule,
		"inotify_add_watch /proc/self/fd/" + h.check(t, "inotify_proc_fd").Out: rule,
		"fcntl " + secret: rule, // dnotify, named by the descriptor's own file
	}
	wantN := 6 // the target itself twice: by its own name and by the name the ".." walk gives it
	if fanotify {
		want["fanotify_mark "+secret] = rule
		want["fanotify_mark "+filepath.Join(h.dir, "ok")] = ruleWatchWhole
		wantN += 3
	}
	n := 0
	for _, ev := range h.sink.all() {
		if ev.Kind != record.KindRefused {
			continue
		}
		var p record.RefusedPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(p.Op, "inotify") && !strings.HasPrefix(p.Op, "fanotify") && p.Op != "fcntl" {
			continue
		}
		n++
		if r, ok := want[p.Op+" "+p.Target]; !ok || ev.Rule != r || p.Rule != r || ev.Reason != record.ReasonReadDenied {
			t.Errorf("refused line %s %q rule=%s reason=%s, want one of %v under read-denied", p.Op, p.Target, ev.Rule, ev.Reason, want)
		}
		if err := ev.Validate(); err != nil {
			t.Errorf("refused line does not validate: %v", err)
		}
	}
	if n != wantN {
		t.Errorf("%d refused watch lines, want %d, one per refused watch", n, wantN)
	}
}

// fidMarkable reports whether an unprivileged fanotify group of this process, outside any filter, can mark dir: its
// filesystem must report file handles (FAN_REPORT_FID), which not every one does.
func fidMarkable(dir string) error {
	fan, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_REPORT_FID|unix.FAN_CLOEXEC, unix.O_RDONLY)
	if err != nil {
		return err
	}
	defer unix.Close(fan) //nolint:errcheck // a probe's group
	return unix.FanotifyMark(fan, unix.FAN_MARK_ADD, unix.FAN_OPEN|unix.FAN_MODIFY|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, dir)
}
