// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestStartHelperFallsBackAndSaysWhy: a helper the launcher cannot put in HelperScope (not root, or a mount
// that is no cgroup2) still starts, in the launcher's own cgroup as before, and says why in its environment
// (HelperEnvUnplaced) and to its caller.
func TestStartHelperFallsBackAndSaysWhy(t *testing.T) {
	for _, tc := range []struct {
		name  string
		root  bool
		mount string
		want  string
	}{
		{"not root", false, t.TempDir(), "not root"},
		{"no cgroup2 at the mount", true, t.TempDir(), "magic"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "env")
			why, err := startHelperIn(tc.mount, tc.root, nil, os.Getpid(), func(extra []string) *exec.Cmd {
				cmd := exec.Command("/bin/sh", "-c", `printf '%s' "$`+HelperEnvUnplaced+`" > "$OUT"`)
				cmd.Env = append([]string{"OUT=" + out}, extra...)
				return cmd
			})
			if err != nil {
				t.Fatalf("StartHelper: %v", err)
			}
			if !strings.Contains(why, tc.want) {
				t.Errorf("why = %q, want it to say %q", why, tc.want)
			}
			var got []byte
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
				if got, err = os.ReadFile(out); err == nil && len(got) > 0 {
					break
				}
			}
			if string(got) != why {
				t.Errorf("the helper's %s = %q, want %q", HelperEnvUnplaced, got, why)
			}
			if _, err := os.Stat(filepath.Join(tc.mount, "tego.slice")); tc.root && err == nil {
				t.Error("a mount that is no cgroup2 got a tego.slice directory")
			}
		})
	}
}

// TestStartHelperAsksCase39: root whose /proc/self/cgroup and cgroup2 mount name different trees (a
// cgroupns-private container handed the host's /sys/fs/cgroup reads "0::/" for its own namespace root) gets no
// HelperScope: startHelperIn falls back, says case 39, and makes no tego.slice in the other tree. It needs no
// privilege: the refusal comes before any mkdir.
func TestStartHelperAsksCase39(t *testing.T) {
	if err := checkCgroup2(Mount); err != nil {
		t.Skipf("no cgroup2 mount here: %v", err)
	}
	data, err := os.ReadFile(procSelfCgroup)
	if err != nil {
		t.Skipf("no %s: %v", procSelfCgroup, err)
	}
	if own := ownCgroup(data); own == "" || own == "/" {
		t.Skipf("this process's cgroup is %q, where the host-tree shape cannot be told apart", own)
	}
	_, before := os.Stat(filepath.Join(Mount, "tego.slice"))
	for _, in := range []string{"0::/\n", "", "0::/../../system.slice/docker-abc.scope\n"} {
		why, err := startHelperIn(Mount, true, []byte(in), os.Getpid(), func([]string) *exec.Cmd {
			return exec.Command("/bin/true")
		})
		if err != nil {
			t.Fatalf("StartHelper: %v", err)
		}
		if !strings.Contains(why, "case 39") {
			t.Errorf("procCgroup %q: why = %q, want a case-39 refusal", in, why)
		}
	}
	if _, after := os.Stat(filepath.Join(Mount, "tego.slice")); os.IsNotExist(before) && !os.IsNotExist(after) {
		t.Error("a mount that disagrees with /proc/self/cgroup got a tego.slice directory")
	}
}

// TestStartHelperReapsItsHelper: a helper that exits while its launcher runs on leaves no zombie child behind. A
// launcher starts the linger timer of another build from Prepare, at the start of a
// run that can last hours, and that timer exits a linger later, or at once on a busy timer lock: released and never
// waited for, each stayed a zombie of `tego run` until the run ended.
func TestStartHelperReapsItsHelper(t *testing.T) {
	out := filepath.Join(t.TempDir(), "pid")
	if _, err := startHelperIn(t.TempDir(), false, nil, os.Getpid(), func(extra []string) *exec.Cmd {
		cmd := exec.Command("/bin/sh", "-c", `echo $$ > "$OUT.tmp" && mv "$OUT.tmp" "$OUT"`)
		cmd.Env = append([]string{"OUT=" + out}, extra...)
		return cmd
	}); err != nil {
		t.Fatalf("StartHelper: %v", err)
	}
	stat := "" // the helper's /proc/<pid>/stat, once it has said its pid
	var last []byte
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if stat == "" {
			b, err := os.ReadFile(out)
			pid, perr := strconv.Atoi(strings.TrimSpace(string(b)))
			if err != nil || perr != nil {
				continue
			}
			stat = filepath.Join("/proc", strconv.Itoa(pid), "stat")
		}
		b, err := os.ReadFile(stat)
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		last = b
	}
	t.Fatalf("the helper (%s), which exits at once, is still a child of the launcher 5 s later: %s", stat, last)
}
