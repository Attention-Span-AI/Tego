// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/check/livestatus"
	"github.com/attention-span-ai/tego/internal/check/rule"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// linkRun is a run id the run directory below is made under.
const linkRun = "r-3f9c2a1b-0dllq06ts7402-l1vexx"

// multiCall is one program file under two names, ls and sleep (hard links, as a multi-call program's applets are on
// Ubuntu 25.10 and 26.04), a symbolic link alias to ls, and a symbolic link lnk to the folder; os.Link makes the
// links, so a host whose coreutils are GNU tests it too.
func multiCall(t *testing.T) (bin, ls, sleep string) {
	t.Helper()
	bin, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ls, sleep = filepath.Join(bin, "ls"), filepath.Join(bin, "sleep")
	if err := os.WriteFile(ls, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // an executable fixture
		t.Fatal(err)
	}
	if err := os.Link(ls, sleep); err != nil {
		t.Skipf("hard link: %v", err)
	}
	if err := os.Symlink(ls, filepath.Join(bin, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(bin, filepath.Join(filepath.Dir(bin), filepath.Base(bin)+"-lnk")); err != nil {
		t.Fatal(err)
	}
	return bin, ls, sleep
}

// TestBlockOfTwoLinksOfOneFile: removing one name of a multi-call file from exec.allow while another entry stays is
// offered its block whatever the other entry leads to on this machine now: another name of the file (the block refuses
// that name only, runact.BlockFromContract), a link to the same name, the same file through a linked folder, a folder
// that holds it through a link, busybox's layout (every applet a symbolic link to one file). The running run grants
// the removed entry by what it led to when the run started, which the dashboard cannot see; the supervisor can, and
// the block refuses only what the run grants under that entry. Only the entries' text keeps a block back.
func TestBlockOfTwoLinksOfOneFile(t *testing.T) {
	bin, ls, sleep := multiCall(t)
	lnk := bin + "-lnk"
	box := filepath.Join(bin, "busybox")
	if err := os.WriteFile(box, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // an executable fixture
		t.Fatal(err)
	}
	bbLs, bbCat := filepath.Join(bin, "bb-ls"), filepath.Join(bin, "bb-cat")
	for _, l := range []string{bbLs, bbCat} {
		if err := os.Symlink(box, l); err != nil {
			t.Fatal(err)
		}
	}
	if k, v, why := blockOf(rule.Change{Remove: true, Key: "exec.allow", Entry: bbLs}, "/p", "/h",
		map[string][]string{"exec.allow": {bbCat}}); string(k)+":"+v != "exec:"+bbLs || why != "" {
		t.Errorf("busybox: %s:%s (%q), want the block on %s", k, v, why, bbLs)
	}
	for _, c := range []struct {
		name string
		rest []string
		want string // kind:value, or "!" plus a word of the reason
	}{
		{"another name of the file stays", []string{sleep}, "exec:" + ls},
		{"a link to the same name stays", []string{filepath.Join(bin, "alias")}, "exec:" + ls},
		{"the same file through a linked folder", []string{filepath.Join(lnk, "ls")}, "exec:" + ls},
		{"a folder that holds it, through a link", []string{lnk + "/"}, "exec:" + ls},
		{"another folder", []string{"/opt/tools/"}, "exec:" + ls},
		{"the same entry stays", []string{ls}, "!" + ls},
		{"its folder stays", []string{bin + "/"}, "!" + bin + "/"},
	} {
		t.Run(c.name, func(t *testing.T) {
			k, v, why := blockOf(rule.Change{Remove: true, Key: "exec.allow", Entry: ls}, "/p", "/h", map[string][]string{"exec.allow": c.rest})
			switch {
			case strings.HasPrefix(c.want, "!"):
				if k != "" || !strings.Contains(why, c.want[1:]) {
					t.Errorf("%s:%s (%q), want no block, a reason naming %q", k, v, why, c.want[1:])
				}
			case string(k)+":"+v != c.want || why != "":
				t.Errorf("%s:%s (%q), want %s", k, v, why, c.want)
			}
		})
	}
}

// TestBlockOfARepointedEntry: an exec.allow entry that is a symbolic link in a folder the agent writes, led to ls
// when the run started, and the agent points it at sleep, another name of the same file that the contract keeps,
// before the change. The running run still grants ls under the entry (the supervisor fixed its file and path at the
// start), and the next run's contract refuses ls, so removing the entry is offered its block: what the entry leads
// to now says nothing of what the running run grants under it.
func TestBlockOfARepointedEntry(t *testing.T) {
	bin, ls, sleep := multiCall(t)
	w := filepath.Join(bin, "w")
	if err := os.Mkdir(w, 0o755); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(w, "tool")
	if err := os.Symlink(ls, tool); err != nil { // as the run started
		t.Fatal(err)
	}
	if err := os.Remove(tool); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sleep, tool); err != nil { // the agent repoints it during the run
		t.Fatal(err)
	}
	k, v, why := blockOf(rule.Change{Remove: true, Key: "exec.allow", Entry: tool}, "/p", "/h",
		map[string][]string{"exec.allow": {sleep}})
	if string(k)+":"+v != "exec:"+tool || why != "" {
		t.Errorf("%s:%s (%q), want the block on %s", k, v, why, tool)
	}
}

// TestAlsoApplyNowLeavesTheOtherNames: "Also apply now" of exec.allow [ls, sleep] → [sleep], where ls and sleep are one
// file, places a block that refuses ls and runs sleep on a run whose launcher reads a link block, and the whole-file
// block (sleep refused too) on a run whose launcher predates it: never no block. The overlay is compiled as the run's
// launcher compiles it.
func TestAlsoApplyNowLeavesTheOtherNames(t *testing.T) {
	_, ls, sleep := multiCall(t)
	var st unix.Stat_t
	if err := unix.Stat(ls, &st); err != nil {
		t.Fatal(err)
	}
	id := liveblock.FileID{Dev: st.Dev, Ino: st.Ino}
	for _, tc := range []struct {
		name         string
		marked       bool
		sleepRefused bool
	}{
		{"a launcher that reads a link block", true, false},
		{"an older launcher", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, linkRun)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			start := `{"v":1,"seq":0,"id":"` + strings.Repeat("0", 63) + `1","prev":"","ts":"2026-11-11T12:00:00Z","mono_ns":1,"run":"` +
				linkRun + `","agent":"probe","pid":10,"tid":10,"cgroup":1,"kind":"run_start","source":"launcher","tier":"landlock",` +
				`"command":["sh"],"record_minor":26}` + "\n"
			if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(start), 0o600); err != nil {
				t.Fatal(err)
			}
			lock, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_RDWR|os.O_CREATE, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = lock.Close() })
			if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				t.Fatal(err)
			}
			if tc.marked {
				if err := liveblock.MarkLink(dir); err != nil {
					t.Fatal(err)
				}
			}
			s := &Service{Ledger: root, Home: "/h",
				readsHeld: func(string) (bool, string) { return true, "" },
				facts:     func(string) livestatus.Facts { return livestatus.Facts{RecordMinor: record.Minor} },
			}
			change := []rule.Change{{Remove: true, Key: "exec.allow", Entry: ls}}
			opts := s.nowOptions(context.Background(), []string{linkRun}, change, "/p", map[string][]string{"exec.allow": {sleep}})
			if len(opts) != 1 || !opts[0].OK || opts[0].Block != "exec:"+ls {
				t.Fatalf("options %+v, want the block on %s", opts, ls)
			}
			res := s.applyNow(context.Background(), opts, []string{linkRun})
			if len(res) != 1 || !res[0].OK {
				t.Fatalf("placed %+v", res)
			}
			o, err := liveblock.Read(dir, linkRun)
			if err != nil {
				t.Fatal(err)
			}
			set := liveblock.Compile(o, liveblock.Resolved{Files: map[string]liveblock.FileID{ls: id}})
			// The running contract exec.allow [ls, sleep], as the supervisor answers it: each entry grants the file at
			// its own path.
			grantOf := func(at string) liveblock.Grant {
				return func(v string) (bool, bool) { return v == ls || v == sleep, v == at }
			}
			if _, ok := set.MatchExec([]string{ls}, id, true, grantOf(ls)); !ok {
				t.Error("ls, the removed entry, is not refused")
			}
			if _, ok := set.MatchExec([]string{sleep}, id, true, grantOf(sleep)); ok != tc.sleepRefused {
				t.Errorf("sleep refused %v, want %v", ok, tc.sleepRefused)
			}
		})
	}
}
