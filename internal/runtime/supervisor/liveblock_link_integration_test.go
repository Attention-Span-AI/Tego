// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// modeExecLiveLink runs liveLinkChecks: the target starts a child by every spelling of one multi-call file's names.
const modeExecLiveLink = "exec-live-link"

// The names of the multi-call layout liveLinkLayout makes in the harness's directory: one program file under three
// names (box, ls, sleep), a symbolic link to ls, and a second hard link in a folder the agent writes, standing in for
// one the agent made there.
const (
	linkBox   = "box"
	linkLs    = "ls"
	linkSleep = "sleep"
	linkSym   = "xls"
	linkHard2 = "w/hard2"
	linkTool  = "w/tool"
)

// liveLinkLayout copies payload (a real true(1)) into dir as box and gives it its other names.
func liveLinkLayout(t *testing.T, dir, payload string) {
	t.Helper()
	b, err := os.ReadFile(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, linkBox), b, 0o755); err != nil { //nolint:gosec // an executable fixture
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "w"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{linkLs, linkSleep, linkHard2} {
		if err := os.Link(filepath.Join(dir, linkBox), filepath.Join(dir, n)); err != nil {
			t.Skipf("hard link: %v", err)
		}
	}
	if err := os.Symlink(filepath.Join(dir, linkLs), filepath.Join(dir, linkSym)); err != nil {
		t.Fatal(err)
	}
}

// liveLinkChecks starts one child per spelling and waits for it: "" is a child that ran and exited 0, an errno the
// exec's refusal. The /proc/self/fd/N spellings run a descriptor the target opened by that name.
func liveLinkChecks() []checkResult {
	dir := os.Getenv(helperDir)
	var out []checkResult
	run := func(name, path string) {
		pid, err := syscall.ForkExec(path, []string{filepath.Base(path)}, &syscall.ProcAttr{})
		if err != nil {
			out = append(out, checkResult{Name: name, Err: errText(err)})
			return
		}
		var ws unix.WaitStatus
		if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
			out = append(out, checkResult{Name: name, Err: errText(err)})
			return
		}
		res := ""
		if !ws.Exited() || ws.ExitStatus() != 0 {
			res = "exit " + strconv.Itoa(ws.ExitStatus())
		}
		out = append(out, checkResult{Name: name, Err: res})
	}
	byFD := func(name, path string) {
		fd, err := unix.Open(path, unix.O_PATH, 0)
		if err != nil {
			out = append(out, checkResult{Name: name, Err: "open: " + errText(err)})
			return
		}
		defer unix.Close(fd) //nolint:errcheck // the target's own descriptor
		run(name, "/proc/self/fd/"+strconv.Itoa(fd))
	}
	run("ls", filepath.Join(dir, linkLs))
	run("xls", filepath.Join(dir, linkSym))
	byFD("proc_ls", filepath.Join(dir, linkLs))
	run("sleep", filepath.Join(dir, linkSleep))
	byFD("proc_sleep", filepath.Join(dir, linkSleep))
	run("hard2", filepath.Join(dir, linkHard2))
	run("box", filepath.Join(dir, linkBox))
	return out
}

// TestLiveLinkBlockOnARealKernel is TestLiveLinkBlockRefusesWhatTheNewContractRefuses on a real kernel, real filter,
// real Loop and real child processes: under exec.allow [ls, sleep], where ls and sleep are hard links of one real
// true(1), the block "Also apply now" places when ls is removed refuses ls by its name, through a symbolic link and
// through /proc/self/fd/N of a descriptor opened by that name, under the block's rule; sleep by its name and by its
// descriptor runs and exits 0, as exec.allow [sleep] lets it; a second hard link in a write folder and the file's
// dispatcher name stay refused under the contract's own rule. Then a person's block on ls by path refuses sleep too.
// Last, exec.allow [w/tool, sleep] with w/tool a symbolic link to ls when the run starts, which the agent points at
// sleep after the loop fixed the entry's grant and before the block on w/tool lands: the block still refuses ls by
// every spelling, as the run granted it under w/tool, and sleep runs.
func TestLiveLinkBlockOnARealKernel(t *testing.T) {
	payload := truePayload(t)
	link := func(o *liveblock.Overlay, v string) error {
		_, _, err := o.AddLink(liveblock.KindExec, v, "uid:1 pid:2 dashboard", time.Now())
		return err
	}
	for _, tc := range []struct {
		name  string
		add   func(o *liveblock.Overlay, value string) error
		allow map[string]bool // the spellings that run
		tool  bool            // the block is on w/tool, a link to ls repointed at sleep once the loop runs
	}{
		{"a block from a rules change", link, map[string]bool{"sleep": true, "proc_sleep": true}, false},
		{"a person's block by path", func(o *liveblock.Overlay, v string) error {
			_, _, err := o.Add(liveblock.KindExec, v, "uid:1 pid:2 cli", time.Now())
			return err
		}, map[string]bool{}, false},
		{"a block from a rules change on an entry repointed in the run", link,
			map[string]bool{"sleep": true, "proc_sleep": true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var (
				set    *liveblock.Set
				value  string
				placed sync.Once
			)
			h := startHarnessWith(t, harnessOpts{mode: modeExecLiveLink,
				prepare: func(dir string) {
					liveLinkLayout(t, dir, payload)
					value = filepath.Join(dir, linkLs)
					if tc.tool {
						value = filepath.Join(dir, linkTool)
						if err := os.Symlink(filepath.Join(dir, linkLs), value); err != nil {
							t.Fatal(err)
						}
					}
				},
				// The block lands at the first exec the loop decides, after the loop fixed each entry's grant; on
				// the repointed case the agent's repoint comes first.
				live: func() *liveblock.Set {
					placed.Do(func() {
						if tc.tool {
							if err := os.Remove(value); err != nil {
								t.Error(err)
							}
							if err := os.Symlink(filepath.Join(filepath.Dir(filepath.Dir(value)), linkSleep), value); err != nil {
								t.Error(err)
							}
						}
						o := liveblock.New("r-test")
						if err := tc.add(o, value); err != nil {
							t.Error(err)
						}
						set = linkSet(t, o)
					})
					return set
				},
				rules: func(rt *agent.RuleTable, dir string) {
					var allow []string
					rt.Exec = nil
					first := linkLs
					if tc.tool {
						first = linkTool
					}
					for _, n := range []string{first, linkSleep} {
						p := filepath.Join(dir, n)
						allow = append(allow, p)
						rt.Exec = append(rt.Exec, agent.ExecRule{Raw: p, Path: p, Basename: filepath.Base(n), Source: agent.ExecSourceAllow})
					}
					rt.Tier = backend.TierLandlock
					rt.Contract = &agent.Contract{Exec: &agent.ExecSection{Allow: allow}}
				}})
			got := map[string]string{}
			for _, c := range h.report.Checks {
				got[c.Name] = c.Err
			}
			for _, name := range []string{"ls", "xls", "proc_ls", "sleep", "proc_sleep", "hard2", "box"} {
				want := unix.EACCES.Error()
				if tc.allow[name] {
					want = ""
				}
				if g, ok := got[name]; !ok || g != want {
					t.Errorf("%s: %q (reported %v), want %q", name, g, ok, want)
				}
			}
			// The ledger: the contract's own refusals keep its rule, the block's name the block.
			blockRule := "live.block[exec:" + value + "]"
			for _, ev := range h.sink.all() {
				if ev.Kind != record.KindExec || ev.Verdict != record.VerdictRefused {
					continue
				}
				var p execPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				contract := strings.HasSuffix(p.Path, "/"+linkHard2) || strings.HasSuffix(p.Path, "/"+linkBox)
				switch {
				case contract && ev.Rule == blockRule:
					t.Errorf("%s refused under the block, want the contract's own rule", p.Path)
				case !contract && ev.Rule != blockRule:
					t.Errorf("%s refused under %s, want %s", p.Path, ev.Rule, blockRule)
				}
			}
		})
	}
}
