// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestOneLinePerActionWithTheSupervisor is supervisor R7a on the recorder's side, at tier 2: the recorder writes
// the line of every fs action its hooks see, with the chain's verdict, and names one its directory index cannot
// by the supervisor's own naming of the action it continued (ContinuedFS), keyed by the thread, the operation
// and the final component; it writes no exec line when the supervisor writes every exec's (SupervisorExecs); it
// writes none for an open the fanotify listener refused after Landlock let it through, whose own line is the
// action's (a Landlock refusal, the chain's EACCES, keeps the recorder's); and it names an allowed modification
// by the entry that granted it, as compile --test does, not by a deny_read entry nearer to the path.
//
// Spec: docs/p0/supervisor.md R7a; docs/p0/enforce-cgroup-observe.md R9.
func TestOneLinePerActionWithTheSupervisor(t *testing.T) {
	f := newFixture(t)
	nested := filepath.Join(f.out, "keys")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	rt := ruleTable([]agent.FSRule{
		{Path: f.out, Kind: agent.FSWrite, Raw: "./out", Access: agent.AccessWriteSet},
		{Path: nested, Kind: agent.FSDenyRead, Raw: "./out/keys", Unenforced: true},
	}, nil, []agent.ExecRule{{Raw: "git", Path: "/usr/bin/git", Basename: "git", Verdict: agent.VerdictAllow}})
	rt.Tier = backend.TierCgroup
	f.rules = rt
	di, ok := statDevIno(nested)
	if !ok {
		t.Fatal("stat")
	}
	eacces := -int32(unix.EACCES)
	at := func(k Kind, mono uint64, ret int32) sample {
		return sample{Kind: k, PID: 50, TID: 51, MonoNS: mono, Ret: ret, RetOK: true, CgroupID: 77, PPID: 1}
	}
	asked := 0
	opts := Options{FlushInterval: time.Hour, SupervisorExecs: true,
		ContinuedFS: func(tid int, op, name, name2 string, at uint64) (string, string, string, record.Verdict, record.Reason, bool) {
			asked++
			if tid != 51 || op != record.FSUnlink || name != "gone.txt" || at != 2 {
				return "", "", "", "", "", false
			}
			return "/spelled/gone.txt", "", agent.UnmatchedRule, record.VerdictRefused, record.ReasonDeleteOutsideContract, true
		}}
	_, sink := runRecorder(t, f, opts,
		execSample(sample{PID: 50, TID: 50, MonoNS: 1}, 900*proc.NanosPerTick, "git", "/usr/bin/git", []string{"git"}, false),
		// An unlink in a directory no entry is: the index cannot name it, the supervisor does.
		fsSample(at(KindUnlink, 2, eacces), 0, 999, 2049, "gone.txt", ""),
		// A read the listener refused (6.13+: the chain returned 0) and one Landlock refused first.
		fsSample(at(KindOpen, 3, 0), 0, 1, di.Dev, filepath.Join(nested, "token"), ""),
		fsSample(at(KindOpen, 4, eacces), 0, 1, di.Dev, filepath.Join(nested, "token2"), ""),
		// A mkdir beneath the nested deny_read, which the write entry's grant allows.
		fsSample(at(KindMkdir, 5, 0), 0, uint32(di.Ino), di.Dev, "sub", ""),
	)
	if got := len(sink.byKind(record.KindExec)); got != 0 {
		t.Errorf("%d exec lines, want none: the supervisor writes every exec's", got)
	}
	lines := map[string]*record.Event{}
	for _, ev := range sink.byKind(record.KindFS) {
		lines[payload[record.FSPayload](t, ev).Path] = ev
	}
	if ev := lines["/spelled/gone.txt"]; ev == nil || ev.Verdict != record.VerdictRefused ||
		ev.Reason != record.ReasonDeleteOutsideContract || ev.Rule != agent.UnmatchedRule {
		t.Errorf("the unlink the index cannot name: %+v (asked %d times), want refused unmatched under the supervisor's path", ev, asked)
	}
	if ev, ok := lines[filepath.Join(nested, "token")]; ok {
		t.Errorf("the listener's refusal has a recorder line too: %+v", ev)
	}
	if ev := lines[filepath.Join(nested, "token2")]; ev == nil || ev.Verdict != record.VerdictRefused {
		t.Errorf("Landlock's refusal: %+v, want the recorder's refused line", ev)
	}
	if ev := lines[filepath.Join(nested, "sub")]; ev == nil || ev.Verdict != record.VerdictAllow || ev.Rule != "fs.write[./out]" {
		t.Errorf("the allowed mkdir: %+v, want allow named by the write entry that granted it", ev)
	}
}

// TestRecorderResolvesNoExecPathNobodyReads: with the supervisor writing every exec's line (SupervisorExecs) and no
// hook, the recorder writes nothing that names an exec's path, so a relative exec name is not resolved: that
// would be a /proc readlink and a stat on the drain goroutine for nothing. A hook reads the path, and gets it
// resolved.
func TestRecorderResolvesNoExecPathNobodyReads(t *testing.T) {
	f := newFixture(t)
	work := t.TempDir()
	if err := os.Symlink(work, filepath.Join(f.procFS.Root(), "50", "cwd")); err != nil {
		t.Fatal(err)
	}
	di, ok := statDevIno(work)
	if !ok {
		t.Fatal("stat the working directory")
	}
	for _, hooked := range []bool{false, true} {
		r, err := New(Options{Rules: f.rules, Proc: f.procFS, Reader: newFakeRing(), SupervisorExecs: true})
		if err != nil {
			t.Fatal(err)
		}
		r.procs = newProcCache(f.procFS, "r-host-1", r.opts.CacheSize)
		if hooked {
			r.hooks = append(r.hooks, &hookLog{})
		}
		rec := &Record{Kind: KindExec, PID: 50, PPID: 1}
		rec.Exec.Path, rec.Exec.CwdDev, rec.Exec.CwdIno = "./tool", di.Dev, di.Ino
		r.handle(rec)
		want := "./tool"
		if hooked {
			want = filepath.Join(work, "tool")
		}
		if rec.Exec.Path != want {
			t.Errorf("hooked=%v: the exec's path is %q, want %q", hooked, rec.Exec.Path, want)
		}
	}
}
