// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// namesTable is a table over the fixture's out/ at tier: a write entry, the expansion entry of an existing out/.env,
// and the built-in .env pair scoped to out/.
func namesTable(f *fixture, tier backend.Tier) *agent.RuleTable {
	w, env := f.out, filepath.Join(f.out, ".env")
	scope := []agent.NameScope{{Canonical: w, Spelling: w}}
	return &agent.RuleTable{Tier: tier, Record: agent.RecordFull,
		FS: []agent.FSRule{
			{Kind: agent.FSWrite, Path: w, Raw: "./out", Resolved: w, Access: agent.AccessWriteSet},
			{Kind: agent.FSDenyRead, Path: env, Raw: "./out/.env", Resolved: env, BuiltIn: true, Unenforced: true,
				Regular: true, Nlink: 1},
		},
		NameDeny: []agent.NameDenyRule{
			{Literal: ".env", Scopes: scope, BuiltIn: true},
			{Literal: ".env.", Prefix: true, Except: []string{".env.example"}, Scopes: scope, BuiltIn: true},
		},
	}
}

// TestPlaneNameRefusalNamesTheRule is ADR 0043 D8 in the recorder: a refusal the plane made by a name entry (the
// rule_idx carries decide.PlaneRuleName) is named by the deny_read entry at the file's own path when there is one,
// the expansion entry compaction dropped from the rows (out/.env), and by the name entry's own rule otherwise (a
// .env.local created after compile: the built-in label with the scope's spelling); one line each.
func TestPlaneNameRefusalNamesTheRule(t *testing.T) {
	f := newFixture(t)
	rt := namesTable(f, backend.TierBPFLSM)
	f.rules = rt
	rows, err := decide.CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows.Scopes) == 0 {
		t.Fatal("the rows carry no name scope")
	}
	refused := func(k Kind, mono uint64, reason bpf.ReasonCode, rule uint16) sample {
		return sample{Kind: k, PID: 50, TID: 50, MonoNS: mono, Start: 900, Verdict: KernelRefused,
			Reason: uint8(reason), RuleIdx: rule, Ret: -13, RetOK: true}
	}
	dev := uint64(2049)
	env, local := filepath.Join(f.out, ".env"), filepath.Join(f.out, "later", ".env.local")
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, DecisionPlane: record.DecisionPlaneLSM},
		fsSample(refused(KindOpen, 1, bpf.ReasonReadDenied, decide.PlaneNameTag(0, 0)), 0, 1, dev, env, ""),
		fsSample(refused(KindOpen, 2, bpf.ReasonReadDenied, decide.PlaneNameTag(1, 0)), 0, 1, dev, local, ""),
		fsSample(refused(KindOpen, 3, bpf.ReasonWriteOutsideContract, decide.PlaneNameTag(1, 0)), unix.O_WRONLY|unix.O_CREAT, 1, dev, local, ""),
	)
	fs := sink.byKind(record.KindFS)
	if len(fs) != 3 {
		t.Fatalf("%d fs lines, want one per action: %+v", len(fs), fs)
	}
	for i, want := range []struct {
		rule   string
		reason record.Reason
	}{
		{"fs.deny_read[./out/.env]", record.ReasonReadDenied},
		{"fs.deny_read[" + f.out + "/**/.env.*]", record.ReasonReadDenied},
		{"fs.deny_read[" + f.out + "/**/.env.*]", record.ReasonWriteOutsideContract},
	} {
		ev := fs[i]
		p := payload[record.FSPayload](t, ev)
		if ev.Verdict != record.VerdictRefused || ev.Rule != want.rule || ev.Reason != want.reason || p.Mechanism != record.MechanismPlane {
			t.Errorf("fs line %d (%s): %s %s %s %s, want refused %s %s by the plane", i, p.Path, ev.Verdict, ev.Rule, ev.Reason,
				p.Mechanism, want.rule, want.reason)
		}
	}
}

// TestRecorderLeavesListenerNameRefusalsToTheListener is ADR 0043 D7 in tier 2's recorder: an open the fanotify
// listener refused by a name entry (the chain returned its EPERM) is the listener's line, so the recorder writes none,
// as for a nested deny_read.
func TestRecorderLeavesListenerNameRefusalsToTheListener(t *testing.T) {
	f := newFixture(t)
	f.rules = namesTable(f, backend.TierCgroup)
	// The scope's mount, which the listener marks (markedDevices).
	di, ok := statDevIno(f.out)
	if !ok {
		t.Fatal("stat")
	}
	mountinfo := filepath.Join(t.TempDir(), "mountinfo")
	line := fmt.Sprintf("1 0 %d:%d / / rw - fs dev rw\n", unix.Major(di.Dev), unix.Minor(di.Dev))
	if err := os.WriteFile(mountinfo, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	// The control: the same refused open of a name no entry covers is the recorder's line.
	local, plain := filepath.Join(f.out, "later", ".env.local"), filepath.Join(f.out, "later", "notes.txt")
	s := sample{Kind: KindOpen, PID: 50, TID: 50, MonoNS: 1, Start: 900, Ret: -int32(unix.EPERM), RetOK: true}
	c := sample{Kind: KindOpen, PID: 50, TID: 50, MonoNS: 2, Start: 900, Ret: -int32(unix.EPERM), RetOK: true}
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, mountinfo: mountinfo},
		fsSample(s, 0, 1, di.Dev, local, ""), fsSample(c, 0, 2, di.Dev, plain, ""))
	lines := map[string]int{}
	for _, ev := range sink.byKind(record.KindFS) {
		lines[filepath.Base(payload[record.FSPayload](t, ev).Path)]++
	}
	if lines[".env.local"] != 0 || lines["notes.txt"] != 1 {
		t.Errorf("the recorder wrote %d lines for an open the listener refused by a name and %d for the control's, want 0 and 1",
			lines[".env.local"], lines["notes.txt"])
	}
}

// TestPlaneAllowedNestedDenyReadKeepsTheChainsAnswer: a read under a deny_read entry the
// Landlock ruleset leaves unenforced is the fanotify listener's only on the fallback (ADR 0016 (4)); where a plane
// mode decides the run, at tier cgroup or bpflsm, the plane is in the chain and stamps its refusals, so an open
// the chain let through (0, no stamp: the plane's row keyed another inode, as for a file recreated at the entry's
// path) is recorded allow from the chain, never the path model's refusal of an open that happened.
func TestPlaneAllowedNestedDenyReadKeepsTheChainsAnswer(t *testing.T) {
	for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
		t.Run(string(tier), func(t *testing.T) {
			f := newFixture(t)
			f.rules = namesTable(f, tier)
			env := filepath.Join(f.out, ".env")
			s := sample{Kind: KindOpen, PID: 50, TID: 50, MonoNS: 1, Start: 900, RetOK: true}
			_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, DecisionPlane: record.DecisionPlaneLSM},
				fsSample(s, 0, 1, 2049, env, ""))
			fs := sink.byKind(record.KindFS)
			if len(fs) != 1 {
				t.Fatalf("%d fs lines, want 1: %+v", len(fs), fs)
			}
			if p := payload[record.FSPayload](t, fs[0]); fs[0].Verdict != record.VerdictAllow || p.VerdictFrom != record.FSVerdictChain {
				t.Errorf("the open the plane let through: %s from %s, want allow from the chain", fs[0].Verdict, p.VerdictFrom)
			}
		})
	}
}

// TestRecorderWritesTheLineOfAnOpenThePlaneAllowed: no fanotify listener decides opens where a
// plane mode decides a tier-cgroup run, so no open there is the listener's to record. The plane exempts an
// author-exempted file by its parent's inode, the path model by path (ADR 0043 D3): once out/app is renamed out/app2
// the plane allows app2/.env, whose open (the chain returned 0) is the recorder's line under record: full, like the
// control's, in either plane mode. On the fanotify fallback the listener decides by the model's rule, so it refused
// app2/.env and wrote that line itself: from 6.13 the chain returns 0 for it too, and the recorder writes none.
func TestRecorderWritesTheLineOfAnOpenThePlaneAllowed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		plane string
		want  int
	}{
		{"lsm mode", record.DecisionPlaneLSM, 1},
		{"fmod_ret mode", record.DecisionPlaneFmodRet, 1},
		{"the fanotify fallback (the listener's line)", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			rt := namesTable(f, backend.TierCgroup)
			rt.NameExempt = []agent.NameExemptRule{{Parent: filepath.Join(f.out, "app"), Name: ".env"}}
			f.rules = rt
			di, ok := statDevIno(f.out)
			if !ok {
				t.Fatal("stat")
			}
			mountinfo := filepath.Join(t.TempDir(), "mountinfo")
			line := fmt.Sprintf("1 0 %d:%d / / rw - fs dev rw\n", unix.Major(di.Dev), unix.Minor(di.Dev))
			if err := os.WriteFile(mountinfo, []byte(line), 0o644); err != nil {
				t.Fatal(err)
			}
			moved, plain := filepath.Join(f.out, "app2", ".env"), filepath.Join(f.out, "app2", "notes.txt")
			s := sample{Kind: KindOpen, PID: 50, TID: 50, MonoNS: 1, Start: 900, RetOK: true}
			c := sample{Kind: KindOpen, PID: 50, TID: 50, MonoNS: 2, Start: 900, RetOK: true}
			_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, mountinfo: mountinfo, DecisionPlane: tc.plane},
				fsSample(s, 0, 1, di.Dev, moved, ""), fsSample(c, 0, 2, di.Dev, plain, ""))
			lines := map[string]int{}
			for _, ev := range sink.byKind(record.KindFS) {
				lines[filepath.Base(payload[record.FSPayload](t, ev).Path)]++
			}
			if lines[".env"] != tc.want || lines["notes.txt"] != 1 {
				t.Errorf("the recorder wrote %d lines for app2/.env and %d for the control's, want %d and 1", lines[".env"],
					lines["notes.txt"], tc.want)
			}
		})
	}
}
