// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"strconv"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestMatchFSCostDoesNotGrowWithEntries: the recorder's per-sample fs questions, the entry naming the path, the
// verdict it infers, the listener's open rule and the grant naming a modification, cost about the same against a small table and against one the built-in .env scan
// filled with 50,000 deny_read entries (agent.Compile's envScanMaxEntries, files the agent can plant in an
// earlier run). Asked by scan, one sample cost 53–65 ms at 50,000 entries, so the single drain goroutine fell
// behind and the ring dropped samples.
func TestMatchFSCostDoesNotGrowWithEntries(t *testing.T) {
	const root = "/nonexistent-tego-scale/u"
	table := func(envs int) *agent.RuleTable {
		rt := &agent.RuleTable{Tier: backend.TierCgroup, FS: []agent.FSRule{
			{Kind: agent.FSWrite, Path: root + "/proj", Raw: "./proj", Access: agent.AccessWriteSet},
			{Kind: agent.FSWrite, Path: "/tmp", Raw: "/tmp", Access: agent.AccessWriteSet},
			{Kind: agent.FSDenyRead, Path: root + "/.ssh", Raw: "~/.ssh", BuiltIn: true},
			{Kind: agent.FSWatch, Path: root + "/proj/logs", Raw: "./proj/logs"},
		}}
		for i := range envs {
			p := root + "/proj/gen/d" + strconv.Itoa(i/100) + "/" + strconv.Itoa(i) + "/.env"
			rt.FS = append(rt.FS, agent.FSRule{Kind: agent.FSDenyRead, Path: p, Raw: p, BuiltIn: true, Unenforced: true})
		}
		return rt
	}
	paths := []string{root + "/proj/src/pkg/main.go", root + "/.ssh/id_ed25519", root + "/proj/gen/d3/345/.env", "/usr/share/zoneinfo/UTC"}
	// One sample is 20 rounds of the paths' questions; each figure the least thread CPU time of 10 samples, small and
	// large interleaved.
	const rounds = 20
	sample := func(ri *ruleIndex) func() {
		return func() {
			for range rounds {
				for _, p := range paths {
					m := ri.matchFS(p)
					ri.inferFS(record.FSOpen, false, m)
					ri.inferFS(record.FSUnlink, true, m)
					// Every tier-2 open asks the listener's rule, and every allowed modification the grant.
					ri.listenerOpenRefused(p)
					ri.grantName(record.FSOpen, p)
					ri.grantName(record.FSUnlink, p)
				}
			}
		}
	}
	small := newRuleIndexAt(table(10), "/nonexistent")
	large := newRuleIndexAt(table(50_000), "/nonexistent")
	if m := large.matchFS(root + "/proj/gen/d3/345/.env"); m.Rule != "fs.deny_read["+root+"/proj/gen/d3/345/.env]" {
		t.Fatalf("a planted .env is named %s", m.Rule)
	}
	mt := testutil.MinOf(testutil.ThreadCPU, 10, sample(small), sample(large))
	s, l := mt[0]/(rounds*time.Duration(len(paths))), mt[1]/(rounds*time.Duration(len(paths)))
	t.Logf("per sample: %v at %d entries, %v at %d", s, len(small.rt.FS), l, len(large.rt.FS))
	if l > 20*s+50*time.Microsecond {
		t.Errorf("a sample costs %v at %d entries against %v at %d: the recorder's cost grows with the entries",
			l, len(large.rt.FS), s, len(small.rt.FS))
	}
}

// TestMatchExecCostDoesNotGrowWithEntries: the recorder asks the decision core about every exec, and an allowed
// exec's open is a read the fs entries decide (SEMANTICS §4), so the exec path asked the same questions the fs
// samples do. Asked by scan it cost 16–31 ms per exec at 50,000 .env entries, 30–60 execs a second before the
// drain goroutine fell behind a build; asked of the index it costs about what it does against a small table,
// with the same answers.
func TestMatchExecCostDoesNotGrowWithEntries(t *testing.T) {
	const root = "/nonexistent-tego-scale/u"
	for _, restricted := range []bool{false, true} {
		table := func(envs int) *agent.RuleTable {
			c := &agent.Contract{}
			rt := &agent.RuleTable{Contract: c, Tier: backend.TierCgroup, FS: []agent.FSRule{
				{Kind: agent.FSWrite, Path: root + "/proj", Raw: "./proj", Access: agent.AccessWriteSet},
				{Kind: agent.FSDenyRead, Path: root + "/.ssh", Raw: "~/.ssh", BuiltIn: true},
			}}
			if restricted {
				c.Exec = &agent.ExecSection{}
				rt.Exec = []agent.ExecRule{
					{Raw: "/usr/bin/make", Path: "/usr/bin/make", Verdict: agent.VerdictAllow},
					{Raw: root + "/.ssh/tool", Path: root + "/.ssh/tool", Verdict: agent.VerdictAllow},
				}
			}
			for i := range envs {
				p := root + "/proj/gen/d" + strconv.Itoa(i/100) + "/" + strconv.Itoa(i) + "/.env"
				rt.FS = append(rt.FS, agent.FSRule{Kind: agent.FSDenyRead, Path: p, Raw: p, BuiltIn: true, Unenforced: true})
			}
			return rt
		}
		paths := []string{"/usr/bin/make", root + "/proj/bin/tool", root + "/.ssh/tool"}
		small := newRuleIndexAt(table(10), "/nonexistent")
		large := newRuleIndexAt(table(50_000), "/nonexistent")
		for _, p := range paths {
			if s, l := small.matchExec(p), large.matchExec(p); s != l {
				t.Fatalf("exec %s: %+v at %d entries, %+v at %d", p, s, len(small.rt.FS), l, len(large.rt.FS))
			}
		}
		if m := large.matchExec(root + "/.ssh/tool"); m.Verdict != record.VerdictRefused || m.Reason != record.ReasonReadDenied {
			t.Fatalf("an exec under ~/.ssh is %+v, want refused read-denied", m)
		}
		// One sample is 10 rounds of the paths; each figure the least thread CPU time of 10 samples, small and large
		// interleaved.
		const rounds = 10
		sample := func(ri *ruleIndex) func() {
			return func() {
				for range rounds {
					for _, p := range paths {
						ri.matchExec(p)
					}
				}
			}
		}
		mt := testutil.MinOf(testutil.ThreadCPU, 10, sample(small), sample(large))
		s, l := mt[0]/(rounds*time.Duration(len(paths))), mt[1]/(rounds*time.Duration(len(paths)))
		t.Logf("exec section %v, per exec: %v at %d entries, %v at %d", restricted, s, len(small.rt.FS), l, len(large.rt.FS))
		if l > 20*s+50*time.Microsecond {
			t.Errorf("exec section %v: an exec costs %v at %d entries against %v at %d: the recorder's cost grows with the entries",
				restricted, l, len(large.rt.FS), s, len(small.rt.FS))
		}
	}
}
