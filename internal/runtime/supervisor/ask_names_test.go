// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestHeldAskOpenRefusesNameMatchedFile is ADR 0043's interface 2 (supervisor R15f): an approval's completion opens
// the held file outside any plane, so a file a name entry covers is refused read-denied, named by the entry, before
// any person is asked, whatever the access mode, at tiers cgroup and bpflsm; and again once the answer came, since the
// table may have gained the entry while the person decided. At tier landlock no name entry decides (D7), and the
// person is asked.
func TestHeldAskOpenRefusesNameMatchedFile(t *testing.T) {
	tid := selfTask(t)
	dir := t.TempDir()
	p := filepath.Join(dir, ".env.local")
	if e := os.WriteFile(p, []byte("SECRET=1"), 0o600); e != nil {
		t.Fatal(e)
	}
	names := []agent.NameDenyRule{{Literal: ".env.", Prefix: true, Except: []string{".env.example"}, BuiltIn: true,
		Scopes: []agent.NameScope{{Canonical: dir, Spelling: dir}}}}
	for _, tc := range []struct {
		name      string
		tier      backend.Tier
		flags     int
		late      bool // the entry reaches the table while the person decides
		asked     int
		completed int
	}{
		{"cgroup write", backend.TierCgroup, unix.O_WRONLY, false, 0, 0},
		{"cgroup read-write", backend.TierCgroup, unix.O_RDWR, false, 0, 0},
		{"bpflsm write", backend.TierBPFLSM, unix.O_WRONLY, false, 0, 0},
		{"cgroup after the wait", backend.TierCgroup, unix.O_WRONLY, true, 1, 0},
		{"landlock", backend.TierLandlock, unix.O_WRONLY, false, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, e := (sysKernel{}).PrepareAskOpen(pathQuery{tid: tid, dirfd: atFDCWD, path: p, joined: p}, tc.flags)
			if e != nil {
				t.Fatal(e)
			}
			defer unix.Close(h.fd)
			f := newFake()
			k := &heldTestKernel{fakeKernel: f, held: h}
			pol := testPolicy(nil, nil, nil)
			pol.Rules.Tier = tc.tier
			pol.Rules.FSAsk = []agent.FSRule{{Path: dir, Resolved: dir, Kind: agent.FSAsk, Raw: dir}}
			if !tc.late {
				pol.Rules.NameDeny = names
			}
			asked := 0
			sink := &testSink{}
			var l *Loop
			l, e = New(testListener(), pol, sink, Options{kernel: k, Ask: func(context.Context, ask.Request) (ask.Decision, error) {
				asked++
				if tc.late {
					later := *pol
					rt := *pol.Rules
					rt.NameDeny = names
					later.Rules = &rt
					l.table.Store(compile(&later))
				}
				return ask.Decision{Approved: true}, nil
			}})
			if e != nil {
				t.Fatal(e)
			}
			n := notifFor(nrFor(t, "openat"), 42, argCWD, 0, uint64(tc.flags))
			r := &reader{l: l, n: n}
			q := pathQuery{tid: 42, dirfd: atFDCWD, path: p, joined: p}
			if !l.askOpen(n, r, q, tc.flags, fsDecided{rule: ruleUnmatched, verdict: record.VerdictRefused, enforce: true}) {
				t.Fatal("the held open bypassed the ask handler")
			}
			l.closeAskScopes()
			if asked != tc.asked || k.completed != tc.completed {
				t.Fatalf("asked=%d completed=%d, want %d %d", asked, k.completed, tc.asked, tc.completed)
			}
			if tc.completed > 0 {
				return
			}
			res, _ := f.lastResp()
			if res.Flags != 0 || res.Error != -int32(unix.EACCES) {
				t.Fatalf("refusal %+v", res)
			}
			ev := sink.one(t)
			if ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonReadDenied || !strings.HasSuffix(ev.Rule, "/**/.env.*]") {
				t.Fatalf("line %+v, want refused read-denied named by the .env.* entry", ev)
			}
		})
	}
}

// TestAlternateRefusalNamesDeclaredNameEntries is interface 2 for an alternate (ADR 0043): the file a person names
// in place of a held one is opened outside any plane, so at tiers cgroup and bpflsm one a declared name entry covers
// is refused, as a built-in .env name is at every tier; at tier landlock no name entry decides (D7).
func TestAlternateRefusalNamesDeclaredNameEntries(t *testing.T) {
	dir := t.TempDir()
	pol := testPolicy(nil, nil, nil)
	pol.Rules.FS = append(pol.Rules.FS, agent.FSRule{Kind: agent.FSWrite, Path: dir, Resolved: dir, Raw: dir, Access: agent.AccessWriteSet})
	pol.Rules.NameDeny = []agent.NameDenyRule{{Literal: "token.json", Raw: "cfg/*/token.json",
		Scopes: []agent.NameScope{{Canonical: dir, Spelling: dir}}}}
	covered, plain := filepath.Join(dir, "a", "token.json"), filepath.Join(dir, "a", "other.json")
	for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM, backend.TierLandlock} {
		pol.Rules.Tier = tier
		why := alternateRefusal(pol.Rules, nil, covered, false)
		if want := tier != backend.TierLandlock; (why != "") != want || want && !strings.Contains(why, "fs.deny_read[cfg/*/token.json]") {
			t.Errorf("tier %s: the covered alternate's refusal %q, want refused=%v naming the entry", tier, why, want)
		}
		if why := alternateRefusal(pol.Rules, nil, plain, false); why != "" {
			t.Errorf("tier %s: an alternate no name entry covers refused: %s", tier, why)
		}
	}
}
