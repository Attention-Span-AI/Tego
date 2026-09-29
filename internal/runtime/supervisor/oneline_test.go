// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestEveryFSAndExecActionHasExactlyOneLine is R7a's "one line per action" for the filesystem and exec actions
// the filter notifies, across tier × record mode × outcome, as TestEveryConnectHasExactlyOneLine is R7's for
// connects. The action's lines are this loop's plus the kernel recorder's, modelled by the producer table: the
// recorder writes the line of a continued fs action its hooks see while it reads the run (KernelFS), under every
// record mode for a refusal and under summary and full for an allow; it writes no exec line (SupervisorExecs).
// Every other line is this loop's. An allowed action under record: off has no line at any tier by design, and a
// mode change is notified under record: full only. A tier-2 exec left with no line (the recorder's exec lines
// dropped and this loop's skipped) is the failure this guards.
//
// Spec: docs/p0/supervisor.md R7a.
func TestEveryFSAndExecActionHasExactlyOneLine(t *testing.T) {
	const work = "/work/proj"
	fs := []agent.FSRule{{Path: work, Kind: agent.FSWrite, Raw: "./proj/", Access: agent.AccessWriteSet}}
	deny := []agent.FSRule{{Path: work + "/.git/config", Kind: agent.FSDenyWrite, BuiltIn: true, Unenforced: true, Resolved: work + "/.git/config"}}
	const pathAddr, argvAddr = 0x10000, 0x20000
	type action struct {
		name, syscall string
		path          string
		args          []uint64
		refused       bool // the action's verdict
		hooked        bool // the recorder's hooks see it when it is continued
		fullOnly      bool // notified under record: full only
	}
	actions := []action{
		{name: "allowed exec", syscall: "execve", path: "/usr/bin/true", args: []uint64{pathAddr, argvAddr, 0}},
		{name: "refused exec", syscall: "execve", path: "/usr/bin/other", args: []uint64{pathAddr, argvAddr, 0}, refused: true},
		{name: "allowed write-open", syscall: "openat", path: work + "/a", args: []uint64{argCWD, pathAddr, 0x241}, hooked: true},
		{name: "refused write-open", syscall: "openat", path: "/etc/x", args: []uint64{argCWD, pathAddr, 0x241}, refused: true, hooked: true},
		{name: "allowed unlink", syscall: "unlinkat", path: work + "/b", args: []uint64{argCWD, pathAddr, 0}, hooked: true},
		{name: "deny_write refusal", syscall: "openat", path: work + "/.git/config", args: []uint64{argCWD, pathAddr, 0x241}, refused: true},
		{name: "mode change", syscall: "fchmodat", path: work + "/c", args: []uint64{argCWD, pathAddr, 0o644}, fullOnly: true},
	}
	type tier struct {
		name    string
		tier    backend.Tier
		kernel  bool // Options.KernelFS is set
		reading bool // and answers true
		observe bool
	}
	tiers := []tier{
		{name: "tier 1", tier: backend.TierLandlock},
		{name: "tier 2", tier: backend.TierCgroup, kernel: true, reading: true},
		{name: "tier 2 recorder reads nothing", tier: backend.TierCgroup, kernel: true},
		{name: "tier 2 no recorder", tier: backend.TierCgroup},
		{name: "observe", tier: backend.TierLandlock, observe: true},
	}
	for _, tr := range tiers {
		for _, rec := range []agent.RecordMode{agent.RecordOff, agent.RecordSummary, agent.RecordFull} {
			for _, a := range actions {
				if a.fullOnly && rec != agent.RecordFull {
					continue // not notified under this record mode (enforce-landlock R11)
				}
				t.Run(fmt.Sprintf("%s/record=%s/%s", tr.name, rec, a.name), func(t *testing.T) {
					f := newFake()
					f.put(pathAddr, cstr(a.path))
					execFixture(f, argvAddr, []string{a.path})
					pol := contractPolicy(&agent.Contract{Exec: &agent.ExecSection{}}, nil, fs)
					pol.Rules.Exec = []agent.ExecRule{{Path: "/usr/bin/true", Source: agent.ExecSourceAllow}}
					pol.Rules.DenyWrite = deny
					pol.Rules.Tier = tr.tier
					pol.Rules.Record = rec
					pol.Record = rec
					pol.Observe = tr.observe
					l, sink := newTestLoop(t, f, pol)
					if tr.kernel {
						reading := tr.reading
						l.kernelFS = func() bool { return reading }
					}
					l.handle(notifFor(nrFor(t, a.syscall), 42, a.args...))
					own := len(sink.all())
					// The deny_write refusal is answered here, so it never reaches the kernel's hook.
					kernel := 0
					response, _ := f.lastResp()
					continued := response.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0
					if tr.reading && a.hooked && continued && (a.refused || rec != agent.RecordOff) {
						kernel = 1
					}
					want := 1
					if !a.refused && rec == agent.RecordOff {
						want = 0
					}
					if own+kernel != want {
						t.Errorf("%d lines from this loop + %d from the recorder, want %d in all", own, kernel, want)
					}
					if own > 0 && sink.all()[0].Kind == record.KindExec && own != 1 {
						t.Errorf("%d exec lines for one exec", own)
					}
				})
			}
		}
	}
}
