// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestExecAnonymousImageIsRefusedBeforeTheHandoff: where a decision plane decides execs (kernelExecHandoff, tier 3 and
// tier cgroup in a plane mode) and nothing of the supervisor's own decides them (no exec gate, no command rules), an
// exec was handed to the kernel before decideExec ran, so an anonymous image was refused by bprm_check, whose sample
// names no entry: the line read unmatched where tier 1's reads exec-anon (SEMANTICS §4), and compile --test's bpflsm
// column answered exec-anon (security F2). The walk that classifies the image has already run when the
// handoff is chosen, so a fileless image the run does not admit is refused here, as at tier 1: exec-anon, fileless,
// the refusal errno, and the kernel never sees it. One the run admits (exec.anonymous: true) is still handed over.
func TestExecAnonymousImageIsRefusedBeforeTheHandoff(t *testing.T) {
	const argvAddr = 0x20000
	for _, tc := range []struct {
		name      string
		anonymous bool
	}{
		{"images restricted", false},
		{"exec.anonymous: true", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.links["/proc/42/fd/7"] = "/memfd:payload (deleted)"
			f.put(emptyPathAddr, cstr(""))
			execFixture(f, argvAddr, []string{"payload"})
			f.tgid[42] = 40
			f.stats[40] = procStat{ppid: 1, start: 1234}
			pol := testPolicy(nil, nil, nil)
			pol.Rules.Exec = []agent.ExecRule{{Path: "/usr/bin/python3", Source: agent.ExecSourceAllow}}
			pol.Rules.Contract = &agent.Contract{Name: "anon", Exec: &agent.ExecSection{Allow: []string{"/usr/bin/python3"}, Anonymous: tc.anonymous}}
			l, sink := newTestLoop(t, f, pol)
			handed := false
			l.kernelExecHandoff = func() bool { handed = true; return true }
			l.handle(notifFor(nrFor(t, "execveat"), 42, 7, emptyPathAddr, argvAddr, 0, unix.AT_EMPTY_PATH))
			got, ok := f.lastResp()
			if !ok {
				t.Fatal("no response")
			}
			if tc.anonymous {
				if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 || len(sink.all()) != 0 || !handed {
					t.Fatalf("response %+v, %d lines, handed=%v: an admitted anonymous image is the kernel's to record", got, len(sink.all()), handed)
				}
				return
			}
			if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error == 0 {
				t.Fatalf("response = %+v, want the refusal errno: the kernel never sees the anonymous image", got)
			}
			ev := sink.one(t)
			var p execPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonExecNotAllowed || ev.Rule != ruleExecAnon || !p.Fileless {
				t.Errorf("verdict/reason/rule/fileless = %s/%s/%s/%v, want refused/exec-not-allowed/exec-anon/true", ev.Verdict, ev.Reason, ev.Rule, p.Fileless)
			}
		})
	}
}
