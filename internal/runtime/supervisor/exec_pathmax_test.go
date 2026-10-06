// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"bytes"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestExecPathnamePastPathMaxEveryRun: an exec pathname with no NUL in its first PATH_MAX bytes is answered
// ENAMETOOLONG in every restricted run, with or without command rules, as the kernel's getname answers it; a
// pathname whose read faults before its NUL is EFAULT. A run with no exec: section continues both, and the kernel
// answers them itself.
func TestExecPathnamePastPathMaxEveryRun(t *testing.T) {
	nr := nrFor(t, "execve")
	restricted := func() *Policy {
		pol := contractPolicy(&agent.Contract{Exec: &agent.ExecSection{Allow: []string{"/usr/bin/true"}}}, nil, nil)
		pol.Rules.Exec = append(pol.Rules.Exec, agent.ExecRule{Raw: "/usr/bin/true", Path: "/usr/bin/true", Basename: "true", Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow})
		return pol
	}
	for _, c := range []struct {
		name      string
		pol       func() *Policy
		path      []byte
		errno     unix.Errno
		continued bool
	}{
		{"restricted, no command rules, past PATH_MAX", restricted, bytes.Repeat([]byte("a"), 5000), unix.ENAMETOOLONG, false},
		{"restricted, no command rules, faulting at 100 bytes", restricted, bytes.Repeat([]byte("a"), 100), unix.EFAULT, false},
		{"command rules, past PATH_MAX", func() *Policy { return commandPolicy(t, "allow: git status") }, bytes.Repeat([]byte("a"), 5000), unix.ENAMETOOLONG, false},
		{"no exec: section, past PATH_MAX", func() *Policy { return contractPolicy(&agent.Contract{}, nil, nil) }, bytes.Repeat([]byte("a"), 5000), 0, true},
	} {
		f := newFake()
		l, sink := newTestLoop(t, f, c.pol())
		const argvAddr, pathAddr = 0x210000, 0x400000
		execFixture(f, argvAddr, []string{"x"})
		f.put(pathAddr, c.path)
		l.handle(notifFor(nr, 42, pathAddr, argvAddr, 0))
		got, _ := f.lastResp()
		if cont := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0; cont != c.continued {
			t.Errorf("%s: response %+v, continued %v, want %v", c.name, got, cont, c.continued)
			continue
		}
		if !c.continued && got.Error != -int32(c.errno) {
			t.Errorf("%s: response %+v, want errno %v", c.name, got, c.errno)
		}
		if evs := sink.all(); !c.continued && (len(evs) != 1 || evs[0].Verdict == record.VerdictAllow) {
			t.Errorf("%s: lines %+v, want one that is not allow", c.name, evs)
		}
	}
}
