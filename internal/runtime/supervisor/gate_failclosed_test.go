// SPDX-License-Identifier: Apache-2.0
//go:build amd64 || arm64

package supervisor

import (
	"fmt"
	"github.com/attention-span-ai/tego/internal/testutil/contracttest"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
	"path/filepath"
	"testing"
)

func TestGateOnlyFilesystemFaultsRefuse(t *testing.T) {
	const pathAddr = 0x10000
	for _, tc := range []struct {
		name string
		args []uint64
	}{
		{"openat read", []uint64{argCWD, pathAddr, unix.O_RDONLY}},
		{"openat write", []uint64{argCWD, pathAddr, unix.O_WRONLY}},
		{"fchmodat", []uint64{argCWD, pathAddr, 0o600}},
		{"unlinkat", []uint64{argCWD, pathAddr, 0}},
	} {
		for _, fault := range []string{"healthy", "panic", "no answer", "ID_VALID error"} {
			t.Run(tc.name+"/"+fault, func(t *testing.T) {
				root := t.TempDir()
				compiled := contracttest.BuildAt(t, root, `version: 0
name: gate-fault
command: [fixture]
capture: off
record: full
fs:
  write: [../outside]
  deny_read: []
gate:
  rules:
    - 'fs.read matches "*.env"': 90
    - fs.write outside worktree: 90
`, contracttest.Tree{"work/": "", "outside/secret.env": "owned"}, agent.WithCwd(filepath.Join(root, "work")))
				if hasOrdinaryWriteFloor(compiled.Rules) || len(compiled.Rules.FSAsk) != 0 {
					t.Fatalf("not gate-only: deny%v ask%v", compiled.Rules.DenyWrite, compiled.Rules.FSAsk)
				}
				f := newFake()
				f.put(pathAddr, cstr(compiled.Path("outside/secret.env")))
				pol := testPolicy(nil, nil, nil)
				pol.Rules = compiled.Rules
				l, sink := newTestLoop(t, f, pol)
				name := tc.name
				if name == "openat read" || name == "openat write" {
					name = "openat"
				}
				nr := nrFor(t, name)
				key := dispatchKey{arch: nativeAuditArch(), nr: nr}
				e := l.dispatch[key]
				switch fault {
				case "panic":
					e.fn = func(*Loop, *notif) { panic("owned gate handler fault") }
					l.dispatch[key] = e
				case "no answer":
					e.fn = func(*Loop, *notif) {}
					l.dispatch[key] = e
				case "ID_VALID error":
					f.idValidFailAll = unix.EBADF
				}
				l.handle(notifFor(nr, 42, tc.args...))
				got, ok := f.lastResp()
				if !ok || got.Flags != 0 || got.Error != -int32(refusalErrno) {
					t.Fatalf("gate-only %s response %+v answered=%v; want refusal, never CONTINUE", fault, got, ok)
				}
				if fault == "healthy" {
					ev := sink.one(t)
					if ev.Verdict != record.VerdictRefused || ev.Authority != record.AuthorityGate {
						t.Fatalf("healthy authority %+v", ev)
					}
				}
			})
		}
	}
}

// A failed handler is refused whatever the gate scores, and a gate adds nothing to that: what it scores
// and what it does not fail alike (failClosed). Observe transforms a refusal centrally, including this
// last-resort response.
func TestGateFilesystemFaultScope(t *testing.T) {
	for _, tc := range []struct {
		name, rule, syscall string
		flags               uint64
		observe, refuse     bool
	}{
		{"read gate read", `fs.read matches "*.env"`, "openat", unix.O_RDONLY, false, true},
		{"read gate write", `fs.read matches "*.env"`, "openat", unix.O_WRONLY, false, true},
		{"read gate read-write", `fs.read matches "*.env"`, "openat", unix.O_RDWR, false, true},
		{"write gate read", "fs.write outside worktree", "openat", unix.O_RDONLY, false, true},
		{"write gate write", "fs.write outside worktree", "openat", unix.O_WRONLY, false, true},
		{"read gate unlink", `fs.read matches "*.env"`, "unlinkat", 0, false, true},
		{"read gate rename", `fs.read matches "*.env"`, "renameat", 0, false, true},
		{"write gate chmod", "fs.write outside worktree", "fchmodat", 0o600, false, true},
		// Review findings R2-3 and N1 of GATE-STEP2-ROWS: a read gate scores a rename's or link's source (ADR 0041
		// Step 4), so a failed handler refuses one; a mknod reads nothing (R2-2).
		{"read gate rename", `fs.read matches "*.env"`, "renameat", 0, false, true},
		{"read gate rename2", `fs.read matches "*.env"`, "renameat2", 0, false, true},
		{"read gate link", `fs.read matches "*.env"`, "linkat", 0, false, true},
		{"read gate mknod", `fs.read matches "*.env"`, "mknodat", 0, false, true},
		// Review finding R2-1: a write gate scores the xattr and chown families, so a failed handler refuses them.
		{"write gate setxattr", "fs.write outside worktree", "setxattr", 0, false, true},
		{"write gate fsetxattr", "fs.write outside worktree", "fsetxattr", 0, false, true},
		{"write gate fchownat", "fs.write outside worktree", "fchownat", 0, false, true},
		{"read gate setxattr", `fs.read matches "*.env"`, "setxattr", 0, false, true},
		{"no gate read", "", "openat", unix.O_RDONLY, false, true},
		{"no gate write", "", "openat", unix.O_WRONLY, false, true},
		{"observe read", `fs.read matches "*.env"`, "openat", unix.O_RDONLY, true, false},
		{"observe write", "fs.write outside worktree", "openat", unix.O_WRONLY, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := gateFaultRules(t, tc.rule)
			f := newFake()
			pol := testPolicy(nil, nil, nil)
			pol.Rules = rt
			pol.Observe = tc.observe
			l, _ := newTestLoop(t, f, pol)
			nr := nrFor(t, tc.syscall)
			key := dispatchKey{arch: nativeAuditArch(), nr: nr}
			e := l.dispatch[key]
			e.fn = func(*Loop, *notif) {}
			l.dispatch[key] = e
			l.handle(notifFor(nr, 42, argCWD, 0x10000, tc.flags))
			got, ok := f.lastResp()
			if !ok || len(f.responses) != 1 {
				t.Fatalf("responses %+v", f.responses)
			}
			if tc.refuse {
				if got.Flags != 0 || got.Error != -int32(refusalErrno) {
					t.Fatalf("want refusal: %+v", got)
				}
			} else if got.Flags != unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE || got.Error != 0 {
				t.Fatalf("want CONTINUE: %+v", got)
			}
		})
	}
}

// Both supported dispatch tables route their record-only filesystem families
// through the gate-aware fallback; this tests the actual registry without
// requiring those architecture's syscalls on the host.
func TestGateWriteFaultCoversFilesystemDispatchTables(t *testing.T) {
	rt := gateFaultRules(t, "fs.write outside worktree")
	for _, arch := range []uint32{auditArchX86, auditArchARM} {
		for key, e := range buildDispatchFor(arch) {
			t.Run(fmt.Sprintf("%x/%s", arch, e.name), func(t *testing.T) {
				f := newFake()
				pol := testPolicy(nil, nil, nil)
				pol.Rules = rt
				l, _ := newTestLoop(t, f, pol)
				l.dispatch = buildDispatchFor(arch)
				e.fn = func(*Loop, *notif) {}
				l.dispatch[key] = e
				n := notifFor(key.nr, 42)
				n.arch = arch
				switch e.name {
				case "open":
					n.args[1] = unix.O_WRONLY
				case "openat":
					n.args[2] = unix.O_WRONLY
				}
				l.handle(n)
				got, ok := f.lastResp()
				if !ok || got.Flags != 0 || got.Error != -int32(refusalErrno) {
					t.Fatalf("filesystem gate bypassed on handler failure: %+v", got)
				}
			})
		}
	}
}

func gateFaultRules(t *testing.T, rule string) *agent.RuleTable {
	t.Helper()
	root := t.TempDir()
	rules := ""
	if rule != "" {
		rules = "gate:\n  rules:\n    - '" + rule + "': 90\n"
	}
	f := contracttest.BuildAt(t, root, `version: 0
name: gate-fault
command: [fixture]
capture: off
record: full
fs:
  write: [../outside]
  deny_read: []
`+rules, contracttest.Tree{"work/": "", "outside/secret.env": "owned"}, agent.WithCwd(filepath.Join(root, "work")))
	if hasOrdinaryWriteFloor(f.Rules) || len(f.Rules.FSAsk) != 0 {
		t.Fatal("fixture is not gate-only")
	}
	return f.Rules
}

// C40 is present even in gate-only fixtures; these assertions disable the
// contract and R20 targets whose priority these gate tests originally isolated.
func hasOrdinaryWriteFloor(rt *agent.RuleTable) bool {
	for _, r := range rt.DenyWrite {
		if r.BuiltinRule == "" {
			return true
		}
	}
	return false
}
