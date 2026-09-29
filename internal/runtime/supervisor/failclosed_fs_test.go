// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestFSHandlerFailureKeepsDenyWrite: "deny_write fails
// open on the supervisor's own error paths". R15c makes this loop the only thing that refuses a modification
// of a built-in deny_write target beneath a write entry (Landlock unions the entry's rights), and
// TestDenyWriteRefusesAnUnreadablePath already holds that a modification this loop cannot decide is refused
// once the set is non-empty. A handler that panics (recovered, R25) or returns without answering (finish, I11)
// continued an fs syscall, and the write to .git/hooks/pre-commit went through with a handler-panic gap as its line.
func TestFSHandlerFailureKeepsDenyWrite(t *testing.T) {
	const pathAddr = 0x10000
	fs := []agent.FSRule{{Path: "/w", Kind: agent.FSWrite}}
	deny := []agent.FSRule{{Path: "/w/.git/hooks", Kind: agent.FSDenyWrite, BuiltIn: true, Unenforced: true, Resolved: "/w/.git/hooks"}}
	for _, tc := range []struct {
		name string
		fn   handlerFunc
	}{
		{name: "panics", fn: func(*Loop, *notif) { panic("a bounds bug in the fs walk") }},
		{name: "returns without answering", fn: func(*Loop, *notif) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nr := nrFor(t, "openat")
			f := newFake()
			f.put(pathAddr, cstr("/w/.git/hooks/pre-commit"))
			pol := testPolicy(nil, fs, nil)
			pol.Rules.DenyWrite = deny
			l, _ := newTestLoop(t, f, pol)
			key := dispatchKey{arch: nativeAuditArch(), nr: nr}
			e := l.dispatch[key]
			e.fn = tc.fn // the real openat row, decision flag and all; only its body fails
			l.dispatch[key] = e
			l.handle(notifFor(nr, 42, argCWD, pathAddr, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC))
			got, ok := f.lastResp()
			if !ok {
				t.Fatal("no response")
			}
			if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
				t.Fatalf("a write-open whose handler %s was answered CONTINUE while the deny_write set is non-empty: "+
					"Landlock allows it beneath the write entry, so the hook is written (R15c)", tc.name)
			}
		})
	}
}

// TestChmodHandlerFailureRefuses: this loop records a mode change and refuses one only where a rule says so (a write
// gate, a live write block, a plane's deny_write, R15c, R17), and a handler that failed cannot say which held: it is
// refused, with or without a decision plane.
func TestChmodHandlerFailureRefuses(t *testing.T) {
	const pathAddr = 0x10000
	fs := []agent.FSRule{{Path: "/w", Kind: agent.FSWrite}}
	deny := []agent.FSRule{{Path: "/w/.git/hooks", Kind: agent.FSDenyWrite, BuiltIn: true, Unenforced: true, Resolved: "/w/.git/hooks"}}
	for _, plane := range []bool{false, true} {
		for _, name := range []string{"chmod", "fchmod", "fchmodat", "fchmodat2", "setxattr", "fsetxattr", "lremovexattr",
			"setxattrat", "chown", "fchown", "fchownat"} {
			for _, fail := range []struct {
				how string
				fn  handlerFunc
			}{
				{how: "panics", fn: func(*Loop, *notif) { panic("a bounds bug in the chmod path") }},
				{how: "returns without answering", fn: func(*Loop, *notif) {}},
			} {
				t.Run(fmt.Sprintf("%s %s plane=%v", name, fail.how, plane), func(t *testing.T) {
					nr := nrFor(t, name)
					f := newFake()
					f.put(pathAddr, cstr("/w/.git/hooks/pre-commit"))
					pol := testPolicy(nil, fs, nil)
					pol.Rules.DenyWrite = deny
					pol.Rules.Record = agent.RecordFull
					l, _ := newTestLoop(t, f, pol)
					l.planeAttrs = plane
					key := dispatchKey{arch: nativeAuditArch(), nr: nr}
					e := l.dispatch[key]
					e.fn = fail.fn
					l.dispatch[key] = e
					l.handle(notifFor(nr, 42, argCWD, pathAddr, 0o755))
					got, ok := f.lastResp()
					if !ok {
						t.Fatal("no response")
					}
					if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(refusalErrno) {
						t.Errorf("a %s whose handler %s was answered %+v; want a refusal", name, fail.how, got)
					}
				})
			}
		}
	}
}

// TestHandlerFailureKeepsWhatOnlyTheHandlerKnew: the rules a failed handler would have applied at tier 1, where
// Landlock has already said yes. A held read beneath a write entry, the fs.reads default for a nested .env or a
// deny_read beneath it (ADR 0069 D6): a panic continued it, and the secret came back with exit 0 and one gap line. And
// a live block, which no fault list knew of: a panic continued an open, a mode change or a rename the block names.
func TestHandlerFailureKeepsWhatOnlyTheHandlerKnew(t *testing.T) {
	const pathAddr = 0x10000
	held := func() *Policy {
		pol := testPolicy(nil, []agent.FSRule{{Path: "/w", Kind: agent.FSWrite}}, nil)
		pol.Rules.Reads = agent.HeldReads{Mode: agent.ReadsHeld}
		pol.Rules.Tier = backend.TierLandlock
		return pol
	}
	blocked := func() *Policy { return testPolicy(nil, []agent.FSRule{{Path: "/w", Kind: agent.FSWrite}}, nil) }
	set := liveSet(t, "path", "/w/keys")
	blocks := Options{LiveBlocks: func() *liveblock.Set { return set }}
	for _, tc := range []struct {
		name    string
		pol     func() *Policy
		opts    Options
		syscall string
		args    []uint64
	}{
		{"held read", held, Options{}, "openat", []uint64{argCWD, pathAddr, unix.O_RDONLY}},
		{"held read-write", held, Options{}, "openat", []uint64{argCWD, pathAddr, unix.O_RDWR}},
		{"held O_PATH", held, Options{}, "openat", []uint64{argCWD, pathAddr, unix.O_PATH}},
		{"blocked read", blocked, blocks, "openat", []uint64{argCWD, pathAddr, unix.O_RDONLY}},
		{"blocked write", blocked, blocks, "openat", []uint64{argCWD, pathAddr, unix.O_WRONLY}},
		{"blocked mode change", blocked, blocks, "fchmodat", []uint64{argCWD, pathAddr, 0o777}},
		{"blocked rename", blocked, blocks, "renameat", []uint64{argCWD, pathAddr, argCWD, pathAddr}},
	} {
		for _, fail := range []struct {
			how string
			fn  handlerFunc
		}{
			{how: "panics", fn: func(*Loop, *notif) { panic("a bounds bug beneath the decision") }},
			{how: "returns without answering", fn: func(*Loop, *notif) {}},
		} {
			t.Run(tc.name+" "+fail.how, func(t *testing.T) {
				nr := nrFor(t, tc.syscall)
				f := newFake()
				f.put(pathAddr, cstr("/w/keys/secret"))
				l, _ := newTestLoopOpts(t, f, tc.pol(), tc.opts)
				key := dispatchKey{arch: nativeAuditArch(), nr: nr}
				e := l.dispatch[key]
				e.fn = fail.fn
				l.dispatch[key] = e
				l.handle(notifFor(nr, 42, tc.args...))
				got, ok := f.lastResp()
				if !ok {
					t.Fatal("no response")
				}
				if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(refusalErrno) {
					t.Errorf("answered %+v; want a refusal, never CONTINUE", got)
				}
			})
		}
	}
}
