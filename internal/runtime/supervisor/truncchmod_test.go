// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestTruncateAndChmodLeaveOneLine is R17 for the two fs mutations the filter once left unnotified (ADR 0017's
// truncate and chmod cells, which left no line at tier 1 or tier 2). truncate(2) is Landlock's TRUNCATE right
// from ABI 3: allowed in a write entry, refused outside one, and refused by this loop when it reaches a
// deny_write target (R15c), as an O_TRUNC open is. A mode change is governed by nothing this build loads, so it
// reads allow, named by the entry a modification there is named by; fchmod names the file its descriptor
// holds. That holds at tier bpflsm too until its path_chmod hook is built (enforce-plane step B, TIER3-PLAN T13):
// a refused line there would record a refusal the kernel never made.
//
// Spec: docs/p0/supervisor.md R17.
func TestTruncateAndChmodLeaveOneLine(t *testing.T) {
	const work = "/work/proj"
	fs := []agent.FSRule{{Path: work, Kind: agent.FSWrite, Raw: "./proj/"}}
	deny := []agent.FSRule{{Path: work + "/.git/config", Kind: agent.FSDenyWrite, BuiltIn: true, Unenforced: true, Resolved: work + "/.git/config"}}
	const pathAddr = 0x10000
	for _, tc := range []struct {
		name, syscall, path string
		args                func(nr int32) *notif
		links               map[string]string
		op                  string
		refusedHere         bool
		tier                backend.Tier
		verdict             record.Verdict
		rule                string
		wantPath            string
	}{
		{name: "truncate in the write entry", syscall: "truncate", path: work + "/a.txt",
			args: func(nr int32) *notif { return notifFor(nr, 42, pathAddr, 0) },
			op:   record.FSTruncate, verdict: record.VerdictAllow, rule: "fs.write[./proj/]"},
		{name: "truncate outside it", syscall: "truncate", path: "/etc/passwd",
			args: func(nr int32) *notif { return notifFor(nr, 42, pathAddr, 0) },
			op:   record.FSTruncate, verdict: record.VerdictRefused, rule: ruleUnmatched},
		{name: "truncate a deny_write target", syscall: "truncate", path: work + "/.git/config",
			args: func(nr int32) *notif { return notifFor(nr, 42, pathAddr, 0) },
			op:   record.FSTruncate, refusedHere: true, verdict: record.VerdictRefused, rule: "fs.deny_write[" + work + "/.git/config]"},
		{name: "fchmodat in the write entry", syscall: "fchmodat", path: work + "/a.txt",
			args: func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, 0o755) },
			op:   record.FSChmod, verdict: record.VerdictAllow, rule: "fs.write[./proj/]"},
		{name: "fchmodat outside it is not refused below tier 3", syscall: "fchmodat", path: "/etc/x",
			args: func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, 0o755) },
			op:   record.FSChmod, verdict: record.VerdictAllow, rule: ruleUnmatched},
		{name: "fchmodat outside it is not refused at tier bpflsm before step B", syscall: "fchmodat", path: "/etc/x",
			args: func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, 0o755) },
			tier: backend.TierBPFLSM, op: record.FSChmod, verdict: record.VerdictAllow, rule: ruleUnmatched},
		{name: "fchmodat2 in the write entry", syscall: "fchmodat2", path: work + "/a.txt",
			args: func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, 0o755, unix.AT_SYMLINK_NOFOLLOW) },
			op:   record.FSChmod, verdict: record.VerdictAllow, rule: "fs.write[./proj/]"},
		// fchmodat2's flags are its fourth argument: AT_EMPTY_PATH with an empty pathname names the file the
		// descriptor holds, as fchmod does, and never the mode in the third.
		{name: "fchmodat2 AT_EMPTY_PATH names the descriptor's file", syscall: "fchmodat2", path: "",
			args:  func(nr int32) *notif { return notifFor(nr, 42, 5, pathAddr, 0o755, unix.AT_EMPTY_PATH) },
			links: map[string]string{"/proc/42/fd/5": work + "/b.txt"},
			op:    record.FSChmod, verdict: record.VerdictAllow, rule: "fs.write[./proj/]", wantPath: work + "/b.txt"},
		{name: "fchmod names the descriptor's file", syscall: "fchmod",
			args:  func(nr int32) *notif { return notifFor(nr, 42, 5, 0o755) },
			links: map[string]string{"/proc/42/fd/5": work + "/b.txt"},
			op:    record.FSChmod, verdict: record.VerdictAllow, rule: "fs.write[./proj/]", wantPath: work + "/b.txt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr(tc.path)) // fchmod reads none; fchmodat2 AT_EMPTY_PATH reads an empty one
			for k, v := range tc.links {
				f.links[k] = v
			}
			pol := testPolicy(nil, fs, nil)
			pol.Rules.Tier = backend.TierLandlock
			if tc.tier != "" {
				pol.Rules.Tier = tc.tier
			}
			pol.Rules.Record = agent.RecordFull
			pol.Rules.DenyWrite = deny
			l, sink := newTestLoop(t, f, pol)
			l.handle(tc.args(nrFor(t, tc.syscall)))
			got, _ := f.lastResp()
			if continued := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0; continued == tc.refusedHere {
				t.Fatalf("response = %+v, refused here: want %v", got, tc.refusedHere)
			}
			ev := sink.one(t)
			if ev.Verdict != tc.verdict || ev.Rule != tc.rule {
				t.Errorf("verdict/rule = %s/%s, want %s/%s", ev.Verdict, ev.Rule, tc.verdict, tc.rule)
			}
			var p record.FSPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			want := tc.wantPath
			if want == "" {
				want = tc.path
			}
			if p.Op != tc.op || p.Path != want {
				t.Errorf("payload = %+v, want op %s path %s", p, tc.op, want)
			}
		})
	}
}

// TestChmodUnderThePlaneRefusesADenyWriteTarget is PlaneAttrs (enforce-plane R12, I8): with a decision plane
// deciding the run, the kernel's path_chmod refuses a mode change beneath a deny_write target, so this loop refuses
// such a chmod it is notified of itself, by R15c's predicate, and writes that refusal as the action's one line; a
// chmod elsewhere is continued as allowed, as the plane lets it by. Without a plane nothing changes.
//
// Spec: docs/p0/supervisor.md R17, docs/p0/enforce-plane.md R12.
func TestChmodUnderThePlaneRefusesADenyWriteTarget(t *testing.T) {
	const work = "/work/proj"
	fs := []agent.FSRule{{Path: work, Kind: agent.FSWrite, Raw: "./proj/"}}
	deny := []agent.FSRule{{Path: work + "/.git", Kind: agent.FSDenyWrite, BuiltIn: true, Unenforced: true, Resolved: work + "/.git"}}
	const pathAddr = 0x10000
	for _, tc := range []struct {
		name, path string
		plane      bool
		refused    bool
		rule       string
	}{
		{"under the plane, beneath a deny_write target", work + "/.git/config", true, true, "fs.deny_write[" + work + "/.git]"},
		{"under the plane, in the write entry", work + "/a.txt", true, false, "fs.write[./proj/]"},
		{"under the plane, outside every entry", "/etc/x", true, false, ruleUnmatched},
		{"without a plane, beneath a deny_write target", work + "/.git/config", false, false, "fs.write[./proj/]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr(tc.path))
			pol := testPolicy(nil, fs, nil)
			pol.Rules.Tier = backend.TierCgroup
			pol.Rules.Record = agent.RecordFull
			pol.Rules.DenyWrite = deny
			l, sink := newTestLoop(t, f, pol)
			l.planeAttrs = tc.plane
			l.handle(notifFor(nrFor(t, "fchmodat"), 42, argCWD, pathAddr, 0o755))
			got, _ := f.lastResp()
			if continued := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0; continued == tc.refused {
				t.Fatalf("response = %+v, refused: want %v", got, tc.refused)
			}
			if tc.refused && got.Error != -int32(unix.EACCES) {
				t.Errorf("refusal errno %d, want EACCES, the plane's", got.Error)
			}
			ev := sink.one(t)
			want := record.VerdictAllow
			if tc.refused {
				want = record.VerdictRefused
			}
			if ev.Verdict != want || ev.Rule != tc.rule {
				t.Errorf("verdict/rule = %s/%s, want %s/%s", ev.Verdict, ev.Rule, want, tc.rule)
			}
		})
	}
}
