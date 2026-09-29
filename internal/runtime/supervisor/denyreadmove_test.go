// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestDenyReadMoveAtTier2: at tier 2 a deny_read nested in a write entry is
// enforced by the fanotify listener, which matches paths, so a hard link or a rename that gave a file beneath
// it another name let the agent read it with no refusal, while the ledger said refused. The loop now refuses
// such a link or rename itself, a rename of a directory above the entry, and RENAME_EXCHANGE with it at
// either end; a move that stays out of the entry, and every move at tier 1 (where the entry refuses no read),
// is continued.
func TestDenyReadMoveAtTier2(t *testing.T) {
	const pathAddr, path2Addr = 0x10000, 0x11000
	fs := []agent.FSRule{
		{Path: "/work/out", Kind: agent.FSWrite},
		{Path: "/work/out/secret", Kind: agent.FSDenyRead, Unenforced: true},
	}
	for _, tc := range []struct {
		name     string
		tier     backend.Tier
		syscall  string
		from, to string
		flags    uint64
		refused  bool
	}{
		{"link a file out of the entry", backend.TierCgroup, "linkat", "/work/out/secret/key", "/work/out/hl", 0, true},
		{"rename a file out of the entry", backend.TierCgroup, "renameat", "/work/out/secret/key2", "/work/out/mv", 0, true},
		{"rename the entry itself", backend.TierCgroup, "renameat", "/work/out/secret", "/work/out/notsecret", 0, true},
		{"rename a directory above the entry", backend.TierCgroup, "renameat", "/work/out", "/work/out2", 0, true},
		{"exchange with a file in the entry", backend.TierCgroup, "renameat2", "/work/out/a", "/work/out/secret/key", unix.RENAME_EXCHANGE, true},
		{"rename into the entry", backend.TierCgroup, "renameat2", "/work/out/a", "/work/out/secret/a", 0, true},
		{"rename beside the entry", backend.TierCgroup, "renameat", "/work/out/a", "/work/out/b", 0, false},
		{"link out of the entry at tier 1", backend.TierLandlock, "linkat", "/work/out/secret/key", "/work/out/hl", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr(tc.from))
			f.put(path2Addr, cstr(tc.to))
			pol := testPolicy(nil, fs, nil)
			pol.Rules.Tier = tc.tier
			l, sink := newTestLoop(t, f, pol)
			args := []uint64{argCWD, pathAddr, argCWD, path2Addr, tc.flags}
			l.handle(notifFor(nrFor(t, tc.syscall), 42, args...))
			got, _ := f.lastResp()
			refused := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0
			if refused != tc.refused {
				t.Fatalf("response %+v: refused=%v, want %v", got, refused, tc.refused)
			}
			ev := sink.one(t)
			if tc.refused && (ev.Verdict != record.VerdictRefused || ev.Rule != "fs.deny_read[/work/out/secret]") {
				t.Errorf("event %s %s, want refused under the deny_read", ev.Verdict, ev.Rule)
			}
			if !tc.refused && ev.Verdict == record.VerdictRefused {
				t.Errorf("a continued move recorded refused (%s)", ev.Rule)
			}
		})
	}
}
