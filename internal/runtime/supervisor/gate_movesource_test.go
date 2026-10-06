// SPDX-License-Identifier: Apache-2.0
//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestGateReadMatchesScoresRenameAndLinkSource is ADR 0041 Step 4 (the review's S8): `fs.read matches` is a
// name predicate, and a rename or a hard link gives the matched file a name it does not match. gateFS scored
// FSRename and FSLink with fs.write predicates only, and returned early when the gate had none, so
// link("secrets/.env", "notes.txt") or rename to the same was allowed and continued, and a later read-open of
// notes.txt read the secret under a name the gate scores 0: a deterministic bypass, no race needed. The end
// that leaves its name (the source, and the destination too under RENAME_EXCHANGE) is now scored with the read
// predicates as well, the two kinds' scores summed (ADR 0007, 2026-10-20). A destination that only receives a name is not a read of
// anything, so an atomic `rename(tmp, x.env)` save stays allowed. A move of a directory renames every file beneath
// it, so under a pattern holding a separator (`secrets/*`) the move of a directory it could match a path beneath is
// scored too: `mv secrets public` was continued at score 0, and a read of public/key then
// read the secret. Only an end that may be a directory has paths beneath it: every end was
// taken to be one, so under a pattern with a wildcard directory component (`*/.env`) every move of a regular file at
// that depth was refused, an editor's atomic save `rename(.out.json.tmp, out.json)` included. An end the decision
// stats (FinalIsDir, not followed) as no directory is matched by its own name alone; one whose stat fails is still
// taken to be a directory.
func TestGateReadMatchesScoresRenameAndLinkSource(t *testing.T) {
	const pathAddr, path2Addr = 0x10000, 0x11000
	fs := []agent.FSRule{{Path: "/work", Kind: agent.FSWrite}}
	for _, tc := range []struct {
		name     string
		syscall  string
		from, to string
		flags    uint64
		refused  bool
		pattern  string   // "*.env" when empty
		dirs     []string // the ends that are directories (FinalIsDir)
	}{
		{"link the secret to another name", "linkat", "/work/secrets/.env", "/work/notes.txt", 0, true, "", nil},
		{"rename the secret to another name", "renameat", "/work/secrets/.env", "/work/notes.txt", 0, true, "", nil},
		{"exchange a file with the secret", "renameat2", "/work/notes.txt", "/work/secrets/.env", unix.RENAME_EXCHANGE, true, "", nil},
		{"rename a file onto a matching name", "renameat", "/work/tmp.123", "/work/config.env", 0, false, "", nil},
		{"rename between unmatched names", "renameat", "/work/a.txt", "/work/b.txt", 0, false, "", nil},
		{"rename the directory a pattern names", "renameat", "/work/secrets", "/work/public", 0, true, "secrets/*", []string{"/work/secrets"}},
		{"rename an ancestor of the directory", "renameat2", "/work/a", "/work/b", 0, true, "a/secrets/*", []string{"/work/a"}},
		{"exchange a directory with the one a pattern names", "renameat2", "/work/public", "/work/secrets", unix.RENAME_EXCHANGE, true, "secrets/*", []string{"/work/public", "/work/secrets"}},
		{"exchange a file with the directory a pattern names", "renameat2", "/work/public", "/work/secrets", unix.RENAME_EXCHANGE, true, "secrets/*", []string{"/work/secrets"}},
		{"rename a directory onto the name a pattern names", "renameat", "/work/public", "/work/secrets", 0, false, "secrets/*", []string{"/work/public"}},
		{"rename a sibling directory", "renameat", "/work/public", "/work/other", 0, false, "secrets/*", []string{"/work/public"}},
		{"rename a directory under a wildcard component", "renameat", "/work/conf", "/work/old", 0, true, "*/.env", []string{"/work/conf"}},
		{"rename a regular file named as the pattern's directory", "renameat", "/work/secrets", "/work/public", 0, false, "secrets/*", nil},
		{"an atomic save under a wildcard component", "renameat", "/work/.out.json.tmp", "/work/out.json", 0, false, "*/.env", nil},
		{"a regular file's move at a wildcard component's depth", "renameat", "/work/notes.txt", "/work/notes.bak", 0, false, "*/.env", nil},
		{"exchange two regular files at that depth", "renameat2", "/work/a.txt", "/work/b.txt", unix.RENAME_EXCHANGE, false, "*/.env", nil},
		{"an end whose stat fails is taken to be a directory", "renameat", "/work/unknown", "/work/x", 0, true, "*/.env", []string{"!/work/unknown"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr(tc.from))
			f.put(path2Addr, cstr(tc.to))
			f.finalDirs, f.finalDirErrs = map[string]bool{}, map[string]error{}
			for _, d := range tc.dirs {
				if d[0] == '!' {
					f.finalDirErrs[d[1:]] = unix.EIO
				} else {
					f.finalDirs[d] = true
				}
			}
			pol := testPolicy(nil, fs, nil)
			pol.Rules.Workdir = "/work"
			pattern := tc.pattern
			if pattern == "" {
				pattern = "*.env"
			}
			pol.Rules.Gate = testGate(t, gate.ReadMatches, pattern, 95)
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(nrFor(t, tc.syscall), 42, argCWD, pathAddr, argCWD, path2Addr, tc.flags))
			got, _ := f.lastResp()
			ev := sink.one(t)
			if !tc.refused {
				if got.Flags == 0 || ev.Verdict == record.VerdictRefused {
					t.Fatalf("response %+v line %+v; want continued", got, ev)
				}
				return
			}
			if got.Flags != 0 || got.Error != -int32(refusalErrno) {
				t.Fatalf("response %+v; want the gate's refusal", got)
			}
			if ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonFSGate || ev.Authority != record.AuthorityGate {
				t.Fatalf("line %+v; want refused fs-gate under the gate's authority", ev)
			}
		})
	}
}
