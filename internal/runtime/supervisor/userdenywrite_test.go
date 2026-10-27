// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestUserDenyWriteRefusedBySupervisor is R15c for an fs.deny_write entry (ADR 0071): beneath a write entry, a
// modification at or beneath the entry, matched on its copied pathname as spelled or where the task's lookup lands, is
// refused by this loop with R10's errno and recorded under the entry's rule, fs.deny_write[<entry as declared>]: a
// write-open, a creat, an unlink, a mkdir, a symlink, a hard link out of it, and a rename into it. A write entry
// strictly beneath the entry reopens its subtree (nearest wins): a write and a rename there are continued under that
// write entry's rule.
func TestUserDenyWriteRefusedBySupervisor(t *testing.T) {
	const work = "/work/proj"
	const deploy, tmp = work + "/deploy", work + "/deploy/tmp"
	fs := []agent.FSRule{{Path: work, Kind: agent.FSWrite, Resolved: work}, {Path: tmp, Kind: agent.FSWrite, Raw: "./deploy/tmp/", Resolved: tmp}}
	deny := []agent.FSRule{{Path: deploy, Kind: agent.FSDenyWrite, Raw: "./deploy/", Unenforced: true, Resolved: deploy}}
	const rule = "fs.deny_write[./deploy/]"
	const pathAddr, path2Addr = 0x10000, 0x11000
	tests := []struct {
		name, syscall, path, path2 string
		args                       func(nr int32) *notif
		lands                      map[string]string
		refused                    bool
		wantRule                   string
		wantRsn                    record.Reason
	}{
		{name: "write a file in it", syscall: "openat", path: deploy + "/a",
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, unix.O_WRONLY|unix.O_TRUNC) },
			refused: true, wantRule: rule, wantRsn: record.ReasonWriteOutsideContract},
		{name: "creat in it", syscall: "creat", path: deploy + "/new",
			args:    func(nr int32) *notif { return notifFor(nr, 42, pathAddr, 0o644) },
			refused: true, wantRule: rule, wantRsn: record.ReasonWriteOutsideContract},
		{name: "unlink in it", syscall: "unlinkat", path: deploy + "/a",
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, 0) },
			refused: true, wantRule: rule, wantRsn: record.ReasonDeleteOutsideContract},
		{name: "mkdir in it", syscall: "mkdirat", path: deploy + "/d",
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, 0o755) },
			refused: true, wantRule: rule, wantRsn: record.ReasonMkdirOutsideContract},
		{name: "a symlink planted in it", syscall: "symlinkat", path: "/tmp/payload", path2: deploy + "/b",
			args:    func(nr int32) *notif { return notifFor(nr, 42, pathAddr, argCWD, path2Addr) },
			refused: true, wantRule: rule, wantRsn: record.ReasonWriteOutsideContract},
		{name: "a hard link out of it", syscall: "linkat", path: deploy + "/a", path2: work + "/alias",
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, argCWD, path2Addr, 0) },
			refused: true, wantRule: rule, wantRsn: record.ReasonWriteOutsideContract},
		{name: "a rename into it", syscall: "renameat", path: work + "/x", path2: deploy + "/x",
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, argCWD, path2Addr) },
			refused: true, wantRule: rule, wantRsn: record.ReasonRenameOutsideContract},
		{name: "a symlink the agent made into it", syscall: "openat", path: work + "/innocent",
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, unix.O_WRONLY|unix.O_CREAT) },
			lands:   map[string]string{work + "/innocent": deploy + "/c"},
			refused: true, wantRule: rule, wantRsn: record.ReasonWriteOutsideContract},
		{name: "a write in the reopened subtree", syscall: "openat", path: tmp + "/x",
			args:     func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, unix.O_WRONLY|unix.O_CREAT) },
			wantRule: "fs.write[./deploy/tmp/]"},
		{name: "a rename within the reopened subtree", syscall: "renameat", path: tmp + "/x", path2: tmp + "/y",
			args:     func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, argCWD, path2Addr) },
			wantRule: "fs.write[./deploy/tmp/]"},
		{name: "a write beside it", syscall: "openat", path: work + "/ok.txt",
			args:     func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, unix.O_WRONLY|unix.O_CREAT) },
			wantRule: "fs.write[" + work + "]"},
		// The reopening write entry's own name is the entry's, as the plane keys it. Moving it away, moving
		// an object of the agent's onto it, and making it anew (a mkdir, a symlink, an exclusive create, a mknod, a hard
		// link's new name) are refused; removing it, and writing what it names, are the write entry's.
		{name: "a rename of the reopened name away", syscall: "renameat", path: tmp, path2: work + "/t2",
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, argCWD, path2Addr) },
			refused: true, wantRule: rule, wantRsn: record.ReasonRenameOutsideContract},
		{name: "a rename onto the reopened name", syscall: "renameat", path: work + "/s", path2: tmp,
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, argCWD, path2Addr) },
			refused: true, wantRule: rule, wantRsn: record.ReasonRenameOutsideContract},
		{name: "a mkdir of the reopened name", syscall: "mkdirat", path: tmp,
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, 0o755) },
			refused: true, wantRule: rule, wantRsn: record.ReasonMkdirOutsideContract},
		{name: "a symlink at the reopened name", syscall: "symlinkat", path: ".", path2: tmp,
			args:    func(nr int32) *notif { return notifFor(nr, 42, pathAddr, argCWD, path2Addr) },
			refused: true, wantRule: rule, wantRsn: record.ReasonWriteOutsideContract},
		{name: "an exclusive create of the reopened name", syscall: "openat", path: tmp,
			args: func(nr int32) *notif {
				return notifFor(nr, 42, argCWD, pathAddr, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
			},
			refused: true, wantRule: rule, wantRsn: record.ReasonWriteOutsideContract},
		{name: "a mknod at the reopened name", syscall: "mknodat", path: tmp,
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, unix.S_IFIFO|0o644, 0) },
			refused: true, wantRule: rule, wantRsn: record.ReasonWriteOutsideContract},
		{name: "a hard link made at the reopened name", syscall: "linkat", path: work + "/ok.txt", path2: tmp,
			args:    func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, argCWD, path2Addr, 0) },
			refused: true, wantRule: rule, wantRsn: record.ReasonWriteOutsideContract},
		{name: "a removal of the reopened name", syscall: "unlinkat", path: tmp,
			args:     func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, unix.AT_REMOVEDIR) },
			wantRule: "fs.write[" + work + "]"}, // a removal's line names the write entry over its directory
		{name: "a hard link of a file in the reopened subtree", syscall: "linkat", path: tmp + "/x", path2: work + "/alias",
			args:     func(nr int32) *notif { return notifFor(nr, 42, argCWD, pathAddr, argCWD, path2Addr, 0) },
			wantRule: "fs.write[./deploy/tmp/]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nr := nrFor(t, tc.syscall)
			f := newFake()
			f.put(pathAddr, cstr(tc.path))
			if tc.path2 != "" {
				f.put(path2Addr, cstr(tc.path2))
			}
			for k, v := range tc.lands {
				f.fsTargets[k] = v
			}
			pol := testPolicy(nil, fs, nil)
			pol.Rules.DenyWrite = deny
			pol.Record = agent.RecordSummary
			l, sink := newTestLoop(t, f, pol)
			l.handle(tc.args(nr))
			got, ok := f.lastResp()
			if !ok {
				t.Fatal("no response")
			}
			checkDenyWrite(t, got, sink.one(t), tc.refused, tc.wantRule, tc.wantRsn, nil)
		})
	}
}
