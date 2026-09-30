// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The supervisor's resolved-path view and the pure evaluator share the root
// mutation bound. A watch can name a deep path without adding mutation rights.
func TestFallbackMutationRootBound(t *testing.T) {
	deep := "/work/" + strings.Repeat("d/", agent.MaxWalk+2) + "file"
	for _, watch := range []bool{false, true} {
		rt := &agent.RuleTable{Tier: backend.TierCgroup, FS: []agent.FSRule{{Kind: agent.FSWrite, Path: "/work", Raw: "/work", Access: agent.AccessWriteSet}}}
		if watch {
			rt.FS = append(rt.FS, agent.FSRule{Kind: agent.FSWatch, Path: deep, Raw: deep})
		}
		tabs := NewAdvisoryTablesFor(rt)
		for _, tc := range []struct {
			op   string
			kind agent.ActionKind
		}{{record.FSUnlink, agent.ActionFSDelete}, {record.FSMkdir, agent.ActionFSMkdir}, {OpMknod, agent.ActionFSWrite}} {
			rule, v, reason := AdvisoryFS(rt, tabs.Resolved, deep, tc.op, 0, false)
			want := NewEvaluator(rt).Evaluate(agent.Action{Kind: tc.kind, Path: deep}, rt.Tier)
			if rule != want.Rule || string(v) != string(want.Verdict) || reason != want.Reason {
				t.Errorf("watch=%v %s: advisory %s/%s/%s, root %+v", watch, tc.op, rule, v, reason, want)
			}
		}
	}
}

// TestIsReadOpenFlags pins which open flags make an open a write: a WriteFlagMask bit (O_TMPFILE carries one) —
// never O_TMPFILE's own bits. O_TMPFILE is __O_TMPFILE|O_DIRECTORY, so testing any of its bits read every opendir (O_DIRECTORY)
// as a write, and on arm64 every O_DIRECT open too.
func TestIsReadOpenFlags(t *testing.T) {
	for _, c := range []struct {
		name  string
		flags int
		read  bool
	}{
		{"rdonly", unix.O_RDONLY, true},
		{"opendir", unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, true},
		{"direct", unix.O_RDONLY | unix.O_DIRECT, true},
		{"path", unix.O_PATH | unix.O_DIRECTORY, true},
		// The kernel drops every access mode, O_CREAT and O_TRUNC from an O_PATH open (build_open_how).
		{"path-wronly", unix.O_PATH | unix.O_WRONLY, true},
		{"path-rdwr-trunc", unix.O_PATH | unix.O_RDWR | unix.O_TRUNC, true},
		{"path-creat", unix.O_PATH | unix.O_CREAT, true},
		{"path-tmpfile", unix.O_PATH | unix.O_TMPFILE | unix.O_WRONLY, true},
		{"wronly", unix.O_WRONLY, false},
		{"rdwr", unix.O_RDWR, false},
		{"creat", unix.O_CREAT, false},
		{"trunc", unix.O_RDONLY | unix.O_TRUNC, false},
		{"tmpfile", unix.O_TMPFILE | unix.O_WRONLY, false},
		{"tmpfile-rdwr", unix.O_TMPFILE | unix.O_RDWR, false},
	} {
		if got := IsRead(record.FSOpen, c.flags); got != c.read {
			t.Errorf("%s: IsRead(open, %#x) = %v, want %v", c.name, c.flags, got, c.read)
		}
	}
}

// TestAdvisoryFSMknodIsNoOpen: the listener refuses a write-open with read-denied;
// a mknod has the supervisor's root mutation refusal instead (ADR 0028 S3).
func TestAdvisoryFSMknodIsNoOpen(t *testing.T) {
	rt := &agent.RuleTable{Tier: backend.TierCgroup, FS: []agent.FSRule{
		{Kind: agent.FSWrite, Path: "/work/out", Raw: "./out/", Resolved: "/work/out", Access: agent.AccessWriteSet},
		{Kind: agent.FSDenyRead, Path: "/work/out/keys", Raw: "./out/keys/", Resolved: "/work/out/keys", Unenforced: true},
	}}
	tabs := NewAdvisoryTables(rt.FS)
	flags := unix.O_CREAT | unix.O_EXCL
	if _, v, _ := AdvisoryFS(rt, tabs.Both, "/work/out/keys/w", record.FSOpen, flags, false); v != record.VerdictRefused {
		t.Fatalf("write-open = %v, want the listener's refusal", v)
	}
	if rule, v, reason := AdvisoryFS(rt, tabs.Both, "/work/out/keys/w", OpMknod, flags, false); v != record.VerdictRefused || reason != record.ReasonWriteOutsideContract {
		t.Errorf("mknod = %s %v %v, want fallback root mutation refusal", rule, v, reason)
	}
	if _, v, reason := AdvisoryFS(rt, tabs.Both, "/tmp/w", OpMknod, flags, false); v != record.VerdictRefused ||
		reason != record.ReasonWriteOutsideContract {
		t.Errorf("mknod outside = %v %v, want refused write-outside-contract", v, reason)
	}
}

// TestAdvisoryFSDirectoryListing: a read-only opendir outside every write entry is a read Landlock allows,
// not a refused write.
func TestAdvisoryFSDirectoryListing(t *testing.T) {
	rt := &agent.RuleTable{Tier: backend.TierLandlock, FS: []agent.FSRule{
		{Kind: agent.FSWrite, Path: "/work", Raw: "/work", Resolved: "/work", Access: agent.AccessWriteSet},
	}}
	tabs := NewAdvisoryTables(rt.FS)
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup} {
		rt.Tier = tier
		_, v, reason := AdvisoryFS(rt, tabs.Both, "/etc", record.FSOpen, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, true)
		if v != record.VerdictAllow {
			t.Errorf("tier %v: opendir /etc = %v %v, want allow", tier, v, reason)
		}
	}
}

// TestOPathIsTheKernels pins OPath to the kernel's O_PATH on the building architecture.
func TestOPathIsTheKernels(t *testing.T) {
	if OPath != unix.O_PATH {
		t.Fatalf("OPath = %#x, want O_PATH %#x", OPath, unix.O_PATH)
	}
}
