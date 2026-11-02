// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The watch tests' entries: a write entry over a project, a deny_read directory beside it, one nested in the project
// (left out of the Landlock ruleset at tier landlock, Unenforced), and a deny_read file.
var (
	watchWrite  = agent.FSRule{Path: "/work/proj", Kind: agent.FSWrite}
	watchSSH    = agent.FSRule{Path: "/home/u/.ssh", Kind: agent.FSDenyRead}
	watchNested = agent.FSRule{Path: "/work/proj/secrets", Kind: agent.FSDenyRead, Unenforced: true}
	watchNetrc  = agent.FSRule{Path: "/home/u/.netrc", Kind: agent.FSDenyRead}
)

// watchCase is one watch and what R36 answers it.
type watchCase struct {
	name    string
	syscall string
	path    string // at watchPathAddr, unless unmapped
	args    func(nr int32) *notif
	lands   map[string]string // where FSTarget says a spelling lands
	links   map[string]string // the task's /proc links
	refused bool
	rule    string // the refused line's rule
	target  string // the refused line's target
	// reason is the refused line's reason; "" is read-denied.
	reason record.Reason
	// errno is the refusal's errno; zero is R10's EACCES.
	errno unix.Errno
	// opts are the loop's options beyond the fake kernel (live blocks, tego's own state).
	opts Options
}

const watchPathAddr, watchUnmapped = 0x10000, 0x99000

// atFD is a descriptor number as the task passes it in a register.
func atFD(fd int32) uint64 { return uint64(uint32(fd)) }

// TestWatchBeneathADenyReadTargetIsRefused is supervisor R36 (GAPS A10): an inotify watch, or a fanotify inode mark,
// whose object a read of would be refused is refused with R10's errno and a refused line, op the syscall, target the
// watched name, reason read-denied, rule the deny_read entry; a watch elsewhere is continued with no line. Before, the
// filter notified neither call and a watch on a deny_read directory reported which of its files were opened and
// changed. The object is matched as spelled and where the task's lookup lands (a symlink, a /proc/<pid>/fd link, a
// ".." the walk names), a descriptor's own file by its /proc link (fanotify_mark with a NULL pathname), and a name or
// descriptor this loop could not read is refused under its marker. A whole-mount, filesystem or mount-namespace mark is
// refused wherever it is placed, with the EPERM the kernel answers a caller without the privilege; a removal, a flush
// and a mark the kernel fails for its own reason are continued. The directory that holds a target is not refused: it
// is the listing's, whose names a run sees (SEMANTICS §1).
func TestWatchBeneathADenyReadTargetIsRefused(t *testing.T) {
	ssh, netrc := watchSSH.RuleName(), watchNetrc.RuleName()
	inotify := func(path uint64, mask uint32) func(nr int32) *notif {
		return func(nr int32) *notif { return notifFor(nr, 42, 3, path, uint64(mask)) }
	}
	fanotify := func(flags uint32, dirfd int32, path uint64) func(nr int32) *notif {
		return func(nr int32) *notif { return notifFor(nr, 42, 3, uint64(flags), unix.FAN_OPEN, atFD(dirfd), path) }
	}
	cases := []watchCase{
		{name: "inotify on the target", syscall: "inotify_add_watch", path: "/home/u/.ssh",
			args: inotify(watchPathAddr, unix.IN_ALL_EVENTS), refused: true, rule: ssh, target: "/home/u/.ssh"},
		{name: "inotify beneath it", syscall: "inotify_add_watch", path: "/home/u/.ssh/keys",
			args: inotify(watchPathAddr, unix.IN_OPEN), refused: true, rule: ssh, target: "/home/u/.ssh/keys"},
		{name: "inotify on a target file", syscall: "inotify_add_watch", path: "/home/u/.netrc",
			args: inotify(watchPathAddr, unix.IN_MODIFY), refused: true, rule: netrc, target: "/home/u/.netrc"},
		{name: "inotify through a symlink into it", syscall: "inotify_add_watch", path: "/work/proj/lnk",
			args:  inotify(watchPathAddr, unix.IN_ALL_EVENTS),
			lands: map[string]string{"/work/proj/lnk": "/home/u/.ssh"}, refused: true, rule: ssh, target: "/work/proj/lnk"},
		{name: "inotify through the task's /proc fd link", syscall: "inotify_add_watch", path: "/proc/42/fd/7",
			args:  inotify(watchPathAddr, unix.IN_ALL_EVENTS),
			lands: map[string]string{"/proc/42/fd/7": "/home/u/.ssh/keys"}, refused: true, rule: ssh, target: "/proc/42/fd/7"},
		{name: "inotify named by a walk that climbs into it", syscall: "inotify_add_watch", path: "/work/proj/up/../keys",
			args:  inotify(watchPathAddr, unix.IN_ALL_EVENTS),
			lands: map[string]string{"/work/proj/keys": "/home/u/.ssh/keys"}, refused: true, rule: ssh, target: "/home/u/.ssh/keys"},
		{name: "inotify relative to the cwd", syscall: "inotify_add_watch", path: ".ssh",
			args:  inotify(watchPathAddr, unix.IN_ALL_EVENTS),
			links: map[string]string{"/proc/42/cwd": "/home/u"}, refused: true, rule: ssh, target: "/home/u/.ssh"},
		{name: "inotify on a name that cannot be read", syscall: "inotify_add_watch",
			args: inotify(watchUnmapped, unix.IN_ALL_EVENTS), refused: true, rule: ruleArgsUnreadable},
		{name: "inotify on the directory that holds the target", syscall: "inotify_add_watch", path: "/home/u",
			args: inotify(watchPathAddr, unix.IN_ALL_EVENTS)},
		{name: "inotify on the project", syscall: "inotify_add_watch", path: "/work/proj/src",
			args: inotify(watchPathAddr, unix.IN_ALL_EVENTS)},
		{name: "inotify on a name beside the target", syscall: "inotify_add_watch", path: "/home/u/.sshd",
			args: inotify(watchPathAddr, unix.IN_ALL_EVENTS)},
		{name: "fanotify inode mark on the target", syscall: "fanotify_mark", path: "/home/u/.ssh",
			args: fanotify(unix.FAN_MARK_ADD, unix.AT_FDCWD, watchPathAddr), refused: true, rule: ssh, target: "/home/u/.ssh"},
		{name: "fanotify inode mark relative to a dirfd", syscall: "fanotify_mark", path: "keys",
			args:  fanotify(unix.FAN_MARK_ADD|unix.FAN_MARK_ONLYDIR, 5, watchPathAddr),
			links: map[string]string{"/proc/42/fd/5": "/home/u/.ssh"}, refused: true, rule: ssh, target: "/home/u/.ssh/keys"},
		{name: "fanotify mark of a descriptor's own file", syscall: "fanotify_mark",
			args:  fanotify(unix.FAN_MARK_ADD, 5, 0),
			links: map[string]string{"/proc/42/fd/5": "/home/u/.ssh"}, refused: true, rule: ssh, target: "/home/u/.ssh"},
		{name: "fanotify mark of a descriptor the task does not hold", syscall: "fanotify_mark",
			args: fanotify(unix.FAN_MARK_ADD, 5, 0)},
		{name: "fanotify mark of a socket's descriptor", syscall: "fanotify_mark",
			args: fanotify(unix.FAN_MARK_ADD, 5, 0), links: map[string]string{"/proc/42/fd/5": "socket:[1234]"}},
		{name: "fanotify mark of AT_FDCWD with no name", syscall: "fanotify_mark",
			args: fanotify(unix.FAN_MARK_ADD, unix.AT_FDCWD, 0), links: map[string]string{"/proc/42/cwd": "/home/u/.ssh"}},
		{name: "fanotify mount mark", syscall: "fanotify_mark", path: "/work/proj",
			args:    fanotify(unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, unix.AT_FDCWD, watchPathAddr),
			refused: true, rule: ruleWatchWhole, target: "/work/proj", errno: unix.EPERM},
		{name: "fanotify filesystem mark of a descriptor", syscall: "fanotify_mark",
			args:  fanotify(unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM, 5, 0),
			links: map[string]string{"/proc/42/fd/5": "/tmp"}, refused: true, rule: ruleWatchWhole, target: "/tmp",
			errno: unix.EPERM},
		{name: "fanotify mount-namespace mark", syscall: "fanotify_mark", path: "/proc/self/ns/mnt",
			args:    fanotify(unix.FAN_MARK_ADD|unix.FAN_MARK_MNTNS, unix.AT_FDCWD, watchPathAddr),
			refused: true, rule: ruleWatchWhole, target: "/proc/self/ns/mnt", errno: unix.EPERM},
		{name: "fanotify mount mark of AT_FDCWD with no name", syscall: "fanotify_mark",
			args: fanotify(unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, unix.AT_FDCWD, 0), links: map[string]string{"/proc/42/cwd": "/work/proj"}},
		{name: "fanotify removal of a mark on the target", syscall: "fanotify_mark", path: "/home/u/.ssh",
			args: fanotify(unix.FAN_MARK_REMOVE, unix.AT_FDCWD, watchPathAddr)},
		{name: "fanotify flush", syscall: "fanotify_mark", args: fanotify(unix.FAN_MARK_FLUSH, unix.AT_FDCWD, 0)},
		{name: "fanotify add and remove at once", syscall: "fanotify_mark", path: "/home/u/.ssh",
			args: fanotify(unix.FAN_MARK_ADD|unix.FAN_MARK_REMOVE, unix.AT_FDCWD, watchPathAddr)},
		{name: "fanotify inode mark on the project", syscall: "fanotify_mark", path: "/work/proj",
			args: fanotify(unix.FAN_MARK_ADD, unix.AT_FDCWD, watchPathAddr)},
	}
	for _, mode := range []agent.RecordMode{agent.RecordSummary, agent.RecordOff} {
		for _, tc := range cases {
			t.Run(string(mode)+"/"+tc.name, func(t *testing.T) {
				f := newFake()
				pol := testPolicy(nil, []agent.FSRule{watchWrite, watchSSH, watchNested, watchNetrc}, nil)
				pol.Rules.Tier, pol.Record = backend.TierLandlock, mode
				runWatchCase(t, f, pol, tc)
			})
		}
	}
}

// dnotify's event bits (linux/fcntl.h), which golang.org/x/sys/unix does not define.
const (
	dnAccess = 0x1
	dnModify = 0x2
)

// dnotifyArgs is fcntl(fd, F_NOTIFY, mask) as the task passes it in registers.
func dnotifyArgs(fd int32, mask uint64) func(nr int32) *notif {
	return func(nr int32) *notif { return notifFor(nr, 42, atFD(fd), unix.F_NOTIFY, mask) }
}

// TestDnotifyOfADenyReadTargetIsRefused is supervisor R36's third watch API (GAPS A10): dnotify, fcntl(fd, F_NOTIFY,
// mask), watches the directory fd holds, and a descriptor of a deny_read directory, which a tier-1 ruleset lets the
// agent open to list, reported every access, change, creation and rename inside the target. Before, no filter
// notified F_NOTIFY (the signal arm below Landlock ABI 6 notifies only F_SETOWN's pair), and the handler continued
// every fcntl command but that pair. A dnotify watch is decided on the descriptor's own file, as a fanotify mark of a
// descriptor is: one at or beneath a
// target is refused EACCES with a refused line, op fcntl, target the directory, rule the entry; one elsewhere, and the
// directory that holds a target (the listing's, SEMANTICS §1), is continued with no line. A mask with no event bit
// removes the descriptor's watches and adds none, and a descriptor the task does not hold or a number past INT_MAX
// names nothing (the kernel's EBADF, never the cwd): each is continued. The kernel reads mask and fd as unsigned ints,
// so junk above either's low half changes nothing. Every other fcntl command is still answerSignal's.
func TestDnotifyOfADenyReadTargetIsRefused(t *testing.T) {
	ssh := watchSSH.RuleName()
	const all = dnAccess | dnModify | dnMultishot
	cases := []watchCase{
		{name: "dnotify of the target", syscall: "fcntl", args: dnotifyArgs(5, all),
			links: map[string]string{"/proc/42/fd/5": "/home/u/.ssh"}, refused: true, rule: ssh, target: "/home/u/.ssh"},
		{name: "dnotify of a directory beneath it", syscall: "fcntl", args: dnotifyArgs(5, dnAccess),
			links: map[string]string{"/proc/42/fd/5": "/home/u/.ssh/keys"}, refused: true, rule: ssh, target: "/home/u/.ssh/keys"},
		{name: "dnotify with junk above the mask's low half", syscall: "fcntl", args: dnotifyArgs(5, 0xdead<<32|dnAccess),
			links: map[string]string{"/proc/42/fd/5": "/home/u/.ssh"}, refused: true, rule: ssh, target: "/home/u/.ssh"},
		{name: "dnotify of a descriptor numbered past the low half", syscall: "fcntl",
			args:  func(nr int32) *notif { return notifFor(nr, 42, 1<<32|5, unix.F_NOTIFY, dnAccess) },
			links: map[string]string{"/proc/42/fd/5": "/home/u/.ssh"}, refused: true, rule: ssh, target: "/home/u/.ssh"},
		{name: "dnotify of the directory beside it", syscall: "fcntl", args: dnotifyArgs(5, all),
			links: map[string]string{"/proc/42/fd/5": "/work/proj/src"}},
		{name: "dnotify of the directory that holds the target", syscall: "fcntl", args: dnotifyArgs(5, all),
			links: map[string]string{"/proc/42/fd/5": "/home/u"}},
		{name: "dnotify removal on the target", syscall: "fcntl", args: dnotifyArgs(5, 0),
			links: map[string]string{"/proc/42/fd/5": "/home/u/.ssh"}},
		{name: "dnotify of DN_MULTISHOT alone on the target", syscall: "fcntl", args: dnotifyArgs(5, dnMultishot),
			links: map[string]string{"/proc/42/fd/5": "/home/u/.ssh"}},
		{name: "dnotify removal with junk above the mask", syscall: "fcntl", args: dnotifyArgs(5, 0xdead<<32|dnMultishot),
			links: map[string]string{"/proc/42/fd/5": "/home/u/.ssh"}},
		{name: "dnotify of a descriptor the task does not hold", syscall: "fcntl", args: dnotifyArgs(5, all)},
		{name: "dnotify of a socket's descriptor", syscall: "fcntl", args: dnotifyArgs(5, all),
			links: map[string]string{"/proc/42/fd/5": "socket:[1234]"}},
		{name: "dnotify of a negative descriptor", syscall: "fcntl", args: dnotifyArgs(-1, all)},
		{name: "dnotify of AT_FDCWD is not the cwd", syscall: "fcntl", args: dnotifyArgs(unix.AT_FDCWD, all),
			links: map[string]string{"/proc/42/cwd": "/home/u/.ssh"}},
		{name: "another fcntl command on the target's descriptor", syscall: "fcntl",
			args:  func(nr int32) *notif { return notifFor(nr, 42, 5, unix.F_GETFL, 0) },
			links: map[string]string{"/proc/42/fd/5": "/home/u/.ssh"}},
	}
	for _, mode := range []agent.RecordMode{agent.RecordSummary, agent.RecordOff} {
		for _, tc := range cases {
			t.Run(string(mode)+"/"+tc.name, func(t *testing.T) {
				f := newFake()
				pol := testPolicy(nil, []agent.FSRule{watchWrite, watchSSH, watchNested, watchNetrc}, nil)
				pol.Rules.Tier, pol.Record = backend.TierLandlock, mode
				runWatchCase(t, f, pol, tc)
			})
		}
	}
}

// runWatchCase sends one watch through a loop over pol and checks its answer and its line.
func runWatchCase(t *testing.T, f *fakeKernel, pol *Policy, tc watchCase) {
	t.Helper()
	nr := nrFor(t, tc.syscall)
	if tc.path != "" {
		f.put(watchPathAddr, cstr(tc.path))
	}
	for k, v := range tc.lands {
		f.fsTargets[k] = v
	}
	for k, v := range tc.links {
		f.links[k] = v
	}
	l, sink := newTestLoopOpts(t, f, pol, tc.opts)
	l.handle(tc.args(nr))
	got, ok := f.lastResp()
	if !ok {
		t.Fatal("no response")
	}
	if !tc.refused {
		if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
			t.Fatalf("response = %+v, want CONTINUE: nothing here is withheld", got)
		}
		if evs := sink.all(); len(evs) != 0 {
			t.Errorf("%d lines for a continued watch, want none: %+v", len(evs), evs)
		}
		return
	}
	errno := tc.errno
	if errno == 0 {
		errno = unix.EACCES
	}
	if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(errno) {
		t.Fatalf("response = %+v, want %v: no Landlock or plane hook refuses a watch, so only this loop can", got, errno)
	}
	reason := tc.reason
	if reason == "" {
		reason = record.ReasonReadDenied
	}
	ev := sink.one(t)
	var p record.RefusedPayload
	if err := ev.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	if ev.Kind != record.KindRefused || ev.Rule != tc.rule || ev.Reason != reason ||
		p.Op != tc.syscall || p.Target != tc.target || p.Rule != tc.rule || p.Reason != reason {
		t.Errorf("line = %s rule=%s reason=%s %+v, want refused op=%s target=%q rule=%s reason=%s",
			ev.Kind, ev.Rule, ev.Reason, p, tc.syscall, tc.target, tc.rule, reason)
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("refused line does not validate: %v", err)
	}
}

// TestWatchFollowsTheKernelsLookup: the object a watch is decided on is the one its own lookup reaches. inotify's
// IN_DONT_FOLLOW and fanotify's FAN_MARK_DONT_FOLLOW watch a final symlink itself, so the walk does not follow it;
// without them it does.
func TestWatchFollowsTheKernelsLookup(t *testing.T) {
	for _, tc := range []struct {
		name, syscall string
		args          func(nr int32) *notif
		nofollow      bool
	}{
		{"inotify", "inotify_add_watch", func(nr int32) *notif { return notifFor(nr, 42, 3, watchPathAddr, unix.IN_OPEN) }, false},
		{"inotify IN_DONT_FOLLOW", "inotify_add_watch", func(nr int32) *notif {
			return notifFor(nr, 42, 3, watchPathAddr, unix.IN_OPEN|unix.IN_DONT_FOLLOW)
		}, true},
		{"fanotify", "fanotify_mark", func(nr int32) *notif {
			return notifFor(nr, 42, 3, unix.FAN_MARK_ADD, unix.FAN_OPEN, atFD(unix.AT_FDCWD), watchPathAddr)
		}, false},
		{"fanotify FAN_MARK_DONT_FOLLOW", "fanotify_mark", func(nr int32) *notif {
			return notifFor(nr, 42, 3, unix.FAN_MARK_ADD|unix.FAN_MARK_DONT_FOLLOW, unix.FAN_OPEN, atFD(unix.AT_FDCWD), watchPathAddr)
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(watchPathAddr, cstr("/work/proj/lnk"))
			f.fsTargets["/work/proj/lnk"] = "/work/proj/src" // a landing the spelling does not name: the walk is asked
			pol := testPolicy(nil, []agent.FSRule{watchWrite, watchSSH}, nil)
			pol.Rules.Tier = backend.TierLandlock
			l, _ := newTestLoop(t, f, pol)
			l.handle(tc.args(nrFor(t, tc.syscall)))
			if len(f.fsQueries) == 0 {
				t.Fatal("the watch's path was never walked")
			}
			if q := f.fsQueries[len(f.fsQueries)-1]; q.nofollow != tc.nofollow || q.parent || q.create {
				t.Errorf("walk = nofollow %t parent %t create %t, want nofollow %t: the watch's own lookup", q.nofollow, q.parent,
					q.create, tc.nofollow)
			}
		})
	}
}

// TestWatchDecidesAsTheRunWithholdsReads: a watch is refused exactly where a read of its object is. A deny_read nested
// in a write entry withholds nothing at tier landlock while the run reads direct, since the Landlock ruleset leaves it
// out (R15), so its watch is continued there; it is withheld at a root tier, whose kernel refuses the read, and where
// the run holds its reads (ADR 0069 D3 (a)), so its watch is refused there under its rule. A directory named as a .env
// file is not one, since a name rule covers files alone, and a file of that name is.
func TestWatchDecidesAsTheRunWithholdsReads(t *testing.T) {
	nested := watchNested.RuleName()
	env := agent.NameDenyRule{Literal: ".env", Scopes: []agent.NameScope{{Canonical: "/work/proj", Spelling: "/work/proj"}},
		BuiltIn: true}
	for _, tc := range []struct {
		name    string
		tier    backend.Tier
		reads   agent.ReadsMode
		path    string
		dir     bool
		refused bool
		rule    string
	}{
		{name: "nested, tier landlock, reads direct", tier: backend.TierLandlock, reads: agent.ReadsDirect,
			path: "/work/proj/secrets"},
		{name: "nested, tier landlock, reads held", tier: backend.TierLandlock, reads: agent.ReadsHeld,
			path: "/work/proj/secrets/api", refused: true, rule: nested},
		{name: "nested, tier cgroup", tier: backend.TierCgroup, reads: agent.ReadsDirect,
			path: "/work/proj/secrets", refused: true, rule: nested},
		{name: "nested, tier bpflsm", tier: backend.TierBPFLSM, reads: agent.ReadsDirect,
			path: "/work/proj/secrets", refused: true, rule: nested},
		{name: "a .env file made during a held run", tier: backend.TierLandlock, reads: agent.ReadsHeld,
			path: "/work/proj/app/.env", refused: true, rule: env.RuleName(0)},
		{name: "a directory named .env in a held run", tier: backend.TierLandlock, reads: agent.ReadsHeld,
			path: "/work/proj/app/.env", dir: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.finalDirs = map[string]bool{tc.path: tc.dir}
			pol := testPolicy(nil, []agent.FSRule{watchWrite, watchSSH, watchNested}, nil)
			pol.Rules.Tier = tc.tier
			pol.Rules.Reads = agent.HeldReads{Mode: tc.reads, Names: []agent.NameDenyRule{env}}
			runWatchCase(t, f, pol, watchCase{syscall: "inotify_add_watch", path: tc.path,
				args:    func(nr int32) *notif { return notifFor(nr, 42, 3, watchPathAddr, unix.IN_ALL_EVENTS) },
				refused: tc.refused, rule: tc.rule, target: tc.path})
		})
	}
}

// TestWatchFollowsEveryReadRefusal is R36's "a watch is refused where a read-open of its object is" past the read
// verdict's deny_read entries (review of 2026-11-02: the first version asked only fsVerdict, and only for read-denied,
// and the held-read floor's (a) and (c)). Each case is a refusal a read of the object meets, and its watch was
// continued: a file a name entry covers at tier bpflsm, whose plane refuses its read by name as tier cgroup's listener
// does (ADR 0043 D7; not at tier landlock, whose reads no name entry reaches, nor a directory of that name); a name
// entry's climb that cannot decide within agent.MaxWalk, which the read is refused for path-unresolved under unmatched
// at both root tiers; tego's own state in a run that holds its reads (ADR 0069 D3 (d)), the table's and the launcher's
// runtime parent (Options.OwnState), but not the run's own runtime directory, and not in a run that reads direct,
// where no floor is asked; and a live read or path block, or an Adjustable run's read fence entry not lifted, but not
// a write block, which no read meets.
func TestWatchFollowsEveryReadRefusal(t *testing.T) {
	env := agent.NameDenyRule{Literal: ".env", Prefix: true,
		Scopes: []agent.NameScope{{Canonical: "/work/proj", Spelling: "/work/proj"}}, BuiltIn: true}
	deep := "/work/proj" + strings.Repeat("/d", agent.MaxWalk+2) + "/.env"
	const parent, own = "/run/user/1000/tego", "/home/u/.tego"
	blocks := func(entries ...liveblock.Entry) Options {
		s := liveblock.CompileEntries(entries, 1, liveblock.Resolved{})
		return Options{LiveBlocks: func() *liveblock.Set { return s }}
	}
	private := "/work/proj/private"
	for _, tc := range []struct {
		name    string
		tier    backend.Tier
		reads   agent.ReadsMode
		names   bool // the table has the name entry env (ADR 0043)
		path    string
		dir     bool
		opts    Options
		refused bool
		rule    string
		reason  record.Reason
	}{
		{name: "a name entry's file at tier bpflsm", tier: backend.TierBPFLSM, names: true,
			path: "/work/proj/app/.env.local", refused: true, rule: env.RuleName(0)},
		{name: "a name entry's file at tier cgroup", tier: backend.TierCgroup, names: true,
			path: "/work/proj/app/.env.local", refused: true, rule: env.RuleName(0)},
		{name: "a name entry's file at tier landlock", tier: backend.TierLandlock, names: true,
			path: "/work/proj/app/.env.local"},
		{name: "a directory of a name entry's name at tier bpflsm", tier: backend.TierBPFLSM, names: true,
			path: "/work/proj/app/.env.d", dir: true},
		{name: "a name entry's climb past the bound at tier cgroup", tier: backend.TierCgroup, names: true, path: deep,
			refused: true, rule: agent.UnmatchedRule, reason: record.ReasonPathUnresolved},
		{name: "a name entry's climb past the bound at tier bpflsm", tier: backend.TierBPFLSM, names: true, path: deep,
			refused: true, rule: agent.UnmatchedRule, reason: record.ReasonPathUnresolved},
		{name: "tego's own state, reads held", tier: backend.TierLandlock, reads: agent.ReadsHeld, path: own + "/runs",
			refused: true, rule: "fs.deny_read[" + own + "]"},
		{name: "tego's own state, reads direct", tier: backend.TierLandlock, reads: agent.ReadsDirect, path: own + "/runs"},
		{name: "another run's runtime directory, reads held", tier: backend.TierLandlock, reads: agent.ReadsHeld,
			path: parent + "/other", dir: true, opts: Options{OwnState: []string{parent}, RuntimeDir: parent + "/this"},
			refused: true, rule: "fs.deny_read[" + parent + "]"},
		{name: "the run's own runtime directory, reads held", tier: backend.TierLandlock, reads: agent.ReadsHeld,
			path: parent + "/this", dir: true, opts: Options{OwnState: []string{parent}, RuntimeDir: parent + "/this"}},
		{name: "a live read block", tier: backend.TierLandlock, path: private + "/notes",
			opts:    blocks(liveblock.Entry{Kind: liveblock.KindRead, Value: private}),
			refused: true, rule: liveblock.Rule(liveblock.KindRead, private)},
		{name: "a live path block", tier: backend.TierLandlock, path: private + "/notes",
			opts:    blocks(liveblock.Entry{Kind: liveblock.KindPath, Value: private}),
			refused: true, rule: liveblock.Rule(liveblock.KindPath, private)},
		{name: "a read fence entry not lifted", tier: backend.TierLandlock, reads: agent.ReadsHeld, path: private,
			dir: true, opts: blocks(liveblock.Entry{Kind: liveblock.KindRead, Value: private, Fence: true}),
			refused: true, rule: liveblock.FenceRule(liveblock.KindRead, private)},
		{name: "a live write block", tier: backend.TierLandlock, path: private + "/notes",
			opts: blocks(liveblock.Entry{Kind: liveblock.KindWrite, Value: private})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.finalDirs = map[string]bool{tc.path: tc.dir}
			pol := testPolicy(nil, []agent.FSRule{watchWrite, watchSSH}, nil)
			pol.Rules.Tier = tc.tier
			pol.Rules.Reads = agent.HeldReads{Mode: tc.reads}
			pol.Rules.OwnState = []string{own}
			if tc.names {
				pol.Rules.NameDeny = []agent.NameDenyRule{env}
			}
			runWatchCase(t, f, pol, watchCase{syscall: "inotify_add_watch", path: tc.path,
				args:    func(nr int32) *notif { return notifFor(nr, 42, 3, watchPathAddr, unix.IN_ALL_EVENTS) },
				refused: tc.refused, rule: tc.rule, reason: tc.reason, target: tc.path, opts: tc.opts})
		})
	}
}

// TestWatchOfAnAskReadEntryIsRefused: a read beneath an fs.ask_read entry is held for a person (SEMANTICS §6), and a
// watch there has no answer to wait for: it is refused, as a deny_read's is, under the entry's rule.
func TestWatchOfAnAskReadEntryIsRefused(t *testing.T) {
	notes := t.TempDir() // an ask scope is pinned when the loop starts, so it exists
	ask := agent.FSRule{Path: notes, Resolved: notes, Kind: agent.FSDenyRead, AskRead: true}
	pol := testPolicy(nil, []agent.FSRule{watchWrite, ask}, nil)
	pol.Rules.Tier = backend.TierLandlock
	runWatchCase(t, newFake(), pol, watchCase{syscall: "inotify_add_watch", path: notes + "/today.md",
		args:    func(nr int32) *notif { return notifFor(nr, 42, 3, watchPathAddr, unix.IN_MODIFY) },
		refused: true, rule: ask.RuleName(), target: notes + "/today.md"})
}

// TestWatchOfAnUnreadableDescriptorIsRefused: a non-dumpable task's /proc links are ptrace-guarded at tier 1, so the
// file its descriptor holds cannot be read, and a fanotify mark of that descriptor's own file, or a dnotify watch of
// it, is refused fd-unreadable: where it lands is unknown and may be a target (R5). Its pathname form is refused
// args-unreadable, as its memory cannot be read either.
func TestWatchOfAnUnreadableDescriptorIsRefused(t *testing.T) {
	for _, tc := range []watchCase{
		{syscall: "fanotify_mark", args: func(nr int32) *notif {
			return notifFor(nr, 42, 3, unix.FAN_MARK_ADD, unix.FAN_OPEN, 5, 0)
		}, refused: true, rule: ruleFDUnreadable},
		{syscall: "fcntl", args: dnotifyArgs(5, dnAccess|dnMultishot), refused: true, rule: ruleFDUnreadable},
	} {
		t.Run(tc.syscall, func(t *testing.T) {
			f := newFake()
			f.dupErr = unix.EPERM // the fake of a non-dumpable task: its fd links read EACCES
			f.links["/proc/42/fd/5"] = "/home/u/.ssh"
			pol := testPolicy(nil, []agent.FSRule{watchWrite, watchSSH}, nil)
			pol.Rules.Tier = backend.TierLandlock
			runWatchCase(t, f, pol, tc)
		})
	}
}

// TestWatchInAnObserveRunIsContinued: an observe run enforces nothing (R30), so a watch it is notified of is continued
// and no refused line is written; its filter carries no watch arm in the first place (BuildFilter).
func TestWatchInAnObserveRunIsContinued(t *testing.T) {
	for _, tc := range []watchCase{
		{syscall: "inotify_add_watch", path: "/home/u/.ssh",
			args: func(nr int32) *notif { return notifFor(nr, 42, 3, watchPathAddr, unix.IN_ALL_EVENTS) }},
		{syscall: "fcntl", args: dnotifyArgs(5, dnAccess|dnMultishot), links: map[string]string{"/proc/42/fd/5": "/home/u/.ssh"}},
	} {
		t.Run(tc.syscall, func(t *testing.T) {
			f := newFake()
			pol := testPolicy(nil, []agent.FSRule{watchWrite, watchSSH}, nil)
			pol.Rules.Tier, pol.Observe = backend.TierLandlock, true
			runWatchCase(t, f, pol, tc)
		})
	}
}
