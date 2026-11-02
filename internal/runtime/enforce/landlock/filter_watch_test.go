// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"path/filepath"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestWatchArmNotifiesTheWatchCalls is R11e on both architectures' tables: with the arm, inotify_add_watch and
// fanotify_mark are notified whatever their arguments, a removal and a whole-mount mark included, so the supervisor
// decides every watch (supervisor R36); without it they are allowed, as they were before (GAPS A10). The calls beside
// them that place no watch (inotify_init1, inotify_rm_watch, fanotify_init) are allowed either way, and the arms after
// this one still see their own syscall: the arm reads no argument, so A keeps the number.
func TestWatchArmNotifiesTheWatchCalls(t *testing.T) {
	atFDCWD := int32(unix.AT_FDCWD)
	cwd := uint64(uint32(atFDCWD)) // an int argument: the kernel reads the low 32 bits
	for _, c := range []struct {
		arch   Arch
		goarch string
	}{{ArchX86_64, "amd64"}, {ArchARM64, "arm64"}} {
		nr, err := testutil.LinuxSyscalls(c.goarch)
		if err != nil {
			t.Fatal(err)
		}
		tab, err := tableFor(c.arch)
		if err != nil {
			t.Fatal(err)
		}
		shapes := [][]uint64{
			{},
			{3, 0x10000, unix.IN_ALL_EVENTS | unix.IN_DONT_FOLLOW},            // inotify_add_watch
			{3, unix.FAN_MARK_ADD, unix.FAN_OPEN, cwd, 0x10000},               // an inode mark by path
			{3, unix.FAN_MARK_ADD | unix.FAN_MARK_MOUNT, unix.FAN_OPEN, 4, 0}, // a mount mark by descriptor
			{3, unix.FAN_MARK_REMOVE, unix.FAN_OPEN, cwd, 0x10000},
			{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)},
		}
		for _, watches := range []bool{false, true} {
			o := filterOpts{abi: minTruncateABI, unixBinds: true, watches: watches}
			want := uint32(retAllow)
			if watches {
				want = retNotify
			}
			for _, name := range []string{"inotify_add_watch", "fanotify_mark"} {
				for _, args := range shapes {
					if got := planeVerdict(t, c.arch, o, nr[name], args...); got != want {
						t.Errorf("%s watches=%v: %s%v = %#x, want %#x", c.arch, watches, name, args, got, want)
					}
				}
			}
			for _, name := range []string{"inotify_init1", "inotify_rm_watch", "fanotify_init"} {
				if got := planeVerdict(t, c.arch, o, nr[name], 3, 1); got != retAllow {
					t.Errorf("%s watches=%v: %s = %#x, want allow: it places no watch", c.arch, watches, name, got)
				}
			}
			// The arms after this one: an addressed sendto and a write-open are notified as before.
			if got := planeVerdict(t, c.arch, o, tab.SendTo, 3, 0, 0, 0, 0x7ffd00001000, 16); got != retNotify {
				t.Errorf("%s watches=%v: an addressed sendto = %#x, want notify", c.arch, watches, got)
			}
			if got := planeVerdict(t, c.arch, o, tab.OpenAt, cwd, 0x10000, unix.O_WRONLY); got != retNotify {
				t.Errorf("%s watches=%v: a write-open = %#x, want notify", c.arch, watches, got)
			}
		}
	}
}

// TestWatchArmNotifiesDnotify is R11e's third watch API on both architectures' tables: with the arm, fcntl(2)'s
// F_NOTIFY, dnotify, is notified whatever its descriptor and mask, a removal included, so the supervisor decides every
// dnotify watch (supervisor R36); without it, it is allowed, as it was before, when a descriptor of a deny_read
// directory, opened to list, watched every access inside it (GAPS A10). Only the command is tested, as the kernel
// reads it, an unsigned int: junk above its low half is still F_NOTIFY, and every other command is allowed with no
// notification. Below Landlock ABI 6 the signal arm sees fcntl first: its F_SETOWN pair is notified as before, and
// F_NOTIFY still reaches this arm. The arms after this one still see their own syscall.
func TestWatchArmNotifiesDnotify(t *testing.T) {
	const dnAccess, dnMultishot = 0x1, 0x80000000
	atFDCWD := int32(unix.AT_FDCWD)
	cwd := uint64(uint32(atFDCWD)) // an int argument: the kernel reads the low 32 bits
	for _, c := range []struct {
		arch   Arch
		goarch string
	}{{ArchX86_64, "amd64"}, {ArchARM64, "arm64"}} {
		nr, err := testutil.LinuxSyscalls(c.goarch)
		if err != nil {
			t.Fatal(err)
		}
		tab, err := tableFor(c.arch)
		if err != nil {
			t.Fatal(err)
		}
		fcntl := nr["fcntl"]
		notified := [][]uint64{
			{3, unix.F_NOTIFY, dnAccess | dnMultishot},
			{3, unix.F_NOTIFY, 0}, // a removal: the supervisor continues it
			{^uint64(0), unix.F_NOTIFY, ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)},
			{3, 0xdead<<32 | unix.F_NOTIFY, dnAccess}, // the kernel's cmd is an unsigned int
		}
		others := []uint64{unix.F_GETFL, unix.F_SETFL, unix.F_GETFD, unix.F_SETFD, unix.F_DUPFD_CLOEXEC, unix.F_SETSIG,
			unix.F_SETLK, unix.F_OFD_SETLK, unix.F_ADD_SEALS, unix.F_NOTIFY + 1, unix.F_NOTIFY << 32}
		for _, signals := range []bool{false, true} {
			for _, watches := range []bool{false, true} {
				o := filterOpts{abi: minTruncateABI, unixBinds: true, watches: watches, signals: signals}
				want := uint32(retAllow)
				if watches {
					want = retNotify
				}
				for _, args := range notified {
					if got := planeVerdict(t, c.arch, o, fcntl, args...); got != want {
						t.Errorf("%s watches=%v signals=%v: fcntl%v = %#x, want %#x", c.arch, watches, signals, args, got, want)
					}
				}
				for _, cmd := range others {
					if got := planeVerdict(t, c.arch, o, fcntl, 3, cmd, 0); got != retAllow {
						t.Errorf("%s watches=%v signals=%v: fcntl(3, %#x) = %#x, want allow: it places no watch", c.arch,
							watches, signals, cmd, got)
					}
				}
				setown := uint32(retAllow)
				if signals {
					setown = retNotify
				}
				if got := planeVerdict(t, c.arch, o, fcntl, 3, unix.F_SETOWN, 1); got != setown {
					t.Errorf("%s watches=%v signals=%v: fcntl F_SETOWN = %#x, want %#x", c.arch, watches, signals, got, setown)
				}
				if got := planeVerdict(t, c.arch, o, tab.SendTo, 3, 0, 0, 0, 0x7ffd00001000, 16); got != retNotify {
					t.Errorf("%s watches=%v signals=%v: an addressed sendto = %#x, want notify", c.arch, watches, signals, got)
				}
				if got := planeVerdict(t, c.arch, o, tab.OpenAt, cwd, 0x10000, unix.O_WRONLY); got != retNotify {
					t.Errorf("%s watches=%v signals=%v: a write-open = %#x, want notify", c.arch, watches, signals, got)
				}
			}
		}
	}
}

// TestPrepareInstallsTheWatchArm is R11e through Prepare: every enforcing table gets the arm, and the filter it
// assembles notifies the three watch calls (fcntl for F_NOTIFY alone). The first version installed it only where the
// table's fs rows withheld a read beneath a deny_read target (withholdsReads), so a table whose only withholding was a
// name entry at a root tier, or a name rule or tego's own state in a run that holds its reads, kept its watches
// undecided, and so would any run where a live block or a read fence entry arrives later: what a run withholds is not
// known when its filter is built. Every table tego run compiles withholds tego's own state anyway (R6a), so the
// predicate saved no run the cost. An observe run's filter (BuildFilter) still has no arm.
func TestPrepareInstallsTheWatchArm(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "w/", "secret/key")
	w := filepath.Join(root, "w")
	tab, err := tableFor(NativeArch())
	if err != nil {
		t.Fatal(err)
	}
	env := agent.NameDenyRule{Literal: ".env", Scopes: []agent.NameScope{{Canonical: w, Spelling: w}}, BuiltIn: true}
	names := func(tier backend.Tier) *agent.RuleTable {
		rt := denyTable(nil, w)
		rt.Tier, rt.NameDeny = tier, []agent.NameDenyRule{env}
		return rt
	}
	heldNames := denyTable(nil, w)
	heldNames.Reads = agent.HeldReads{Mode: agent.ReadsHeld, Names: []agent.NameDenyRule{env}}
	heldOwn := denyTable(nil, w)
	heldOwn.Reads, heldOwn.OwnState = agent.HeldReads{Mode: agent.ReadsHeld}, []string{filepath.Join(root, "secret")}
	for _, tc := range []struct {
		name string
		rt   *agent.RuleTable
	}{
		{"a deny_read target", denyTable([]string{filepath.Join(root, "secret")}, w)},
		{"no deny_read target", denyTable(nil, w)},
		{"only a name entry, at tier cgroup", names(backend.TierCgroup)},
		{"only a name entry, at tier bpflsm", names(backend.TierBPFLSM)},
		{"only a held-read name rule", heldNames},
		{"only tego's own state, reads held", heldOwn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := prepare(t, 7, tc.rt)
			if !h.filterOpts.watches {
				t.Fatal("filterOpts.watches = false, want the arm: only the supervisor refuses a watch")
			}
			for _, s := range tab.Watch {
				if got := planeVerdict(t, NativeArch(), h.filterOpts, s.NR, 3, 0x10000, unix.IN_ALL_EVENTS); got != retNotify {
					t.Errorf("%s = %#x, want notify", s.Name, got)
				}
			}
			if got := planeVerdict(t, NativeArch(), h.filterOpts, tab.Fcntl, 3, unix.F_NOTIFY, 1); got != retNotify {
				t.Errorf("fcntl F_NOTIFY = %#x, want notify", got)
			}
		})
	}
	observe, err := BuildFilter(NativeArch(), false, false)
	if err != nil {
		t.Fatal(err)
	}
	if n := countNotify(t, observe, tab); n != 0 {
		t.Errorf("an observe filter notifies %d watch calls, want none: its supervisor continues every one", n)
	}
}

// countNotify runs the watch calls (fcntl with F_NOTIFY) through insts and counts the ones it notifies.
func countNotify(t *testing.T, insts []bpf.Instruction, tab archTable) int {
	t.Helper()
	vm, err := bpf.NewVM(insts)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	n := 0
	calls := [][]uint64{{uint64(tab.Fcntl), 3, unix.F_NOTIFY, 1}}
	for _, s := range tab.Watch {
		calls = append(calls, []uint64{uint64(s.NR), 3, 0x10000, unix.IN_ALL_EVENTS})
	}
	for _, c := range calls {
		ret, err := vm.Run(seccompData(NativeArch(), uint32(c[0]), c[1:]...))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if uint32(ret) == retNotify {
			n++
		}
	}
	return n
}
