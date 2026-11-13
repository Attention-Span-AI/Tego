// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

// A bind alias preserves a slave's character-device identity while changing its
// pathname. A symlink supplies that same stat identity without a privileged
// mount in this unit test. The actual bind and other-session proof is a guest check.
func TestBuiltinTTYOpenUsesDeviceIdentity(t *testing.T) {
	master, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(master) //nolint:errcheck // test terminal
	if err := unix.IoctlSetPointerInt(master, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	slave := "/dev/pts/" + ptyIndex(master)
	var st unix.Stat_t
	if err := unix.Stat(slave, &st); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "terminal")
	if err := os.Symlink(slave, alias); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path string
		own        uint64
		refuse     bool
	}{
		{"canonical-other", slave, 0, true},
		{"alias-other", alias, 0, true},
		// A different devpts instance can reuse a slave's major/minor. An
		// arbitrary alias cannot claim the inherited-terminal exception by rdev.
		{"alias-reusing-own-device-number", alias, st.Rdev, true},
		{"canonical-own", slave, st.Rdev, false},
	} {
		for _, flags := range []int{unix.O_RDONLY, unix.O_WRONLY, unix.O_RDWR | unix.O_NOCTTY} {
			t.Run(tc.name+"/"+openFlagName(flags), func(t *testing.T) {
				f := newFake()
				pol := testPolicy(nil, nil, nil)
				pol.Rules.Record = agent.RecordFull
				pol.Rules.Builtins = &agent.BuiltinRefusals{}
				l, sink := newTestLoop(t, f, pol)
				l.table.Load().ownTTY = tc.own
				n := notifFor(nrFor(t, "openat"), 42, argCWD, 0, uint64(flags))
				q := pathQuery{tid: 42, dirfd: atFDCWD, path: tc.path, joined: tc.path}
				if got := l.builtinTTYOpen(n, l.newReader(n), tc.path, q, flags); got != tc.refuse {
					t.Fatalf("terminal open handled=%v, want refusal=%v", got, tc.refuse)
				}
				if !tc.refuse {
					return
				}
				response, ok := f.lastResp()
				if !ok || response.Error != -int32(unix.EACCES) || response.Flags != 0 {
					t.Fatalf("terminal open response %+v, want EACCES", response)
				}
				if ev := sink.one(t); ev.Rule != agent.BuiltinOtherTTY || ev.Verdict != record.VerdictRefused {
					t.Fatalf("terminal open event %s/%s", ev.Rule, ev.Verdict)
				}
			})
		}
	}
}

func openFlagName(flags int) string {
	switch flags & unix.O_ACCMODE {
	case unix.O_RDONLY:
		return "read"
	case unix.O_WRONLY:
		return "write"
	default:
		return "read-write"
	}
}

func TestOtherTTYDeviceClass(t *testing.T) {
	for _, tc := range []struct {
		name         string
		mode         uint32
		major, minor uint32
		terminal     bool
	}{
		{"regular-file", unix.S_IFREG, 136, 1, false},
		{"first-pts-major", unix.S_IFCHR, 136, 0, true},
		{"last-pts-major", unix.S_IFCHR, 143, 255, true},
		{"after-pts-majors", unix.S_IFCHR, 144, 0, false},
		{"first-console", unix.S_IFCHR, 4, 0, true},
		{"last-console", unix.S_IFCHR, 4, 63, true},
		{"serial-device", unix.S_IFCHR, 4, 64, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := unix.Stat_t{Mode: tc.mode, Rdev: unix.Mkdev(tc.major, tc.minor)}
			if got := otherTTYDevice(st); got != tc.terminal {
				t.Fatalf("device mode=%#o %d:%d terminal=%v, want %v", tc.mode, tc.major, tc.minor, got, tc.terminal)
			}
		})
	}
}
