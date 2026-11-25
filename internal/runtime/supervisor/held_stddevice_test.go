// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestStandardDeviceRuleIsTheObjectsNotTheNames is the held open's half of ADR 0158: the verdict is taken on the
// pinned object's path, and a write the product's standard-device rule allowed is delivered only where that object is
// the character device the path names. A regular file, another device and a directory at the same path are refused
// as a file outside every entry; a read is not the rule's business.
func TestStandardDeviceRuleIsTheObjectsNotTheNames(t *testing.T) {
	devStat := func(p string) unix.Stat_t {
		var st unix.Stat_t
		if err := unix.Stat(p, &st); err != nil {
			t.Skipf("host has no %s: %v", p, err)
		}
		return st
	}
	plain := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, dir := devStat(plain), devStat(filepath.Dir(plain))
	null, zero := devStat("/dev/null"), devStat("/dev/zero")
	for _, tc := range []struct {
		name  string
		rule  string
		flags int
		path  string
		st    unix.Stat_t
		want  bool
	}{
		{"the device", agent.BuiltinStandardDevices, unix.O_WRONLY, "/dev/null", null, false},
		{"the device, read-write", agent.BuiltinStandardDevices, unix.O_RDWR, "/dev/null", null, false},
		{"another device's numbers", agent.BuiltinStandardDevices, unix.O_WRONLY, "/dev/null", zero, true},
		{"a regular file", agent.BuiltinStandardDevices, unix.O_WRONLY, "/dev/null", reg, true},
		{"a directory", agent.BuiltinStandardDevices, unix.O_RDWR | unix.O_CREAT, "/dev/null", dir, true},
		{"a read of a file at the name", agent.BuiltinStandardDevices, unix.O_RDONLY, "/dev/null", reg, false},
		{"an entry of the contract", "fs.write[/dev/null]", unix.O_WRONLY, "/dev/null", reg, false},
		{"another rule", agent.UnmatchedRule, unix.O_WRONLY, "/dev/null", reg, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := standardDeviceRefused(tc.rule, tc.flags, tc.path, &tc.st); got != tc.want {
				t.Fatalf("standardDeviceRefused = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestHeldFloorsRefuseALookAlikeOfAStandardDevice drives heldFloors with a table holding the device row: the pinned
// object at /dev/null's path is the real device (floors pass) or a regular file (refused, rule unmatched, one line).
func TestHeldFloorsRefuseALookAlikeOfAStandardDevice(t *testing.T) {
	plain := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var reg, null unix.Stat_t
	if err := unix.Stat(plain, &reg); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat("/dev/null", &null); err != nil {
		t.Skipf("host has no /dev/null: %v", err)
	}
	for _, tc := range []struct {
		name string
		st   unix.Stat_t
		ok   bool
	}{{"the device", null, true}, {"a regular file at its name", reg, false}} {
		t.Run(tc.name, func(t *testing.T) {
			x := newHeldAskFixture(t)
			x.pol.Rules.FS = append(x.pol.Rules.FS, agent.FSRule{Path: "/dev/null", Resolved: "/dev/null", Kind: agent.FSWrite,
				Access: agent.AccessWriteFile, BuiltIn: true, StdDevice: true})
			l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
			n := notifFor(nrFor(t, "openat"), 42, argCWD, 0, uint64(unix.O_WRONLY))
			h := &heldPlan{n: n, flags: unix.O_WRONLY, resolved: "/dev/null", st: tc.st, pin: -1, opened: -1}
			if got := l.heldFloors(h, l.table.Load()); got != tc.ok {
				t.Fatalf("heldFloors = %v, want %v", got, tc.ok)
			}
			evs := sink.all()
			if tc.ok {
				if len(evs) != 0 || h.d.rule != agent.BuiltinStandardDevices {
					t.Fatalf("lines %d, rule %q: want none and the device rule", len(evs), h.d.rule)
				}
				return
			}
			if len(evs) != 1 || evs[0].Rule != agent.UnmatchedRule || evs[0].Verdict != record.VerdictRefused {
				t.Fatalf("lines %+v: want one refusal under rule unmatched", evs)
			}
		})
	}
}
