// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestOpenLabelsRequireEveryActiveLabel(t *testing.T) {
	for _, tc := range []struct {
		name, lsms, attr, task, opener string
		fail                           string
		want                           bool
		differs                        bool
	}{
		{name: "no label LSM", lsms: "capability,landlock,yama,bpf\n", want: true},
		{name: "AppArmor same", lsms: "capability,apparmor", attr: "apparmor/current", task: "p (enforce)\n", opener: "p (enforce)\n", want: true},
		{name: "AppArmor transition", lsms: "apparmor", attr: "apparmor/current", task: "p (enforce)\n", opener: "unconfined\n", differs: true},
		{name: "AppArmor mode differs", lsms: "apparmor", attr: "apparmor/current", task: "p (enforce)\n", opener: "p (complain)\n", differs: true},
		{name: "SELinux same", lsms: "selinux,bpf", attr: "current", task: "u:r:t:s0\x00", opener: "u:r:t:s0\x00", want: true},
		{name: "SELinux transition", lsms: "selinux", attr: "current", task: "u:r:t:s0", opener: "u:r:s:s0", differs: true},
		{name: "Smack same", lsms: "smack", attr: "smack/current", task: "_", opener: "_"},
		{name: "Smack differs", lsms: "smack", attr: "smack/current", task: "secret", opener: "_"},
		{name: "stacked labels all required", lsms: "apparmor,smack", attr: "apparmor/current", task: "unconfined\n", opener: "unconfined\n"},
		{name: "ambiguous generic attr", lsms: "apparmor,selinux", attr: "current", task: "x", opener: "x"},
		{name: "unreadable task", lsms: "apparmor", attr: "apparmor/current", task: "x", opener: "x", fail: "/proc/123/"},
		{name: "unreadable completer", lsms: "apparmor", attr: "apparmor/current", task: "x", opener: "x", fail: "/proc/456/"},
		{name: "unreadable list", lsms: "apparmor", fail: "/sys/"},
		{name: "empty list"},
		{name: "unknown LSM", lsms: "tomoyo"},
		{name: "duplicate LSM", lsms: "apparmor,apparmor"},
		{name: "empty label", lsms: "apparmor", attr: "apparmor/current"},
		{name: "hidden label", lsms: "apparmor", attr: "apparmor/current", task: "---", opener: "---"},
		{name: "malformed label", lsms: "apparmor", attr: "apparmor/current", task: "a\x00b", opener: "a\x00b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read := func(p string) ([]byte, error) {
				if tc.fail != "" && strings.HasPrefix(p, tc.fail) {
					return nil, unix.EACCES
				}
				switch p {
				case "/sys/kernel/security/apparmor/.ns_level":
					return []byte("0\n"), nil
				case "/sys/kernel/security/lsm":
					return []byte(tc.lsms), nil
				case "/proc/123/attr/" + tc.attr:
					return []byte(tc.task), nil
				case "/proc/456/attr/" + tc.attr:
					return []byte(tc.opener), nil
				default:
					return nil, fmt.Errorf("unexpected label read %s", p)
				}
			}
			err := checkOpenLabel(123, 456, unix.O_RDONLY, read, nil)
			if (err == nil) != tc.want || errors.Is(err, errOpenLabelDiffers) != tc.differs {
				t.Fatalf("check %v, want success=%t, mismatch=%t", err, tc.want, tc.differs)
			}
		})
	}
}

// Equal current strings alone omit authority relevant to a completion. In an
// AppArmor child namespace, two different ancestor profiles can both print as
// "local (enforce)". SELinux creation contexts and Smack load-self2 rules are
// separate from current. These facts must not be inferred from string equality.
func TestOpenLabelsRequireCompleteAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, lsm, current, level, taskCreate, openerCreate string
		missing                                             string
		want                                                bool
	}{
		{name: "hidden AppArmor ancestors", lsm: "apparmor", current: "local (enforce)\n", level: "1\n"},
		{name: "AppArmor namespace unknown", lsm: "apparmor", current: "local (enforce)\n", missing: "/sys/kernel/security/apparmor/.ns_level"},
		{name: "fully visible AppArmor", lsm: "apparmor", current: "local (enforce)\n", level: "0\n", want: true},
		{name: "SELinux creation differs", lsm: "selinux", current: "u:r:t:s0", taskCreate: "u:object_r:restricted_t:s0", openerCreate: ""},
		{name: "SELinux creation unreadable", lsm: "selinux", current: "u:r:t:s0", missing: "/proc/123/attr/fscreate"},
		{name: "SELinux defaults equal", lsm: "selinux", current: "u:r:t:s0", want: true},
		{name: "SELinux explicit creation equal", lsm: "selinux", current: "u:r:t:s0", taskCreate: "u:object_r:f:s0\x00", openerCreate: "u:object_r:f:s0\x00", want: true},
		{name: "Smack process rules unknown", lsm: "smack", current: "same"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read := func(p string) ([]byte, error) {
				if p == tc.missing {
					return nil, unix.EACCES
				}
				switch p {
				case "/sys/kernel/security/lsm":
					return []byte(tc.lsm), nil
				case "/sys/kernel/security/apparmor/.ns_level":
					return []byte(tc.level), nil
				case "/proc/123/attr/fscreate":
					return []byte(tc.taskCreate), nil
				case "/proc/456/attr/fscreate":
					return []byte(tc.openerCreate), nil
				}
				if strings.HasSuffix(p, "/current") {
					return []byte(tc.current), nil
				}
				return nil, fmt.Errorf("unexpected fact %s", p)
			}
			err := checkOpenLabel(123, 456, unix.O_CREAT, read, nil)
			if (err == nil) != tc.want {
				t.Fatalf("check=%v, want success=%t", err, tc.want)
			}
		})
	}
}

func TestOpenLabelCreationAttributesOnlyForCreation(t *testing.T) {
	for _, flags := range []int{unix.O_RDONLY, unix.O_WRONLY | unix.O_TRUNC, unix.O_WRONLY | unix.O_CREAT, unix.O_TMPFILE | unix.O_RDWR} {
		t.Run(fmt.Sprintf("flags=%x", flags), func(t *testing.T) {
			read := func(p string) ([]byte, error) {
				switch p {
				case "/sys/kernel/security/lsm":
					return []byte("selinux"), nil
				case "/proc/123/attr/current", "/proc/456/attr/current":
					return []byte("u:r:t:s0"), nil
				default:
					return nil, unix.EACCES
				}
			}
			err := checkOpenLabel(123, 456, flags, read, nil)
			creates := flags&unix.O_CREAT != 0 || flags&unix.O_TMPFILE == unix.O_TMPFILE
			if (err != nil) != creates {
				t.Fatalf("check=%v, creates=%t", err, creates)
			}
		})
	}
}

func TestOpenLabelDiscoveryWithoutSecurityFS(t *testing.T) {
	for _, tc := range []struct {
		name string
		ids  []uint64
		err  error
		want bool
	}{
		{name: "complete AppArmor list", ids: []uint64{100, 104, 110}, want: true},
		{name: "complete SELinux list without securityfs", ids: []uint64{100, 101}, want: true},
		{name: "Smack still refuses", ids: []uint64{100, 102}},
		{name: "unknown module", ids: []uint64{100, 999}},
		{name: "missing list", err: unix.ENOSYS},
		{name: "blocked syscall", err: unix.EPERM},
		{name: "empty list"},
		{name: "duplicate module", ids: []uint64{104, 104}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read := func(p string) ([]byte, error) {
				if p == "/sys/kernel/security/lsm" {
					return nil, unix.EACCES
				}
				if p == "/sys/kernel/security/apparmor/.ns_level" {
					return []byte("0\n"), nil
				}
				if strings.HasSuffix(p, "/attr/apparmor/current") {
					return []byte("same (enforce)\n"), nil
				}
				if strings.HasSuffix(p, "/attr/current") {
					return []byte("u:r:t:s0"), nil
				}
				return nil, unix.ENOENT
			}
			err := checkOpenLabel(123, 456, unix.O_RDONLY, read, func() ([]uint64, error) { return tc.ids, tc.err })
			if (err == nil) != tc.want {
				t.Fatalf("check=%v, want success=%t", err, tc.want)
			}
		})
	}
}

// The task transitions between two syscalls with the same TID. Every attempted
// read and destructive open must recheck it before PinOpenStart or Open.
func TestHeldOpenLabelIsFreshAndPrecedesOpen(t *testing.T) {
	for _, flags := range []int{unix.O_RDONLY, unix.O_WRONLY | unix.O_TRUNC, unix.O_WRONLY | unix.O_CREAT} {
		for _, failure := range []error{errOpenLabelDiffers, unix.EACCES} {
			t.Run(fmt.Sprintf("flags=%x/%v", flags, failure), func(t *testing.T) {
				x := newHeldAskFixture(t)
				x.writeHeld(t)
				if flags == unix.O_RDONLY {
					x.pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.never", 90).WithHeldCompletion()
				}
				l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
				calls := 0
				x.f.openLabelCheck = func(tid, opener, flags int) error {
					calls++
					if tid != x.k.tid || opener != x.dep.PID() {
						t.Errorf("checked tid=%d opener=%d", tid, opener)
					}
					return nil
				}
				x.openAs(t, l, x.standIn, flags&^(unix.O_TRUNC|unix.O_CREAT), 0)
				if calls == 0 || len(x.k.heldDelivered) != 1 {
					t.Fatal("same-label control did not complete")
				}
				before := len(x.dep.opened)
				pins := x.dep.pins
				x.f.openLabelCheck = func(tid, opener, flags int) error { return failure }
				x.openAs(t, l, x.standIn, flags, 0o600)
				res, _ := x.f.lastResp()
				if len(x.dep.opened) != before || x.dep.pins != pins || len(x.k.heldDelivered) != 1 || res.Error != -int32(unix.EACCES) {
					t.Fatalf("label refusal opened/pinned/delivered: opens %v, pins %d, delivered %v, response %+v", x.dep.opened, x.dep.pins, x.k.heldDelivered, res)
				}
				evs := sink.all()
				last := evs[len(evs)-1]
				want := ruleHeldLabelUnavailable
				if errors.Is(failure, errOpenLabelDiffers) {
					want = ruleHeldLabelDiffers
				}
				if last.Verdict != record.VerdictRefused || last.Rule != want {
					t.Fatalf("line %s %s, want refused %s", last.Verdict, last.Rule, want)
				}
			})
		}
	}
}

// A real creation-attribute comparison must receive the operation's flags at
// the completion site; checking current alone would let this create through.
func TestHeldLabelChecksCreationAuthority(t *testing.T) {
	x := newHeldAskFixture(t)
	x.writeHeld(t)
	l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
	x.f.openLabelCheck = func(tid, opener, flags int) error {
		read := func(p string) ([]byte, error) {
			if p == "/sys/kernel/security/lsm" {
				return []byte("selinux"), nil
			}
			if strings.HasSuffix(p, "/attr/current") {
				return []byte("u:r:t:s0"), nil
			}
			if p == "/proc/123/attr/fscreate" {
				return []byte("u:object_r:restricted_t:s0"), nil
			}
			if p == "/proc/456/attr/fscreate" {
				return nil, nil
			}
			return nil, unix.EACCES
		}
		// This in-process fixture uses its own TID for both roles. Supply
		// distinct modeled identities to exercise the real attribute comparator.
		if tid != x.k.tid || opener != x.dep.PID() {
			t.Errorf("identities=%d/%d", tid, opener)
		}
		return checkOpenLabel(123, 456, flags, read, nil)
	}
	x.openAs(t, l, x.standIn, unix.O_WRONLY|unix.O_CREAT, 0o600)
	res, _ := x.f.lastResp()
	if len(x.dep.opened) != 0 || x.dep.pins != 0 || res.Error != -int32(unix.EACCES) {
		t.Fatalf("creation bypassed label check: opens=%v pins=%d response=%+v", x.dep.opened, x.dep.pins, res)
	}
	evs := sink.all()
	if len(evs) != 1 || evs[0].Rule != ruleHeldLabelDiffers {
		t.Fatalf("events: %+v", evs)
	}
}

func TestHeldOpenLabelReadIsBracketed(t *testing.T) {
	x := newHeldAskFixture(t)
	x.writeHeld(t)
	l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
	x.f.openLabelCheck = func(int, int, int) error {
		x.f.mu.Lock()
		x.f.stale[7] = true
		x.f.mu.Unlock()
		return nil
	}
	x.openAs(t, l, x.standIn, unix.O_WRONLY|unix.O_TRUNC, 0)
	if len(x.dep.opened) != 0 || len(x.k.heldDelivered) != 0 || len(sink.all()) != 0 {
		t.Fatal("a notification lost during the label read opened or delivered a file")
	}
}

func TestOpenLabelFileIsBounded(t *testing.T) {
	p := t.TempDir() + "/label"
	if err := os.WriteFile(p, []byte(strings.Repeat("x", 64*1024+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readOpenLabelFile(p); err == nil {
		t.Fatal("oversized label accepted")
	}
}

func TestAskOpenLabelsRefuseBeforeCompletion(t *testing.T) {
	for _, mode := range []string{"before ask", "after approval", "alternate", "alternate probe"} {
		t.Run(mode, func(t *testing.T) {
			x := newAskReadFixture(t)
			failure := mode == "before ask"
			x.f.openLabelCheck = func(tid, opener, flags int) error {
				if tid != 42 || opener != os.Getpid() {
					t.Errorf("label check tid=%d opener=%d", tid, opener)
				}
				if failure {
					return errOpenLabelDiffers
				}
				return nil
			}
			l, sink, asked := x.loop(t, func(req ask.Request) ask.Decision {
				failure = true
				if mode == "alternate probe" {
					if _, err := req.Alternates.Check(altOf(t, x.standIn)); !errors.Is(err, errOpenLabelDiffers) {
						t.Errorf("alternate probe: %v, want label refusal", err)
					}
				}
				if mode == "alternate" {
					return alternateDecision(t, x.standIn)
				}
				return ask.Decision{Approved: true, By: "uid:1 pid:2"}
			})
			x.open(t, l, x.secret, unix.O_RDONLY)
			res, _ := x.f.lastResp()
			if len(x.k.completed) != 0 || len(x.k.delivered) != 0 || res.Error != -int32(unix.EACCES) {
				t.Fatalf("completed %v delivered %v response %+v", x.k.completed, x.k.delivered, res)
			}
			if mode == "before ask" && len(*asked) != 0 {
				t.Fatal("asked about an open with incompatible labels")
			}
			evs := sink.all()
			if len(evs) != 1 || evs[0].Rule != ruleHeldLabelDiffers || evs[0].Verdict != record.VerdictRefused {
				t.Fatalf("lines %+v, want one held-label-differs refusal", evs)
			}
		})
	}
}

func TestAlternateLabelProbeKeepsTheOriginalNotification(t *testing.T) {
	x := newAskReadFixture(t)
	var probe *ask.AlternateCheck
	l, _, _ := x.loop(t, func(req ask.Request) ask.Decision {
		probe = req.Alternates
		return ask.Decision{Approved: true, By: "uid:1 pid:2"}
	})
	n := x.open(t, l, x.secret, unix.O_RDONLY)
	x.f.stale[n.id] = true
	// A late callback cannot follow the worker's notification into another
	// syscall after the original hold has ended.
	n.id, n.pid = 8, 88
	if _, err := probe.Check(altOf(t, x.standIn)); err == nil {
		t.Fatal("late alternate probe accepted a substituted notification")
	}
}
