// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/internal/runtime/deputy"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// openAs is heldAskFixture.open made by the test's own thread as the task, with a mode: a create reads the task's
// umask from its /proc entry, which the fixture's stand-in pid has none of.
func (x *heldAskFixture) openAs(t *testing.T, l *Loop, path string, flags int, mode uint32) *notif {
	t.Helper()
	x.addr += 0x2000
	x.f.put(0x10000+x.addr, cstr(path))
	n := notifFor(nrFor(t, "openat"), x.k.tid, argCWD, 0x10000+x.addr, uint64(flags), uint64(mode))
	l.handle(n)
	return n
}

// writeHeld makes x a write-gated held fixture: the worktree is a write entry, and a write outside it scores into the
// refused range, so every write-open is held.
func (x *heldAskFixture) writeHeld(t *testing.T) {
	t.Helper()
	x.pol.Rules.FS = append(x.pol.Rules.FS, agent.FSRule{Path: x.dir, Resolved: x.dir, Kind: agent.FSWrite, Raw: x.dir, Access: agent.AccessWriteSet})
	x.pol.Rules.Gate = testGate(t, gate.WriteOutsideWorktree, "", 90).WithHeldCompletion()
}

// heldOutcome is a held open's E35 fields.
type heldOutcome struct {
	heldLine
	OperationCompleted *bool  `json:"operation_completed"`
	SyscallRet         *int64 `json:"syscall_ret"`
}

func decodeHeldOutcome(t *testing.T, ev *record.Event) heldOutcome {
	t.Helper()
	var p heldOutcome
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		t.Fatalf("payload %s: %v", ev.Payload, err)
	}
	return p
}

// A held create that the deputy made, whose new leaf a sibling renames before this loop checks the descriptor's
// identity, happened: its line is E35's (operation_completed true, fd_delivered false, the errno the task got as
// syscall_ret) and it counts orphaned, as ADR 0041 D5 says of a create made and not delivered. It was written as
// refused held-unavailable with no operation_completed, a refusal of an open whose side effect had happened. Nothing
// is delivered either way.
func TestHeldCreateWhoseLeafMovesIsRecordedAsMade(t *testing.T) {
	x := newHeldAskFixture(t)
	x.writeHeld(t)
	created, moved := filepath.Join(x.dir, "new"), filepath.Join(x.dir, "moved")
	x.dep.afterOpen = func(int, string) {
		if err := os.Rename(created, moved); err != nil {
			t.Errorf("rename the new leaf: %v", err)
		}
	}
	l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
	x.openAs(t, l, created, unix.O_WRONLY|unix.O_CREAT, 0o644)
	if _, err := os.Lstat(moved); err != nil {
		t.Fatalf("the deputy's create did not happen: %v", err)
	}
	if len(x.k.heldDelivered) != 0 {
		t.Fatalf("delivered %q: a descriptor whose identity failed is never delivered", x.k.heldDelivered)
	}
	res, _ := x.f.lastResp()
	if res.Error != -int32(unix.EACCES) {
		t.Fatalf("answer %+v, want EACCES", res)
	}
	evs := sink.all()
	if len(evs) != 1 {
		t.Fatalf("lines %+v: want one", evs)
	}
	p := decodeHeldOutcome(t, evs[0])
	if evs[0].Rule == ruleHeldUnavailable || p.OperationCompleted == nil || !*p.OperationCompleted || p.FDDelivered ||
		p.SyscallRet == nil || *p.SyscallRet != -int64(unix.EACCES) || p.Path != created {
		t.Fatalf("line %s %s %s: want the create's line, operation_completed true, fd_delivered false, syscall_ret -13", evs[0].Verdict, evs[0].Rule, evs[0].Payload)
	}
	if m := l.Metrics(); m.Orphaned != 1 {
		t.Fatalf("orphaned %d, want 1", m.Orphaned)
	}
}

// A held open whose descriptor is not the pinned inode (here the deputy's reopen is pointed at another file, as a
// confused deputy's would be) is never delivered. A read-only open had no effect but atime: it is refused
// held-unavailable, with no E35 fields, and counts nothing orphaned. A write-open was made: its line says so, as a
// create's does.
func TestHeldOpenWhoseIdentityFails(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags int
	}{{"read", unix.O_RDONLY}, {"write", unix.O_WRONLY}} {
		t.Run(tc.name, func(t *testing.T) {
			x := newHeldAskFixture(t)
			x.writeHeld(t)
			if tc.flags == unix.O_RDONLY {
				x.pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.env", 90).WithHeldCompletion()
			}
			other := filepath.Join(x.dir, "other")
			if err := os.WriteFile(other, []byte("other"), 0o600); err != nil {
				t.Fatal(err)
			}
			x.dep.beforeOpen = func(pin int, _ string) {
				fd, err := unix.Open(other, unix.O_PATH|unix.O_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				if err := unix.Dup3(fd, pin, unix.O_CLOEXEC); err != nil {
					t.Fatal(err)
				}
				_ = unix.Close(fd)
			}
			l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
			x.openAs(t, l, x.standIn, tc.flags, 0)
			evs := sink.all()
			res, _ := x.f.lastResp()
			if len(x.k.heldDelivered) != 0 || len(evs) != 1 || res.Error != -int32(unix.EACCES) {
				t.Fatalf("delivered %q, answer %+v, lines %+v: want nothing delivered, EACCES, one line", x.k.heldDelivered, res, evs)
			}
			p := decodeHeldOutcome(t, evs[0])
			orphaned := l.Metrics().Orphaned
			if tc.flags == unix.O_RDONLY {
				if evs[0].Verdict != record.VerdictRefused || evs[0].Rule != ruleHeldUnavailable || p.OperationCompleted != nil || orphaned != 0 {
					t.Fatalf("read line %s %s %s, orphaned %d: want refused held-unavailable, no E35 fields", evs[0].Verdict, evs[0].Rule, evs[0].Payload, orphaned)
				}
				return
			}
			if evs[0].Rule == ruleHeldUnavailable || p.OperationCompleted == nil || !*p.OperationCompleted || p.FDDelivered || orphaned != 1 {
				t.Fatalf("write line %s %s %s, orphaned %d: want the open's line, made and not delivered", evs[0].Verdict, evs[0].Rule, evs[0].Payload, orphaned)
			}
		})
	}
}

// Under held completion an open an fs.ask scope or an fs.ask_read entry holds for a person takes D3 step 1 first, as
// every held open does (heldOpen): the gate's score of the copied name where this loop's walk of it landed, whose
// refusal is final, so the name the hold pins cannot pick a lower score. The hold scored the pinned target alone and
// asked. Here a sibling re-points a link between the walk and the pin: the walk lands on a name the gate
// refuses (a file outside the worktree for a write-open under an fs.ask scope, a *.env file for a read under an
// fs.ask_read entry), and the pin on a benign file the scope covers.
func TestHeldAskScopeRefusesOnTheCopiedName(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write bool
	}{{"fs.ask write", true}, {"fs.ask_read read", false}} {
		t.Run(tc.name, func(t *testing.T) {
			x := newHeldAskFixture(t)
			x.f.realWalks = true // this loop's own walk of the copied name, as a run makes it
			scope := filepath.Join(x.dir, "scope")
			if err := os.Mkdir(scope, 0o700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(scope, "data")
			if err := os.WriteFile(target, []byte("data"), 0o600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(scope, "link")
			var gated string
			flags := unix.O_RDONLY
			if tc.write {
				outside, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				gated = filepath.Join(outside, "f")
				flags = unix.O_WRONLY
				x.pol.Rules.FSAsk = []agent.FSRule{{Path: scope, Resolved: scope, Kind: agent.FSAsk, Raw: scope}}
				x.pol.Rules.Gate = testGate(t, gate.WriteOutsideWorktree, "", 90).WithHeldCompletion()
			} else {
				gated = filepath.Join(scope, "s.env")
				x.pol.Rules.FS = append(x.pol.Rules.FS, agent.FSRule{Path: scope, Resolved: scope, Kind: agent.FSDenyRead, AskRead: true, Raw: scope})
				x.pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.env", 90).WithHeldCompletion()
			}
			if err := os.WriteFile(gated, []byte("gated"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(gated, link); err != nil {
				t.Fatal(err)
			}
			x.k.beforePrepare = func() {
				if err := os.Remove(link); err != nil {
					t.Error(err)
				}
				if err := os.Symlink(target, link); err != nil {
					t.Error(err)
				}
			}
			l, sink, asked := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{Approved: true, By: "uid:1 pid:2"} })
			x.openAs(t, l, link, flags, 0)
			res, _ := x.f.lastResp()
			evs := sink.all()
			if len(*asked) != 0 || len(x.k.completed) != 0 || len(x.k.heldDelivered) != 0 {
				t.Fatalf("asked %d, completed %v, delivered %q: a copied name the gate refuses is refused before any hold", len(*asked), x.k.completed, x.k.heldDelivered)
			}
			if res.Error != -int32(unix.EACCES) || len(evs) != 1 || evs[0].Verdict != record.VerdictRefused ||
				evs[0].Reason != record.ReasonFSGate || evs[0].Authority != record.AuthorityGate {
				t.Fatalf("answer %+v, lines %+v: want EACCES, one gate refusal", res, evs)
			}
		})
	}
}

// An open that reads, O_RDWR included, is held and scored on the pinned object by the read predicates as well as the
// write ones (scoreOpen, gate.md R1 as amended 2026-10-16), so the race a held read-open is closed against is closed
// for a read-write open too. Here the copied name is a benign file, and a sibling's rewrite
// makes the deputy's lookup reach the *.env file the read gate refuses. Under a read gate alone a read-write open was
// not held at all (its kind was taken as the write gate's, which cannot escalate), so the copied name decided it and the
// open was continued; under a read and a write gate it was held and scored by the write predicates alone, and the
// secret was delivered. A read-write open of the benign file itself is held and delivered.
func TestHeldReadWriteOpenIsScoredByTheReadGate(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write bool // a write gate beside the read gate
	}{{"read gate", false}, {"read and write gates", true}} {
		t.Run(tc.name, func(t *testing.T) {
			x := newHeldAskFixture(t)
			x.pol.Rules.FS = append(x.pol.Rules.FS, agent.FSRule{Path: x.dir, Resolved: x.dir, Kind: agent.FSWrite, Raw: x.dir, Access: agent.AccessWriteSet})
			rules := []gate.Rule{{Predicate: gate.ReadMatches, Argument: "*.env", Score: 90}}
			if tc.write {
				rules = append(rules, gate.Rule{Predicate: gate.WriteOutsideWorktree, Score: 90})
			}
			g, err := gate.New(rules, 50, 80)
			if err != nil {
				t.Fatal(err)
			}
			x.pol.Rules.Gate = g.WithHeldCompletion()
			secret := filepath.Join(x.dir, "s.env")
			if err := os.WriteFile(secret, []byte("TOKEN=1"), 0o600); err != nil {
				t.Fatal(err)
			}
			x.dep.swapTo = secret
			l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
			n := x.openAs(t, l, x.standIn, unix.O_RDWR, 0)
			res, _ := x.f.lastResp()
			evs := sink.all()
			if x.dep.pins != 1 {
				t.Fatalf("%d pins: a read-write open under a read gate is held", x.dep.pins)
			}
			if len(x.k.heldDelivered) != 0 || res.Error != -int32(unix.EACCES) || res.Flags != 0 {
				t.Fatalf("answer %+v, delivered %q: the read gate refuses the pinned *.env file", res, x.k.heldDelivered)
			}
			if len(evs) != 1 || evs[0].Verdict != record.VerdictRefused || evs[0].Reason != record.ReasonFSGate || evs[0].Rule != "gate.rules[0]" {
				t.Fatalf("lines %+v: want one refusal by the read rule", evs)
			}
			if p := decodeHeldLine(t, evs[0]); p.Path != secret || p.GateFacts != gateFactsHeld {
				t.Fatalf("line %s: want the pinned secret, held_object", evs[0].Payload)
			}
			_ = n
			x.dep.swapTo = ""
			x.openAs(t, l, x.standIn, unix.O_RDWR, 0)
			if x.dep.pins != 2 || len(x.k.heldDelivered) != 1 || x.k.heldDelivered[0] != "fake credentials" {
				t.Fatalf("%d pins, delivered %q: the benign read-write open is held and delivered", x.dep.pins, x.k.heldDelivered)
			}
		})
	}
}

// A pin the deputy's walk reached by a name, whose last name is removed before this loop reads it, has no name left
// for the floors or the gate to decide on (ADR 0041 D4). It was taken as nameless, so a benign symlink to a gated
// file, unlinked just after the pin, was scored on the benign name alone and delivered. It is pinned
// once more, as the task's own open made now would walk the name again (D4's one re-pin; ADR 0069's held reads met it
// on every rename over a file the run read): a target removed meanwhile is the walk's ENOENT, and one a sibling
// replaces after every pin is refused gate.unreadable on the second answer, as a linked object this loop cannot see
// is. Neither is ever delivered or decided on the copied name. An unlinked file reached through a descriptor, a
// /proc/self/fd magic link, is nameless as D4's row says, and is still delivered.
func TestHeldPinWhoseNameIsRemovedIsUnreadable(t *testing.T) {
	// Each sibling is what happens to the target after a pin: removed once, or replaced by a rename every time.
	siblings := map[string]func(t *testing.T, target string) func(){
		"removed": func(t *testing.T, target string) func() {
			return func() {
				if err := os.Remove(target); err != nil {
					t.Error(err)
				}
			}
		},
		"replaced every time": func(t *testing.T, target string) func() {
			return func() { replaceByRename(t, target, "TOKEN=again") }
		},
	}
	// want is the answer and the lines of each sibling's open.
	want := func(t *testing.T, sibling string, res sysResp, evs []*record.Event) {
		t.Helper()
		if sibling == "removed" {
			if res.Error != -int32(unix.ENOENT) {
				t.Fatalf("answer %+v, lines %+v: want the second walk's ENOENT", res, evs)
			}
			// The walk's errno is the kernel's answer, written as such (TestHeldOpenKernelErrnoIsTheResultNotARefusal).
			for _, e := range evs {
				if e.Verdict == record.VerdictRefused || decodeHeldLine(t, e).FDDelivered {
					t.Fatalf("line %s %s: want the kernel's ENOENT, nothing delivered", e.Verdict, e.Payload)
				}
			}
			return
		}
		if res.Error != -int32(unix.EACCES) || len(evs) != 1 || evs[0].Verdict != record.VerdictRefused || evs[0].Rule != "gate.unreadable" {
			t.Fatalf("answer %+v, lines %+v: want one refusal, gate.unreadable", res, evs)
		}
	}
	for sibling, after := range siblings {
		t.Run("by name, "+sibling, func(t *testing.T) {
			x := newHeldAskFixture(t)
			x.pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.env", 90).WithHeldCompletion()
			secret := filepath.Join(x.dir, "s.env")
			if err := os.WriteFile(secret, []byte("TOKEN=1"), 0o600); err != nil {
				t.Fatal(err)
			}
			benign := filepath.Join(x.dir, "benign")
			if err := os.Symlink(secret, benign); err != nil {
				t.Fatal(err)
			}
			x.dep.afterPin = after(t, secret)
			l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
			x.openAs(t, l, benign, unix.O_RDONLY, 0)
			res, _ := x.f.lastResp()
			if len(x.k.heldDelivered) != 0 || x.dep.pins != 2 {
				t.Fatalf("answer %+v, delivered %q, %d pins: a pin whose name was removed is pinned once more, never decided on the copied name alone",
					res, x.k.heldDelivered, x.dep.pins)
			}
			want(t, sibling, res, sink.all())
		})
		// The same for a write-open under a write gate, where no read gate's refusal of an unlinked file stands
		// in for it: a benign name in the worktree that is a symlink to a file outside it, whose last name a sibling
		// removes just after the pin. Taken as nameless, the floor and the gate's score on the pinned object were skipped
		// and the benign copied name allowed the write-open.
		t.Run("by name, a write, "+sibling, func(t *testing.T) {
			x := newHeldAskFixture(t)
			x.writeHeld(t)
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte("elsewhere"), 0o600); err != nil {
				t.Fatal(err)
			}
			benign := filepath.Join(x.dir, "benign-w")
			if err := os.Symlink(outside, benign); err != nil {
				t.Fatal(err)
			}
			x.dep.afterPin = after(t, outside)
			l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
			x.openAs(t, l, benign, unix.O_WRONLY|unix.O_APPEND, 0)
			res, _ := x.f.lastResp()
			if len(x.k.heldDelivered) != 0 || len(x.dep.opened) != 0 || x.dep.pins != 2 {
				t.Fatalf("answer %+v, delivered %q, %d opens, %d pins: a pin whose name was removed is pinned once more, never decided on the copied name alone",
					res, x.k.heldDelivered, len(x.dep.opened), x.dep.pins)
			}
			want(t, sibling, res, sink.all())
		})
	}
	// A regular file behind a descriptor whose last name was removed lost a name the read gate may have matched: a held
	// read of it is refused gate.unreadable. It was taken as nameless and delivered, so a file
	// the gate refused by name could be read: open it write-only (a read gate does not score that), remove its name
	// (nor that), and reopen the descriptor for reading. A file that never had a name, a memfd, is nameless and
	// delivered, as D4's row says.
	t.Run("an unlinked file by descriptor", func(t *testing.T) {
		x := newHeldAskFixture(t)
		x.pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.env", 90).WithHeldCompletion()
		gone := filepath.Join(x.dir, "gone.env")
		if err := os.WriteFile(gone, []byte("TOKEN=1"), 0o600); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Open(gone, unix.O_WRONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd) //nolint:errcheck // a test descriptor
		if err := os.Remove(gone); err != nil {
			t.Fatal(err)
		}
		l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
		x.openAs(t, l, "/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDONLY, 0)
		res, _ := x.f.lastResp()
		evs := sink.all()
		if len(x.k.heldDelivered) != 0 || res.Error != -int32(unix.EACCES) {
			t.Fatalf("answer %+v, delivered %q: an unlinked file is never read through a held reopen", res, x.k.heldDelivered)
		}
		if len(evs) != 1 || evs[0].Verdict != record.VerdictRefused || evs[0].Rule != "gate.unreadable" || evs[0].Reason != record.ReasonFSGate {
			t.Fatalf("lines %+v: want one refusal, gate.unreadable", evs)
		}
	})
	t.Run("a memfd by descriptor", func(t *testing.T) {
		x := newHeldAskFixture(t)
		x.pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.env", 90).WithHeldCompletion()
		fd, err := unix.MemfdCreate("held.env", unix.MFD_CLOEXEC)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd) //nolint:errcheck // a test descriptor
		if _, err := unix.Write(fd, []byte("anonymous")); err != nil {
			t.Fatal(err)
		}
		l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
		x.openAs(t, l, "/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDONLY, 0)
		res, _ := x.f.lastResp()
		if len(x.k.heldDelivered) != 1 || x.k.heldDelivered[0] != "anonymous" {
			t.Fatalf("answer %+v, delivered %q, lines %+v: a memfd never had a name, and is delivered", res, x.k.heldDelivered, sink.all())
		}
	})
}

// The copied completion's walk of a reopen (TestHeldPinWhoseNameIsRemovedIsUnreadable's for the held one): a read the
// gate scores, of a regular file reached through a descriptor with no name left, has no name the gate can read, and is
// refused gate.unreadable; it was scored on the descriptor's procfs spelling, matched nothing, and was continued. A
// write-only reopen keeps its verdict, and a memfd is nameless and continued.
func TestGateReadRefusesAReopenOfAnUnlinkedFile(t *testing.T) {
	x := newHeldAskFixture(t)
	x.f.realWalks = true
	x.pol.Rules.FS = append(x.pol.Rules.FS, agent.FSRule{Path: x.dir, Resolved: x.dir, Kind: agent.FSWrite, Raw: x.dir, Access: agent.AccessWriteSet})
	x.pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.env", 90)
	gone := filepath.Join(x.dir, "gone.env")
	if err := os.WriteFile(gone, []byte("TOKEN=1"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(gone, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd) //nolint:errcheck // a test descriptor
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	mfd, err := unix.MemfdCreate("copied.env", unix.MFD_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(mfd) //nolint:errcheck // a test descriptor
	sink := &testSink{}
	l, err := New(testListener(), x.pol, sink, Options{kernel: x.k})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		fd      int
		flags   int
		refused bool
	}{
		{"read of the unlinked file", fd, unix.O_RDONLY, true},
		{"read-write of the unlinked file", fd, unix.O_RDWR, true},
		{"write-only reopen of the unlinked file", fd, unix.O_WRONLY, false},
		{"read of a memfd", mfd, unix.O_RDONLY, false},
	} {
		before := len(sink.all())
		x.openAs(t, l, "/proc/self/fd/"+strconv.Itoa(tc.fd), tc.flags, 0)
		res, _ := x.f.lastResp()
		evs := sink.all()[before:]
		refused := res.Error == -int32(unix.EACCES) && len(evs) == 1 && evs[0].Rule == "gate.unreadable"
		if refused != tc.refused {
			var lines []string
			for _, ev := range evs {
				lines = append(lines, string(ev.Verdict)+" "+ev.Rule+" "+string(ev.Payload))
			}
			t.Errorf("%s: answer %+v, lines %q: refused gate.unreadable %t, want %t", tc.name, res, lines, refused, tc.refused)
		}
		if !tc.refused && res.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
			t.Errorf("%s: answer %+v, want it continued", tc.name, res)
		}
	}
}

// The deputy's walk says how it reached what it pinned (deputy.Pinned's ByDescriptor), on its one-lookup path and on
// the walk alike: by a name for a file, a relative name, a directory's "..", and a symlink to a file; through a
// descriptor for a relative "." (the dirfd itself), a /proc/self/fd magic link, a symlink to one, and AT_EMPTY_PATH.
func TestDeputyPinSaysHowItReached(t *testing.T) {
	tid := selfTask(t)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("f"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	dirfd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dirfd) //nolint:errcheck // a test descriptor
	held, err := unix.Open(file, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(held) //nolint:errcheck // a test descriptor
	magic := "/proc/self/fd/" + strconv.Itoa(held)
	if err := os.Symlink(magic, filepath.Join(dir, "to-fd")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("f", filepath.Join(dir, "to-f")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		q    deputy.PinQuery
		byFD bool
	}{
		{"absolute file", deputy.PinQuery{DirFD: atFDCWD, Path: file}, false},
		{"relative file", deputy.PinQuery{DirFD: int32(dirfd), Path: "f"}, false},
		{"relative dot", deputy.PinQuery{DirFD: int32(dirfd), Path: "."}, true},
		{"relative dots", deputy.PinQuery{DirFD: int32(dirfd), Path: "./."}, true},
		{"dotdot", deputy.PinQuery{DirFD: int32(dirfd), Path: "d/.."}, false},
		{"symlink to a file", deputy.PinQuery{DirFD: int32(dirfd), Path: "to-f"}, false},
		{"magic link", deputy.PinQuery{DirFD: atFDCWD, Path: magic}, true},
		{"symlink to a magic link", deputy.PinQuery{DirFD: int32(dirfd), Path: "to-fd"}, true},
		{"AT_EMPTY_PATH", deputy.PinQuery{DirFD: int32(held), Empty: true}, true},
	} {
		q := tc.q
		q.TID, q.TGID = tid, os.Getpid()
		p, err := DeputyPin(q)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		_ = unix.Close(p.FD)
		if p.ByDescriptor != tc.byFD {
			t.Errorf("%s: ByDescriptor %v, want %v", tc.name, p.ByDescriptor, tc.byFD)
		}
	}
}

// A held create whose leaf appears as a symlink between the deputy's pin and its open (the open adds O_NOFOLLOW to a
// create beneath the pinned parent, so it meets ELOOP) is pinned and scored once more, as ADR 0041 D4 says: the
// kernel's own O_CREAT open without O_NOFOLLOW would follow the link, so the re-pin follows it and the deputy opens
// what it reaches, decided as any held open is. The second answer stands: a link into the worktree is opened, as the
// kernel's open of it is; one out of the write entry is refused by the floor on the new pin; and an agent that asked
// for O_NOFOLLOW gets ELOOP, the kernel's answer, with no re-pin. Every case answered ELOOP before.
func TestHeldCreateRepinsALeafThatAppeared(t *testing.T) {
	for _, tc := range []struct {
		name      string
		outside   bool
		nofollow  bool
		wantPins  int
		wantErrno unix.Errno
	}{
		{"a link into the worktree", false, false, 2, 0},
		{"a link out of the write entry", true, false, 2, unix.EACCES},
		{"the agent's O_NOFOLLOW", false, true, 1, unix.ELOOP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newHeldAskFixture(t)
			x.writeHeld(t)
			target := filepath.Join(x.dir, "f")
			if tc.outside {
				outside, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				target = filepath.Join(outside, "f")
			}
			if err := os.WriteFile(target, []byte("f-content"), 0o600); err != nil {
				t.Fatal(err)
			}
			leaf := filepath.Join(x.dir, "new")
			first := true
			x.dep.beforeOpen = func(int, string) {
				if first {
					first = false
					if err := os.Symlink(target, leaf); err != nil {
						t.Errorf("plant the link: %v", err)
					}
				}
			}
			flags := unix.O_RDWR | unix.O_CREAT
			if tc.nofollow {
				flags |= unix.O_NOFOLLOW
			}
			l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
			x.openAs(t, l, leaf, flags, 0o644)
			res, _ := x.f.lastResp()
			if x.dep.pins != tc.wantPins {
				t.Fatalf("%d pins, want %d (answer %+v)", x.dep.pins, tc.wantPins, res)
			}
			if tc.wantErrno != 0 {
				if res.Error != -int32(tc.wantErrno) || len(x.k.heldDelivered) != 0 {
					t.Fatalf("answer %+v, delivered %q: want %v, nothing delivered", res, x.k.heldDelivered, tc.wantErrno)
				}
				if b, _ := os.ReadFile(target); string(b) != "f-content" {
					t.Fatalf("the link's target became %q", b)
				}
				return
			}
			// The kernel's own open of the name, with the link in place, opens the link's target.
			want, err := os.ReadFile(leaf)
			if err != nil {
				t.Fatal(err)
			}
			if len(x.k.heldDelivered) != 1 || x.k.heldDelivered[0] != string(want) {
				t.Fatalf("answer %+v, delivered %q: want the link's target %q, as the kernel's open gives", res, x.k.heldDelivered, want)
			}
			evs := sink.all()
			if len(evs) != 1 || evs[0].Verdict != record.VerdictAllow {
				t.Fatalf("lines %+v: want the delivered open's", evs)
			}
			if p := decodeHeldLine(t, evs[0]); p.Path != target || p.GateFacts != gateFactsHeld {
				t.Fatalf("line %s: want the re-pinned target %s, held_object", evs[0].Payload, target)
			}
		})
	}
}

// probeSink is a testSink that runs probe on each line before it keeps it: what is true of the run at the moment the
// loop writes the line.
type probeSink struct {
	testSink
	probe func(*record.Event)
}

func (s *probeSink) Emit(ev *record.Event) {
	s.probe(ev)
	s.testSink.Emit(ev)
}

// A held open's descriptor is the agent's once ADDFD|SEND delivered it, and this loop's copy is closed before the open's
// line is written: the line can wait on the ledger's queue (backpressure, R23), and a copy kept open meanwhile is a
// second reference to the agent's open file description. A FIFO the agent opened for reading then still has a reader
// after the agent closed it (a writer's O_NONBLOCK open succeeds where the kernel answers ENXIO, and a reader of a
// FIFO the agent wrote waits for an end of file the copy holds back); an flock the agent released by its close is
// still held. The copy was closed after the line (the differential matrix's FIFO cases saw a reader that was not the
// agent's).
func TestHeldOpenClosesItsCopyBeforeItsLine(t *testing.T) {
	x := newHeldAskFixture(t)
	x.pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.env", 90).WithHeldCompletion()
	fifo := filepath.Join(x.dir, "pipe")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	sink := &probeSink{}
	var writerOpen []string
	sink.probe = func(ev *record.Event) {
		// The test's delivery installs nothing: the loop's copy is the only reader the FIFO can have.
		fd, err := unix.Open(fifo, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err == nil {
			_ = unix.Close(fd)
			writerOpen = append(writerOpen, "ok")
			return
		}
		name := err.Error()
		if errno, ok := err.(unix.Errno); ok {
			name = unix.ErrnoName(errno)
		}
		writerOpen = append(writerOpen, name)
	}
	l, err := New(testListener(), x.pol, sink, Options{kernel: x.k, openDeputy: x.dep, Ask: func(context.Context, ask.Request) (ask.Decision, error) {
		return ask.Decision{}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.closeAskScopes)
	x.openAs(t, l, fifo, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if len(x.k.heldDelivered) != 1 {
		t.Fatalf("delivered %q: the FIFO's read-open is held and delivered", x.k.heldDelivered)
	}
	if len(writerOpen) != 1 || writerOpen[0] != "ENXIO" {
		t.Fatalf("a writer's O_NONBLOCK open while the line was written: %v, want ENXIO (no reader left but the agent's)", writerOpen)
	}
}

// A pin the task left while the deputy's lookup was late (the wait found its notification gone, and the pin was
// abandoned) is no failure of the deputy's: the task is gone, nothing is answered and no line written, as for every
// other notification a task leaves, and no anomaly is counted. It was refused held-unavailable and counted an anomaly,
// a deputy failure that did not happen.
func TestHeldPinTheTaskLeftIsNoAnomaly(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags int
	}{{"read", unix.O_RDONLY}, {"write", unix.O_WRONLY}} {
		t.Run(tc.name, func(t *testing.T) {
			x := newHeldAskFixture(t)
			x.writeHeld(t)
			if tc.flags == unix.O_RDONLY {
				x.pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.env", 90).WithHeldCompletion()
			}
			x.dep.slowPin = func() {
				x.f.mu.Lock()
				x.f.staleAfter = 1 // every ID_VALID from here on finds the notification gone
				x.f.mu.Unlock()
			}
			l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
			// R22's soft ceiling (SoftCeiling, 200 µs) counts any notification held longer as an anomaly, which a
			// loaded box makes of this one (the pin is late on purpose). The count asserted below is the deputy's
			// failures alone (heldUnavailable, heldMismatch), so the ceiling is put out of reach (3 of 10 runs failed at load
			// 12 to 23 on the ceiling, not on the behaviour under test).
			l.budget = time.Hour
			before := l.Metrics().Anomalies
			n := x.openAs(t, l, x.standIn, tc.flags, 0)
			if !n.gone {
				t.Fatal("the task's notification is not gone: the pin was not abandoned")
			}
			if evs := sink.all(); len(evs) != 0 {
				t.Fatalf("lines %+v: a task that left gets none", evs)
			}
			if got := l.Metrics().Anomalies - before; got != 0 {
				t.Fatalf("%d anomalies counted for a pin the task left", got)
			}
		})
	}
}
