// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// sink collects the events a listener emits, the way internal/runtime's queue would.
type sink struct {
	mu     sync.Mutex
	events []*record.Event
}

func (s *sink) Emit(e *record.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func (s *sink) all() []*record.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*record.Event(nil), s.events...)
}

// metadata encodes one fanotify record the way the kernel writes it.
func metadata(mask uint64, fd, pid int32, vers uint8, length uint32) []byte {
	if length == 0 {
		length = fanMetadataLen
	}
	b := make([]byte, fanMetadataLen)
	binary.NativeEndian.PutUint32(b[0:4], length)
	b[4] = vers
	binary.NativeEndian.PutUint64(b[8:16], mask)
	binary.NativeEndian.PutUint32(b[16:20], uint32(fd))
	binary.NativeEndian.PutUint32(b[20:24], uint32(pid))
	return b
}

// TestParseFanotifyEvents covers a batch, the empty buffer, and every malformed shape a reader of kernel
// bytes must survive without indexing out of range (§8 I11).
func TestParseFanotifyEvents(t *testing.T) {
	t.Parallel()
	good := metadata(unix.FAN_OPEN_PERM, 7, 1234, fanMetadataVersion, 0)

	t.Run("batch", func(t *testing.T) {
		buf := append(append([]byte{}, good...), metadata(unix.FAN_OPEN_EXEC_PERM, 8, 5, fanMetadataVersion, 0)...)
		events, err := parseFanotifyEvents(buf)
		if err != nil {
			t.Fatalf("parseFanotifyEvents: %v", err)
		}
		if len(events) != 2 {
			t.Fatalf("%d events, want 2", len(events))
		}
		if events[0].FD != 7 || events[0].PID != 1234 || !events[0].isPermission() || events[0].isExec() {
			t.Fatalf("first event = %+v", events[0])
		}
		if !events[1].isExec() {
			t.Fatalf("second event is not an exec open: %+v", events[1])
		}
	})

	t.Run("empty", func(t *testing.T) {
		events, err := parseFanotifyEvents(nil)
		if err != nil || len(events) != 0 {
			t.Fatalf("= %v, %v", events, err)
		}
	})

	malformed := []struct {
		name string
		buf  []byte
	}{
		{"short record", good[:10]},
		{"zero length", metadata(unix.FAN_OPEN_PERM, 1, 1, fanMetadataVersion, 0)[:fanMetadataLen]},
		{"length below the minimum", metadata(unix.FAN_OPEN_PERM, 1, 1, fanMetadataVersion, 8)},
		{"length past the buffer", metadata(unix.FAN_OPEN_PERM, 1, 1, fanMetadataVersion, 4096)},
		{"wrong ABI version", metadata(unix.FAN_OPEN_PERM, 1, 1, 99, 0)},
		{"trailing partial record", append(append([]byte{}, good...), 1, 2, 3)},
	}
	for _, tc := range malformed {
		t.Run(tc.name, func(t *testing.T) {
			events, err := parseFanotifyEvents(tc.buf)
			if tc.name == "zero length" {
				// The helper writes the real length, so this case is well formed; assert that explicitly.
				if err != nil || len(events) != 1 {
					t.Fatalf("= %v, %v", events, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted %s: %+v", tc.name, events)
			}
			if tc.name == "trailing partial record" && len(events) != 1 {
				t.Fatalf("a good record before a bad one must still be returned, got %d", len(events))
			}
		})
	}
}

// testListener builds a listener whose "fanotify descriptor" is a pipe, so the responses it writes can be
// read back without privilege. Every decision is stubbed.
func testListener(t *testing.T, out Emitter, decide func(fanEvent) (verdict, error), deadline time.Duration) (*fanotifyListener, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	// The listener owns and closes its own descriptor, exactly as it owns a real fanotify group's, so it
	// gets a duplicate rather than the *os.File's: sharing one would be a double close, and a reused
	// descriptor number is the worst kind of test flake.
	dup, err := unix.Dup(int(w.Fd()))
	if err != nil {
		t.Fatalf("dup: %v", err)
	}
	l := &fanotifyListener{
		fd: dup, run: Run{ID: "run-1", Agent: "a", CgroupID: 99}, out: out,
		deadline: deadline, now: time.Now, marks: map[string]uint64{},
	}
	l.decide = decide
	l.markMount = func(string, uint64) error { return nil }
	l.unmarkMounts = func() error { return nil }
	t.Cleanup(func() {
		_ = l.Close()
		w.Close()
		r.Close()
	})
	return l, r
}

// readResponse reads one eight-byte fanotify response off the pipe.
func readResponse(t *testing.T, r *os.File) (int32, uint32) {
	t.Helper()
	var buf [8]byte
	if err := r.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := r.Read(buf[:]); err != nil {
		t.Fatalf("read response: %v", err)
	}
	return int32(binary.NativeEndian.Uint32(buf[0:4])), binary.NativeEndian.Uint32(buf[4:8])
}

// openFD returns a raw descriptor the listener may close, standing in for the one fanotify hands over.
func openFD(t *testing.T) int32 {
	t.Helper()
	fd, err := unix.Open(os.DevNull, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	return int32(fd)
}

// TestListenerAnswersEveryPermissionEvent is invariant I8 (and enforce-cgroup-observe.md §6 E9: a refused exec's event is this
// listener's, source fanotify, never a sched_process_exec record): an allow and a refusal each produce exactly one
// response, and a refusal also produces the ledger event that explains it.
func TestListenerAnswersEveryPermissionEvent(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		mask     uint64
		v        verdict
		wantDeny bool
		wantKind record.Kind
	}{
		{"allowed open", unix.FAN_OPEN_PERM, allowed, false, ""},
		{"refused open", unix.FAN_OPEN_PERM,
			verdict{path: "/home/u/.ssh/id_ed25519", rule: "fs.deny_read[~/.ssh]", reason: record.ReasonReadDenied},
			true, record.KindFS},
		{"refused exec", unix.FAN_OPEN_EXEC_PERM,
			verdict{path: "/usr/bin/curl", rule: agent.UnmatchedRule, reason: record.ReasonExecNotAllowed},
			true, record.KindExec},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &sink{}
			l, r := testListener(t, s, func(fanEvent) (verdict, error) { return tc.v, nil }, time.Second)
			l.threadGroup = func(int) int { return 4200 }
			fd := openFD(t)
			l.handle(fanEvent{Len: fanMetadataLen, Vers: fanMetadataVersion, Mask: tc.mask, FD: fd, PID: 4242})

			gotFD, resp := readResponse(t, r)
			if gotFD != fd {
				t.Fatalf("responded for descriptor %d, want %d", gotFD, fd)
			}
			// The whole word, not a bit of it: FAN_ALLOW and the bare FAN_DENY are the only two this listener
			// writes. The group has no FAN_ENABLE_AUDIT, so the kernel would refuse FAN_AUDIT, and the listener
			// sends no info record, so it never sets FAN_INFO, which the kernel would accept from this group
			// with a well-formed audit-rule record. A refusal carrying errno bits besides is one every kernel
			// answers with EINVAL for a FAN_CLASS_CONTENT group (§6 E2).
			want := uint32(unix.FAN_ALLOW)
			if tc.wantDeny {
				want = unix.FAN_DENY
			}
			if resp != want {
				t.Fatalf("response %#x, want %#x", resp, want)
			}
			answered, refused, timeouts, _ := l.stats()
			if answered != 1 {
				t.Fatalf("answered %d events, want exactly one", answered)
			}
			if tc.wantDeny && refused != 1 {
				t.Fatalf("refused counter = %d", refused)
			}
			if timeouts != 0 {
				t.Fatalf("timeouts = %d", timeouts)
			}

			events := s.all()
			if !tc.wantDeny {
				if len(events) != 0 {
					t.Fatalf("an allowed open produced %d events", len(events))
				}
				return
			}
			if len(events) != 1 {
				t.Fatalf("%d events for a refusal, want 1", len(events))
			}
			e := events[0]
			if e.Kind != tc.wantKind || e.Verdict != record.VerdictRefused || e.Reason != tc.v.reason {
				t.Fatalf("event = %+v", e)
			}
			if e.Source != record.SourceFanotify || e.Authority != record.AuthorityRule {
				t.Fatalf("event provenance = %s/%s", e.Source, e.Authority)
			}
			// FAN_REPORT_TID identifies the thread; the status lookup supplies its process.
			if e.PID != 4200 || e.TID != 4242 || e.Run != "run-1" || e.Cgroup != 99 {
				t.Fatalf("event identity = %+v", e)
			}
			if e.Rule != tc.v.rule {
				t.Fatalf("event names rule %q, want %q", e.Rule, tc.v.rule)
			}
			// The payload carries the file the kernel was about to open, not the rule that refused it.
			if tc.wantKind == record.KindExec {
				var p record.ExecPayload
				if err := e.DecodePayload(&p); err != nil {
					t.Fatalf("decode payload: %v", err)
				}
				if p.Path != tc.v.path {
					t.Fatalf("exec payload path = %q, want %q", p.Path, tc.v.path)
				}
			} else {
				var p record.FSPayload
				if err := e.DecodePayload(&p); err != nil {
					t.Fatalf("decode payload: %v", err)
				}
				if p.Path != tc.v.path || p.Op != record.FSOpen {
					t.Fatalf("fs payload = %+v, want op %q at %q", p, record.FSOpen, tc.v.path)
				}
			}
		})
	}
}

// TestListenerDeadlineFailsOpen is enforce-cgroup-observe.md §6 E16: a decision that outlives the deadline is answered FAN_ALLOW so the
// opener is never left blocked, and the gap says so.
func TestListenerDeadlineFailsOpen(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	s := &sink{}
	l, r := testListener(t, s, func(fanEvent) (verdict, error) {
		<-release
		return verdict{rule: "fs.deny_read[x]", reason: record.ReasonReadDenied}, nil
	}, 20*time.Millisecond)

	fd := openFD(t)
	l.handle(fanEvent{Len: fanMetadataLen, Vers: fanMetadataVersion, Mask: unix.FAN_OPEN_PERM, FD: fd, PID: 7})
	gotFD, resp := readResponse(t, r)
	close(release)

	if gotFD != fd {
		t.Fatalf("responded for descriptor %d, want %d", gotFD, fd)
	}
	if resp != unix.FAN_ALLOW {
		t.Fatalf("response %#x, want FAN_ALLOW at the deadline", resp)
	}
	if _, _, timeouts, _ := l.stats(); timeouts != 1 {
		t.Fatalf("timeouts = %d, want 1", timeouts)
	}
	if !hasGap(s.all(), GapFanotifyTimeout) {
		t.Fatalf("no %s gap: %+v", GapFanotifyTimeout, s.all())
	}
}

// TestListenerUnresolvedFailsOpen asserts a decision that errors with nothing to refuse allows the open and
// reports it. It is the case where no entry of the policy could refuse the event (decideEvent); an unresolved
// path the run opens where one could is refused (TestDecideEventRefusesAnUnresolvedPathForTheRun).
func TestListenerUnresolvedFailsOpen(t *testing.T) {
	t.Parallel()
	s := &sink{}
	l, r := testListener(t, s, func(fanEvent) (verdict, error) {
		return allowed, errors.New("readlink: bad descriptor")
	}, time.Second)
	fd := openFD(t)
	l.handle(fanEvent{Len: fanMetadataLen, Vers: fanMetadataVersion, Mask: unix.FAN_OPEN_PERM, FD: fd, PID: 7})
	if _, resp := readResponse(t, r); resp != unix.FAN_ALLOW {
		t.Fatalf("response %#x, want FAN_ALLOW", resp)
	}
	if !hasGap(s.all(), GapFanotifyUnresolved) {
		t.Fatalf("no %s gap: %+v", GapFanotifyUnresolved, s.all())
	}
}

// TestListenerOverflowAndNonPermission asserts the two record shapes that need no response: an overflow
// notice, which carries no descriptor, and a plain notification event.
func TestListenerOverflowAndNonPermission(t *testing.T) {
	t.Parallel()
	s := &sink{}
	l, _ := testListener(t, s, func(fanEvent) (verdict, error) { return allowed, nil }, time.Second)

	l.handle(fanEvent{Len: fanMetadataLen, Vers: fanMetadataVersion, Mask: unix.FAN_Q_OVERFLOW, FD: int32(unix.FAN_NOFD)})
	if !hasGap(s.all(), GapFanotifyOverflow) {
		t.Fatalf("no %s gap: %+v", GapFanotifyOverflow, s.all())
	}
	if answered, _, _, _ := l.stats(); answered != 0 {
		t.Fatalf("an overflow record must need no response, answered %d", answered)
	}

	fd := openFD(t)
	l.handle(fanEvent{Len: fanMetadataLen, Vers: fanMetadataVersion, Mask: unix.FAN_OPEN, FD: fd})
	if answered, _, _, _ := l.stats(); answered != 0 {
		t.Fatalf("a notification record must need no response, answered %d", answered)
	}

	l.handle(fanEvent{Len: fanMetadataLen, Vers: fanMetadataVersion, Mask: unix.FAN_OPEN_PERM, FD: int32(unix.FAN_NOFD)})
	if !hasGap(s.all(), GapFanotifyUnresolved) {
		t.Fatalf("a permission record with no descriptor must be reported: %+v", s.all())
	}
}

// TestListenerNilSinkCounts asserts a backend with no event sink drops and counts rather than panicking.
func TestListenerNilSinkCounts(t *testing.T) {
	t.Parallel()
	l, r := testListener(t, nil, func(fanEvent) (verdict, error) {
		return verdict{rule: "r", reason: record.ReasonReadDenied}, nil
	}, time.Second)
	fd := openFD(t)
	l.handle(fanEvent{Len: fanMetadataLen, Vers: fanMetadataVersion, Mask: unix.FAN_OPEN_PERM, FD: fd, PID: 1})
	if _, resp := readResponse(t, r); resp != unix.FAN_DENY {
		t.Fatalf("response %#x, want the bare FAN_DENY %#x", resp, unix.FAN_DENY)
	}
	if _, _, _, dropped := l.stats(); dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
}

// hasGap reports whether the events contain a gap with the given reason.
func hasGap(events []*record.Event, why string) bool {
	for _, e := range events {
		if e.Kind != record.KindGap {
			continue
		}
		var p record.GapPayload
		if err := e.DecodePayload(&p); err != nil {
			continue
		}
		if strings.HasPrefix(p.Why, why) {
			return true
		}
	}
	return false
}

// FuzzParseFanotifyEvents drives the decoder of kernel-supplied bytes (§8 I11): it must never panic, never
// return a record shorter than the ABI's minimum, and never claim a descriptor it did not read.
func FuzzParseFanotifyEvents(f *testing.F) {
	f.Add(metadata(unix.FAN_OPEN_PERM, 7, 1234, fanMetadataVersion, 0))
	f.Add(metadata(unix.FAN_Q_OVERFLOW, int32(unix.FAN_NOFD), 0, fanMetadataVersion, 0))
	f.Add(append(metadata(unix.FAN_OPEN_PERM, 1, 1, fanMetadataVersion, 0), 0xff, 0xff))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		events, _ := parseFanotifyEvents(b)
		total := 0
		for _, e := range events {
			if e.Len < fanMetadataLen {
				t.Fatalf("returned a record of %d bytes", e.Len)
			}
			if e.Vers != fanMetadataVersion {
				t.Fatalf("returned a record with ABI version %d", e.Vers)
			}
			total += int(e.Len)
		}
		if total > len(b) {
			t.Fatalf("records total %d bytes from a %d-byte buffer", total, len(b))
		}
	})
}

// TestFanotifyQuotaFailuresNameTheirSetting: every group and mark this listener makes is charged to root's
// fanotify quotas, which every other fanotify user of root on the host shares, so concurrent runs can use
// them up. The run is then refused, and the error must say which setting ran out rather than blame a missing
// privilege: EMFILE from fanotify_init is fs.fanotify.max_user_groups, ENOSPC from fanotify_mark is
// fs.fanotify.max_user_marks.
func TestFanotifyQuotaFailuresNameTheirSetting(t *testing.T) {
	saved := fanotifyInit
	t.Cleanup(func() { fanotifyInit = saved })
	for errno, want := range map[unix.Errno]string{unix.EMFILE: "fs.fanotify.max_user_groups", unix.EPERM: "CAP_SYS_ADMIN"} {
		fanotifyInit = func(uint, uint) (int, error) { return -1, errno }
		l, err := newFanotifyListener(&policy{}, Run{}, nil, 0)
		if l != nil {
			_ = l.Close()
		}
		if errors.Is(err, errThreadBudget) {
			t.Skipf("this host's thread budget refuses a listener before fanotify_init: %v", err)
		}
		if !errors.Is(err, ErrFanotify) || !errors.Is(err, errno) || !strings.Contains(err.Error(), want) {
			t.Errorf("fanotify_init failing with %v gave %v; want ErrFanotify naming %s", errno, err, want)
		}
	}

	l := &fanotifyListener{fd: -1, now: time.Now, marks: map[string]uint64{}}
	l.markMount = func(string, uint64) error { return unix.ENOSPC }
	err := l.markFor("/", fanPermMask)
	if !errors.Is(err, ErrFanotify) || !strings.Contains(err.Error(), "fs.fanotify.max_user_marks") {
		t.Errorf("a mount mark failing with ENOSPC gave %v; want ErrFanotify naming fs.fanotify.max_user_marks", err)
	}
	if len(l.marked()) != 0 {
		t.Errorf("a mark the kernel refused is recorded as placed: %v", l.marked())
	}
	if proc.Armed() {
		t.Error("a first mark the kernel refused left the process armed, with no mark to arm for")
	}
	l.markMount = func(string, uint64) error { return unix.ENOENT }
	if err := l.markFor("/gone", fanPermMask); err == nil || strings.Contains(err.Error(), "max_user") {
		t.Errorf("a mark failing with ENOENT gave %v; want the error without a quota hint", err)
	}
}
