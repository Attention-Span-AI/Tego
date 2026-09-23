// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// metadata builds one struct fanotify_event_metadata.
func metadata(eventLen uint32, version byte, mask uint64, fd int32, pid int32) []byte {
	b := make([]byte, fanotifyMetadataLen)
	e := binary.NativeEndian
	e.PutUint32(b[0:4], eventLen)
	b[4] = version
	e.PutUint16(b[6:8], fanotifyMetadataLen)
	e.PutUint64(b[8:16], mask)
	e.PutUint32(b[16:20], uint32(fd))
	e.PutUint32(b[20:24], uint32(pid))
	return b
}

func TestParseFanotifyMetadata(t *testing.T) {
	good := metadata(fanotifyMetadataLen, fanotifyMetadataVersion, 0x10000, 9, 4242)
	m, err := ParseFanotifyMetadata(good)
	if err != nil {
		t.Fatal(err)
	}
	if m.fd != 9 || m.pid != 4242 || m.mask != 0x10000 {
		t.Errorf("metadata %+v", m)
	}
	// FAN_NOFD (-1) is a real value the kernel sends and must survive the round trip as -1.
	m, err = ParseFanotifyMetadata(metadata(fanotifyMetadataLen, fanotifyMetadataVersion, 0, -1, 1))
	if err != nil || m.fd != -1 {
		t.Errorf("FAN_NOFD decoded as %d (%v)", m.fd, err)
	}
	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"short", good[:fanotifyMetadataLen-1]},
		{"wrong version", metadata(fanotifyMetadataLen, fanotifyMetadataVersion+1, 0, 1, 1)},
		{"event_len below the header", metadata(4, fanotifyMetadataVersion, 0, 1, 1)},
		{"event_len past the read", metadata(fanotifyMetadataLen*4, fanotifyMetadataVersion, 0, 1, 1)},
		{"an fd that is neither a descriptor nor FAN_NOFD", metadata(fanotifyMetadataLen, fanotifyMetadataVersion, 0, -42, 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseFanotifyMetadata(tc.in); !errors.Is(err, ErrFanotify) {
				t.Fatalf("ParseFanotifyMetadata = %v, want ErrFanotify", err)
			}
		})
	}
}

// TestProbeFanotifyWithoutRoot is §6 E18's wording rule: a probe that needs privilege says
// "requires root to test", never "unsupported".
// (limits-check-doctor-cli.md E18 again, for D8.)
func TestProbeFanotifyWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this test describes the unprivileged answer")
	}
	r, state := probeFanotify(false, Version{6, 17, 0})
	if r.OK || r.ID != CheckFanotify {
		t.Fatalf("result %+v", r)
	}
	if !contains(r.Detail, "requires root") || r.Fix == "" {
		t.Errorf("detail %q fix %q", r.Detail, r.Fix)
	}
	if state.PermissionMarks || state.DenyErrno || state.ReportFID {
		t.Errorf("an unprivileged probe reported state %+v", state)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func FuzzParseFanotifyMetadata(f *testing.F) {
	f.Add(metadata(fanotifyMetadataLen, fanotifyMetadataVersion, 0x10000, 9, 1))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, in []byte) {
		if m, err := ParseFanotifyMetadata(in); err == nil && m.fd < -1 {
			t.Fatalf("decoded fd %d", m.fd)
		}
	})
}

// TestFanotifyVerdict is D8's answer for every reply a kernel can give. The kernel takes a reply errno
// only from a FAN_CLASS_PRE_CONTENT group and never EACCES, so on every kernel so far the EACCES reply
// is refused and the bare FAN_DENY that follows reaches the opener as EPERM — and D8 used to read that
// as "refusals are a coarse EPERM below 6.13.0", naming a release that fixes nothing. What tier 2
// needs is that a FAN_DENY refuses the open at all, so a round trip that did not refuse it, or could
// not be completed, fails D8 rather than passing with a note.
//
// Neither failure is a missing CONFIG_FANOTIFY_ACCESS_PERMISSIONS: both come after the kernel took
// FAN_CLASS_CONTENT and the FAN_OPEN_PERM mark, which that option is, and D8's fix reaches the doctor
// fix line whenever tier cgroup is next. So each failing row's fix is pinned to its own cause, and
// none may name the option.
func TestFanotifyVerdict(t *testing.T) {
	marks := FanotifyState{PermissionMarks: true}
	cases := []struct {
		name      string
		reply     fanotifyReply
		err       error
		ok        bool
		refuses   bool
		denyErrno bool
		detail    string
		fix       string
	}{
		{"EACCES refused, the bare FAN_DENY gives EPERM (every kernel so far)",
			fanotifyReply{openErr: &os.PathError{Op: "open", Err: unix.EPERM}}, nil, true, true, false,
			"reaches the agent as EPERM", ""},
		{"a kernel that takes EACCES from this group",
			fanotifyReply{errnoAccepted: true, openErr: &os.PathError{Op: "open", Err: unix.EACCES}}, nil,
			true, true, true, "FAN_DENY_ERRNO=true", ""},
		{"a kernel that takes the errno and still gives EPERM",
			fanotifyReply{errnoAccepted: true, openErr: unix.EPERM}, nil, true, true, false, "EPERM", ""},
		{"the open went through", fanotifyReply{}, nil, false, false, false, "not EPERM",
			"did not refuse an open its fanotify listener denied"},
		{"EACCES the reply never asked for", fanotifyReply{openErr: unix.EACCES}, nil, false, false, false,
			"not EPERM", "boot a current stable kernel"},
		{"the round trip timed out", fanotifyReply{},
			fmt.Errorf("%w: no permission event within %s", ErrFanotify, fanotifyProbeTimeout), false, false, false,
			"could not be tested", "re-run tego doctor"},
		{"the answer could not be written", fanotifyReply{},
			fmt.Errorf("%w: answer the permission event: %w", ErrFanotify, unix.ENOENT), false, false, false,
			"could not be tested", "report it as a tego bug"},
		// Another LSM or a fanotify group of higher priority refused the open before this listener saw
		// it: the host's policy, the same on every run, and not a tego bug.
		{"the open was refused before the listener saw it", fanotifyReply{},
			noEvent(fmt.Errorf("%w: no permission event within %s", ErrFanotify, fanotifyProbeTimeout),
				refusedOpener(&os.PathError{Op: "open", Path: "/tmp/probe", Err: unix.EACCES})),
			false, false, false, "permission denied", "exempt tego's files"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, st := fanotifyVerdict(marks, tc.reply, tc.err)
			if r.OK != tc.ok || st.Refuses != tc.refuses || st.DenyErrno != tc.denyErrno {
				t.Fatalf("verdict %+v state %+v, want ok=%v refuses=%v deny_errno=%v", r, st, tc.ok, tc.refuses, tc.denyErrno)
			}
			if !strings.Contains(r.Detail, tc.detail) {
				t.Errorf("detail %q, want it to mention %q", r.Detail, tc.detail)
			}
			if strings.Contains(r.Detail, "6.13") {
				t.Errorf("detail %q names 6.13, a release that gives this listener no errno reply", r.Detail)
			}
			if !r.OK && r.Fix == "" {
				t.Errorf("a failing D8 without a fix: %+v", r)
			}
			if !strings.Contains(r.Fix, tc.fix) {
				t.Errorf("fix %q, want it to say %q", r.Fix, tc.fix)
			}
			if strings.Contains(r.Fix, "CONFIG_FANOTIFY_ACCESS_PERMISSIONS") {
				t.Errorf("fix %q names a kernel option this kernel has: it took the class and the mark", r.Fix)
			}
			if tc.name == "the open was refused before the listener saw it" && strings.Contains(r.Fix, "tego bug") {
				t.Errorf("fix %q blames tego for the host's own policy", r.Fix)
			}
		})
	}
}

// refusedOpener is the probe's opener goroutine having returned err before any event arrived.
func refusedOpener(err error) <-chan openResult {
	ch := make(chan openResult, 1)
	ch <- openResult{err}
	return ch
}

// TestNoEventTellsARefusedOpen is how D8 tells the host's policy from a slow round trip when no permission
// event arrives: an opener that has already failed was refused before the listener, and its errno is named;
// an opener still waiting, or one that opened, is the timeout it was.
func TestNoEventTellsARefusedOpen(t *testing.T) {
	timeout := fmt.Errorf("%w: no permission event within %s", ErrFanotify, fanotifyProbeTimeout)
	err := noEvent(timeout, refusedOpener(unix.EPERM))
	if !errors.Is(err, errRefusedBeforeListener) || !errors.Is(err, unix.EPERM) {
		t.Errorf("noEvent = %v, want the refusal before the listener with its EPERM", err)
	}
	if err := noEvent(timeout, make(chan openResult, 1)); err != timeout {
		t.Errorf("noEvent with the opener still waiting = %v, want the timeout itself", err)
	}
	if err := noEvent(timeout, refusedOpener(nil)); err != timeout {
		t.Errorf("noEvent with an opener that opened = %v, want the timeout itself", err)
	}
}
