// SPDX-License-Identifier: Apache-2.0

package runscope

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	otherNS  = InitCgroupNS + 0x10000001 // a namespace made after boot: its inode is a dynamic one
	nsDev    = 4
	shellCg  = "0::/non-systemd\n" // where WSL puts an ordinary shell
	testUID  = 1000
	initFile = "0::/init.scope\n"
)

// facts is a table's Facts. It records every reader Decide called, in order.
type facts struct {
	cgroup      []byte
	cgroupErr   error
	ns          Namespace
	nsErr       error
	real        int
	effective   int
	saved       int
	permitted   uint64
	permErr     error
	seccomp     int
	seccompErr  error
	anchored    []byte
	anchoredErr error
	proof       Answer
	withheld    Cause // the gate's cause beyond the first namespace
	heldFirst   Cause // the gate's cause in the first namespace
	calls       []string
}

func (f *facts) OwnCgroup() ([]byte, error) {
	f.calls = append(f.calls, "cgroup")
	return f.cgroup, f.cgroupErr
}

func (f *facts) CgroupNS() (Namespace, error) {
	f.calls = append(f.calls, "ns")
	return f.ns, f.nsErr
}

func (f *facts) UIDs() (int, int, int) {
	f.calls = append(f.calls, "uids")
	return f.real, f.effective, f.saved
}

func (f *facts) Permitted() (uint64, error) {
	f.calls = append(f.calls, "caps")
	return f.permitted, f.permErr
}

func (f *facts) Seccomp() (int, error) {
	f.calls = append(f.calls, "seccomp")
	return f.seccomp, f.seccompErr
}

func (f *facts) AnchoredCgroup() ([]byte, error) {
	f.calls = append(f.calls, "anchored")
	return f.anchored, f.anchoredErr
}

func (f *facts) Proof(Namespace, int) Answer {
	f.calls = append(f.calls, "proof")
	return f.proof
}

func (f *facts) Withheld(first bool) (Cause, bool) {
	if first {
		f.calls = append(f.calls, "withheld-first")
		return f.heldFirst, f.heldFirst != ""
	}
	f.calls = append(f.calls, "withheld")
	return f.withheld, f.withheld != ""
}

// wslShell is the facts of an ordinary WSL shell whose every fact holds.
func wslShell() *facts {
	return &facts{cgroup: []byte(shellCg), ns: Namespace{Dev: nsDev, Ino: otherNS}, real: testUID, effective: testUID,
		saved: testUID, anchored: []byte(shellCg), proof: Answer{verdict: Outside}}
}

func want(t *testing.T, name string, got Answer, v Verdict, c Cause) {
	t.Helper()
	if got.verdict != v || got.cause != c {
		t.Errorf("%s: answer %s %q (%v); want %s %q", name, got.verdict, got.cause, got.err, v, c)
	}
	if got.Outside() != (v == Outside) {
		t.Errorf("%s: Outside() = %v for verdict %s", name, got.Outside(), got.verdict)
	}
}

// TestAnswerZeroValueIsInside: an answer nobody filled in refuses, and the type offers one way to read it and no
// way to encode it.
func TestAnswerZeroValueIsInside(t *testing.T) {
	var a Answer
	if a.verdict != Inside || a.Outside() {
		t.Fatalf("the zero answer is %s, Outside() %v; want inside and false", a.verdict, a.Outside())
	}
	if (Answer{verdict: Unknown, cause: CauseProbeTimeout}).Outside() {
		t.Fatal("an unknown answer reads as outside")
	}
	for _, ty := range []reflect.Type{reflect.TypeFor[Answer](), reflect.TypeFor[*Answer]()} {
		if ty.NumMethod() != 1 || ty.Method(0).Name != "Outside" {
			t.Errorf("%s has %d methods; want Outside alone (no encoder, no second reading)", ty, ty.NumMethod())
		}
	}
	for _, v := range []Verdict{Inside, Unknown, Outside} {
		if v.String() == "" {
			t.Errorf("verdict %d has no name", v)
		}
	}
	// A malformed answer (a verdict past the three, an unknown with no cause) is no outside and still has words.
	for _, a := range []Answer{{verdict: Outside + 1}, {verdict: Unknown}} {
		if a.Outside() || Why(a) == "" || SaysGoverned(a) {
			t.Errorf("malformed answer %+v: Outside() %v, words %q, governed %v", a, a.Outside(), Why(a), SaysGoverned(a))
		}
	}
}

// TestAnswerCannotBeForged: no other package can make an Outside answer. The type has no exported field, so a
// composite literal elsewhere is the zero value, inside, and a decoder fills nothing: JSON that names every
// field, in either case, still decodes to inside. The one constructor other packages have, Unproven, makes unknown
// whatever it is given, and an empty cause becomes probe-error.
func TestAnswerCannotBeForged(t *testing.T) {
	ty := reflect.TypeFor[Answer]()
	for i := range ty.NumField() {
		if f := ty.Field(i); f.IsExported() {
			t.Errorf("Answer has the exported field %s: another package could set or read it", f.Name)
		}
	}
	for _, in := range []string{`{"Verdict":2}`, `{"verdict":2,"cause":""}`, `{"Verdict":2,"Cause":"","Err":null}`, `2`, `{}`} {
		var a Answer
		//nolint:staticcheck // SA9005 is the assertion: an answer has no exported field for a decoder to fill
		_ = json.Unmarshal([]byte(in), &a)
		if a.Outside() || a != (Answer{}) {
			t.Errorf("json %s decoded to %+v; want the zero answer", in, a)
		}
	}
	for _, c := range []Cause{"", CauseGoverned, CauseNoUserManager, Cause("outside")} {
		a := Unproven(c, nil)
		if a.Outside() || a.verdict != Unknown || a.cause == "" {
			t.Errorf("Unproven(%q) = %+v; want unknown with a cause", c, a)
		}
	}
	if a := Unproven("", nil); a.cause != CauseProbeError {
		t.Errorf("Unproven with no cause carries %q; want probe-error", a.cause)
	}
	d := Describe(Unproven(CauseNoUserManager, syscall.ENOENT))
	if d.Verdict != Unknown || d.Cause != CauseNoUserManager || !errors.Is(d.Err, syscall.ENOENT) ||
		d.String() != "unknown, no-user-manager (no such file or directory)" {
		t.Errorf("Describe = %+v, %q", d, d.String())
	}
	if s := Describe(Answer{}).String(); s != "inside" {
		t.Errorf("the zero answer described: %q", s)
	}
}

// TestDecideOwnPathComesFirst: a cgroup file that cannot be read, names no single absolute path, names one above
// the namespace root, or looks governed answers inside with its cause, in the first namespace and in any other, and
// nothing else is read: not the namespace, the capabilities, the seccomp mode or the socket.
func TestDecideOwnPathComesFirst(t *testing.T) {
	for _, c := range []struct {
		file  string
		cause Cause
	}{
		{"run.cgroup", CauseGoverned},
		{"lookalike.cgroup", CauseGoverned},
		{"outside-ns.cgroup", CausePathAboveRoot},
		{"v1only.cgroup", CausePathMalformed},
		{"two-unified.cgroup", CausePathMalformed},
		{"relative.cgroup", CausePathMalformed},
		{"deleted.cgroup", CausePathMalformed},
		{"empty.cgroup", CausePathMalformed},
	} {
		for _, ino := range []uint64{InitCgroupNS, otherNS} {
			f := wslShell()
			f.cgroup, f.ns.Ino = fixture(t, c.file), ino
			want(t, c.file, Decide(f), Inside, c.cause)
			if !slices.Equal(f.calls, []string{"cgroup"}) {
				t.Errorf("%s: Decide read %v; want the cgroup file alone", c.file, f.calls)
			}
		}
	}
	f := wslShell()
	f.cgroup, f.cgroupErr = nil, os.ErrPermission
	got := Decide(f)
	want(t, "unreadable", got, Inside, CausePathUnreadable)
	if !errors.Is(got.err, os.ErrPermission) || !slices.Equal(f.calls, []string{"cgroup"}) {
		t.Errorf("unreadable: err %v, reads %v; want the read's error and no other read", got.err, f.calls)
	}
	for _, shape := range []string{
		"0::/tego.slice/tego-a.slice/run-x.scope\n", "0::/user.slice/tego.slice/x/adopt-y.scope/z\n",
		"0::/a/tego.slice/tego-b.slice\n", "0::/tego/agent/run\n",
	} {
		f := wslShell()
		f.cgroup = []byte(shape)
		want(t, shape, Decide(f), Inside, CauseGoverned)
	}
}

// TestDecideFirstNamespaceReadsNothingElse: in the kernel's first cgroup namespace a path that shows no run is
// outside, and no fact of the other branch is read: ordinary Linux keeps its answers, and the only thing asked beyond
// the path and the namespace file is the gate (on WSL it withholds the answer there too, cause
// wsl-launcher-unproven: a distribution with isolateDistroCgroup=false sits in the first namespace). A namespace file
// that could not be shown to be one is unknown, whatever inode it carries.
func TestDecideFirstNamespaceReadsNothingElse(t *testing.T) {
	for _, file := range []string{"v2.cgroup", "hybrid.cgroup", "root.cgroup"} {
		f := &facts{cgroup: fixture(t, file), ns: Namespace{Dev: nsDev, Ino: InitCgroupNS},
			// Everything the other branch would refuse: none of it may be read.
			real: 0, effective: 1, saved: 2, permitted: 1, seccomp: 2, anchoredErr: ErrUnanchored, withheld: CauseSystemUnproven}
		want(t, file, Decide(f), Outside, "")
		if !slices.Equal(f.calls, []string{"cgroup", "ns", "withheld-first"}) {
			t.Errorf("%s: Decide read %v; want the cgroup file, the namespace and the gate alone", file, f.calls)
		}
		f.calls, f.heldFirst = nil, CauseWSLLauncherUnproven
		want(t, file+" on WSL", Decide(f), Unknown, CauseWSLLauncherUnproven)
		if !slices.Equal(f.calls, []string{"cgroup", "ns", "withheld-first"}) {
			t.Errorf("%s on WSL: Decide read %v; want the cgroup file, the namespace and the gate alone", file, f.calls)
		}
	}
	f := &facts{cgroup: fixture(t, "run.cgroup"), ns: Namespace{Dev: nsDev, Ino: InitCgroupNS}, heldFirst: CauseWSLLauncherUnproven}
	want(t, "a run's path on WSL", Decide(f), Inside, CauseGoverned)
	if !slices.Equal(f.calls, []string{"cgroup"}) {
		t.Errorf("a run's path on WSL: Decide read %v; want the cgroup file alone", f.calls)
	}
	f = wslShell()
	f.ns, f.nsErr = Namespace{Dev: nsDev, Ino: InitCgroupNS}, errors.New("fstatfs: not a namespace file")
	want(t, "a forged namespace file", Decide(f), Unknown, CauseNSUnreadable)
	if !slices.Equal(f.calls, []string{"cgroup", "ns"}) {
		t.Errorf("a forged namespace file: Decide read %v", f.calls)
	}
}

// TestDecideLocalFacts: outside the first namespace, root, differing ids and any permitted capability each answer
// unknown with their cause before the proof is asked for, so no connect is made.
func TestDecideLocalFacts(t *testing.T) {
	for _, c := range []struct {
		name  string
		set   func(*facts)
		cause Cause
		reads []string
	}{
		{"root", func(f *facts) { f.real, f.effective, f.saved = 0, 0, 0 }, CauseRootCaller, []string{"cgroup", "ns", "uids"}},
		{"effective differs", func(f *facts) { f.effective = 0 }, CauseMixedIDs, []string{"cgroup", "ns", "uids"}},
		{"saved differs", func(f *facts) { f.saved = 0 }, CauseMixedIDs, []string{"cgroup", "ns", "uids"}},
		{"real root, dropped", func(f *facts) { f.real = 0 }, CauseMixedIDs, []string{"cgroup", "ns", "uids"}},
		{"one permitted capability", func(f *facts) { f.permitted = 1 << 21 }, CauseCapabilities, []string{"cgroup", "ns", "uids", "caps"}},
		{"capget fails", func(f *facts) { f.permErr = syscall.EPERM }, CauseCapabilities, []string{"cgroup", "ns", "uids", "caps"}},
	} {
		f := wslShell()
		c.set(f)
		got := Decide(f)
		want(t, c.name, got, Unknown, c.cause)
		if !slices.Equal(f.calls, c.reads) {
			t.Errorf("%s: Decide read %v; want %v", c.name, f.calls, c.reads)
		}
		if d := Describe(got); d.Seccomp != "" {
			t.Errorf("%s: a seccomp mode %q is recorded, but the rule stopped before reading it", c.name, d.Seccomp)
		}
	}
}

// TestSeccompIsRecordedNotJudged: the signed rule's fact 4c is removed (every ordinary WSL shell carries a filter
// under mirrored networking, row W-FACT-SHELLS-MIRRORED). Outside the first namespace the mode is read after the
// capabilities, whatever it is the rule goes on, and the answer records it for a diagnostic line; in the first
// namespace it is not read at all.
func TestSeccompIsRecordedNotJudged(t *testing.T) {
	all := []string{"cgroup", "ns", "uids", "caps", "seccomp", "anchored", "proof", "withheld"}
	for _, c := range []struct {
		name   string
		mode   int
		err    error
		record string
	}{
		{"no filter", 0, nil, "0"},
		{"strict mode", 1, nil, "1"},
		{"a filter (WSL's mirrored networking)", 2, nil, "2"},
		{"the mode cannot be read", 0, syscall.EINVAL, "unreadable (invalid argument)"},
	} {
		f := wslShell()
		f.seccomp, f.seccompErr = c.mode, c.err
		got := Decide(f)
		want(t, c.name, got, Outside, "")
		if !slices.Equal(f.calls, all) {
			t.Errorf("%s: Decide read %v; want %v", c.name, f.calls, all)
		}
		d := Describe(got)
		if d.Seccomp != c.record || !strings.HasSuffix(d.String(), "; seccomp mode "+c.record+" (recorded, not judged)") {
			t.Errorf("%s: recorded %q, line %q; want %q", c.name, d.Seccomp, d.String(), c.record)
		}
		f = wslShell()
		f.seccomp, f.proof = c.mode, Answer{verdict: Unknown, cause: CauseNoUserManager}
		if d := Describe(Decide(f)); d.Cause != CauseNoUserManager || c.err == nil && d.Seccomp != c.record {
			t.Errorf("%s, no user manager: %+v; want no-user-manager with the mode recorded", c.name, d)
		}
	}
	f := &facts{cgroup: []byte("0::/user.slice\n"), ns: Namespace{Dev: nsDev, Ino: InitCgroupNS}, seccomp: 2}
	if d := Describe(Decide(f)); d.Seccomp != "" || slices.Contains(f.calls, "seccomp") {
		t.Errorf("the first namespace: recorded %q after reads %v; want nothing read", d.Seccomp, f.calls)
	}
}

// TestDecideAnchorAndProof: the path is read again through the anchored /proc and judged again; a read that is not
// anchored is unknown; then the proof's answer is the rule's, unless the gate withholds it. A proof that came back
// as the zero value is a failed probe, never a run.
func TestDecideAnchorAndProof(t *testing.T) {
	all := []string{"cgroup", "ns", "uids", "caps", "seccomp", "anchored", "proof", "withheld"}
	f := wslShell()
	want(t, "every fact holds", Decide(f), Outside, "")
	if !slices.Equal(f.calls, all) {
		t.Errorf("every fact holds: Decide read %v; want %v", f.calls, all)
	}
	for _, c := range []Cause{CauseWSLLauncherUnproven, CauseSystemUnproven} {
		f = wslShell()
		f.withheld = c
		want(t, "the gate", Decide(f), Unknown, c)
		if slices.Contains(f.calls, "withheld-first") {
			t.Errorf("the gate beyond the first namespace was asked as the first namespace's: %v", f.calls)
		}
	}

	for _, c := range []struct {
		name    string
		set     func(*facts)
		verdict Verdict
		cause   Cause
		last    string
	}{
		{"unanchored", func(f *facts) { f.anchoredErr = errors.Join(ErrUnanchored, syscall.EXDEV) }, Unknown, CauseProcUnanchored, "anchored"},
		{"no openat2", func(f *facts) { f.anchoredErr = errors.Join(ErrUnanchored, syscall.ENOSYS) }, Unknown, CauseProcUnanchored, "anchored"},
		{"anchored read fails", func(f *facts) { f.anchoredErr = syscall.ESRCH }, Inside, CausePathUnreadable, "anchored"},
		{"the anchored path shows a run", func(f *facts) { f.anchored = fixture(t, "run.cgroup") }, Inside, CauseGoverned, "anchored"},
		{"the anchored path is above the root", func(f *facts) { f.anchored = fixture(t, "outside-ns.cgroup") }, Inside, CausePathAboveRoot, "anchored"},
		{"the anchored file is malformed", func(f *facts) { f.anchored = fixture(t, "two-unified.cgroup") }, Inside, CausePathMalformed, "anchored"},
		{"the proof failed", func(f *facts) { f.proof = Answer{verdict: Unknown, cause: CausePeerElsewhere} }, Unknown, CausePeerElsewhere, "proof"},
		{"the proof is the zero value", func(f *facts) { f.proof = Answer{} }, Unknown, CauseProbeError, "proof"},
		{"the proof has no cause", func(f *facts) { f.proof = Answer{verdict: Unknown} }, Unknown, CauseProbeError, "proof"},
	} {
		f := wslShell()
		f.withheld = CauseWSLLauncherUnproven // never reached: a failed answer keeps its own cause
		c.set(f)
		want(t, c.name, Decide(f), c.verdict, c.cause)
		if f.calls[len(f.calls)-1] != c.last {
			t.Errorf("%s: the last read was %q of %v; want %q", c.name, f.calls[len(f.calls)-1], f.calls, c.last)
		}
	}
}

// TestDescribeProbeTime: the time a probe took travels with its answer through the rest of the rule, the gate's
// unknown included, and the description's line says it; an answer no probe made says nothing of one.
func TestDescribeProbeTime(t *testing.T) {
	const took = 377700 * time.Microsecond
	for _, c := range []struct {
		name  string
		proof Answer
		held  Cause
		want  string
	}{
		{"outside", WithProbeTime(Answer{verdict: Outside}, took), "", "outside; seccomp mode 0 (recorded, not judged); probe took 377.7 ms"},
		{"held by the gate", WithProbeTime(Answer{verdict: Outside}, took), CauseWSLLauncherUnproven,
			"unknown, wsl-launcher-unproven; seccomp mode 0 (recorded, not judged); probe took 377.7 ms"},
		{"a failed probe", WithProbeTime(Answer{verdict: Unknown, cause: CauseNoUserManager}, took), "",
			"unknown, no-user-manager; seccomp mode 0 (recorded, not judged); probe took 377.7 ms"},
		{"a causeless proof", WithProbeTime(Answer{}, took), "", "unknown, probe-error; seccomp mode 0 (recorded, not judged); probe took 377.7 ms"},
	} {
		f := wslShell()
		f.proof, f.withheld = c.proof, c.held
		if got := Describe(Decide(f)).String(); got != c.want {
			t.Errorf("%s: %q; want %q", c.name, got, c.want)
		}
	}
	if got := Describe(Answer{verdict: Outside}).String(); got != "outside" {
		t.Errorf("an answer no probe made: %q", got)
	}
	if a := WithProbeTime(Answer{verdict: Unknown, cause: CauseProbeTimeout}, took); a.Outside() {
		t.Error("WithProbeTime made an outside answer")
	}
}

// probe is a table's Prober; it records every read Prove made.
type probe struct {
	nsType     int
	nsTypeErr  error
	owner      Owner
	ownerErr   error
	init       []byte
	initErr    error
	connectErr error
	peerUID    int
	peerPID    int
	credErr    error
	pidfdErr   error
	shown      []int // the Pid: line at the first and the second read
	shownErr   error
	peerCg     []byte
	peerCgErr  error
	exited     bool
	pollErr    error
	calls      []string
}

func (p *probe) NSType() (int, error) {
	p.calls = append(p.calls, "nstype")
	return p.nsType, p.nsTypeErr
}
func (p *probe) Owner() (Owner, error) {
	p.calls = append(p.calls, "owner")
	return p.owner, p.ownerErr
}
func (p *probe) InitCgroup() ([]byte, error) {
	p.calls = append(p.calls, "init")
	return p.init, p.initErr
}
func (p *probe) Connect() error { p.calls = append(p.calls, "connect"); return p.connectErr }
func (p *probe) PeerCred() (int, int, error) {
	p.calls = append(p.calls, "cred")
	return p.peerUID, p.peerPID, p.credErr
}
func (p *probe) PeerPidfd() error { p.calls = append(p.calls, "pidfd"); return p.pidfdErr }
func (p *probe) PidfdPID() (int, error) {
	p.calls = append(p.calls, "fdinfo")
	n := 0
	for _, c := range p.calls {
		if c == "fdinfo" {
			n++
		}
	}
	if p.shownErr != nil {
		return 0, p.shownErr
	}
	return p.shown[min(n, len(p.shown))-1], nil
}
func (p *probe) PeerCgroup(int) ([]byte, error) {
	p.calls = append(p.calls, "peercgroup")
	return p.peerCg, p.peerCgErr
}
func (p *probe) PeerExited() (bool, error) {
	p.calls = append(p.calls, "poll")
	return p.exited, p.pollErr
}

const managerPID = 403

// settled is a probe on a settled WSL session: every fact holds.
func settled() *probe {
	return &probe{nsType: CgroupNSType, owner: Owner{NSFS: true, Dev: nsDev, Ino: InitUserNS}, init: []byte(initFile),
		peerUID: testUID, peerPID: managerPID, shown: []int{managerPID, managerPID},
		peerCg: []byte("0::" + ManagerCgroup(testUID) + "\n")}
}

var everyProbeRead = []string{"nstype", "owner", "init", "connect", "cred", "pidfd", "fdinfo", "peercgroup", "fdinfo", "poll"}

// TestProve walks facts (a), (b) and (c'): each failure is unknown with its cause, nothing after the failing read is
// made (no socket after a failed (b), no read of the peer before it is identified), and only the settled session is
// outside.
func TestProve(t *testing.T) {
	ns := Namespace{Dev: nsDev, Ino: otherNS}
	p := settled()
	want(t, "a settled session", Prove(p, ns, testUID), Outside, "")
	if !slices.Equal(p.calls, everyProbeRead) {
		t.Errorf("a settled session: Prove read %v; want %v", p.calls, everyProbeRead)
	}
	manager := ManagerCgroup(testUID)
	if manager != "/user.slice/user-1000.slice/user@1000.service/init.scope" || ManagerSocket(testUID) != "/run/user/1000/systemd/private" {
		t.Fatalf("the manager's cgroup and socket for uid 1000: %q, %q", manager, ManagerSocket(testUID))
	}
	cg := func(path string) []byte { return []byte("0::" + path + "\n") }
	for _, c := range []struct {
		name  string
		set   func(*probe)
		cause Cause
		reads int // how many of everyProbeRead were made
	}{
		// (a)
		{"NS_GET_NSTYPE fails", func(p *probe) { p.nsTypeErr = syscall.ENOTTY }, CauseUserNamespace, 1},
		{"another namespace type", func(p *probe) { p.nsType = 0x10000000 }, CauseUserNamespace, 1},
		{"NS_GET_USERNS is EPERM", func(p *probe) { p.ownerErr = syscall.EPERM }, CauseUserNamespace, 2},
		{"an owner that is a child user namespace", func(p *probe) { p.owner.Ino = 0xF0000123 }, CauseUserNamespace, 2},
		{"a result that is no namespace file", func(p *probe) { p.owner.NSFS = false }, CauseUserNamespace, 2},
		{"an owner on another device", func(p *probe) { p.owner.Dev = nsDev + 1 }, CauseUserNamespace, 2},
		// (b): no socket is touched after a failure
		{"pid 1 hidden (ENOENT)", func(p *probe) { p.initErr = syscall.ENOENT }, CauseInitUnreadable, 3},
		{"pid 1 hidden (EACCES)", func(p *probe) { p.initErr = syscall.EACCES }, CauseInitUnreadable, 3},
		{"pid 1 hidden (EPERM)", func(p *probe) { p.initErr = syscall.EPERM }, CauseInitUnreadable, 3},
		{"pid 1 read crosses a mount", func(p *probe) { p.initErr = errors.Join(ErrUnanchored, syscall.EXDEV) }, CauseProcUnanchored, 3},
		{"pid 1 below init.scope", func(p *probe) { p.init = cg("/init.scope/x") }, CauseInitNotAtRoot, 3},
		{"pid 1 above the root", func(p *probe) { p.init = cg("/../init.scope") }, CauseInitNotAtRoot, 3},
		{"pid 1 with trailing text", func(p *probe) { p.init = []byte("0::/init.scope \n") }, CauseInitNotAtRoot, 3},
		{"pid 1 with two 0:: lines", func(p *probe) { p.init = []byte(initFile + initFile) }, CauseInitNotAtRoot, 3},
		{"pid 1 in a removed cgroup", func(p *probe) { p.init = cg("/init.scope (deleted)") }, CauseInitNotAtRoot, 3},
		{"pid 1 at the root (no systemd)", func(p *probe) { p.init = cg("/") }, CauseInitNotAtRoot, 3},
		{"pid 1 of a run's own tree", func(p *probe) { p.init = cg("/../../../init.scope") }, CauseInitNotAtRoot, 3},
		// (c') the connect
		{"no socket", func(p *probe) { p.connectErr = syscall.ENOENT }, CauseNoUserManager, 4},
		{"no runtime folder", func(p *probe) { p.connectErr = syscall.ENOTDIR }, CauseNoUserManager, 4},
		{"nobody listens", func(p *probe) { p.connectErr = syscall.ECONNREFUSED }, CauseManagerNotListening, 4},
		{"a full queue to the deadline", func(p *probe) { p.connectErr = syscall.EAGAIN }, CauseManagerBusy, 4},
		{"refused (EACCES)", func(p *probe) { p.connectErr = syscall.EACCES }, CauseSocketRefused, 4},
		{"refused (EPERM)", func(p *probe) { p.connectErr = syscall.EPERM }, CauseSocketRefused, 4},
		{"another connect error", func(p *probe) { p.connectErr = syscall.ENOBUFS }, CauseProbeError, 4},
		// (c') the listener
		{"SO_PEERCRED fails", func(p *probe) { p.credErr = syscall.ENOTCONN }, CausePeerUnidentified, 5},
		{"another uid listens", func(p *probe) { p.peerUID = testUID + 1 }, CausePeerUID, 5},
		{"another uid, pid 0", func(p *probe) { p.peerUID, p.peerPID = 0, 0 }, CausePeerUID, 5},
		{"pid 0 (another pid namespace)", func(p *probe) { p.peerPID = 0 }, CausePeerUnidentified, 5},
		{"no SO_PEERPIDFD", func(p *probe) { p.pidfdErr = syscall.ENOPROTOOPT }, CauseNoPeerPidfd, 6},
		{"SO_PEERPIDFD fails", func(p *probe) { p.pidfdErr = syscall.EINVAL }, CausePeerUnidentified, 6},
		{"the pidfd shows a reaped process", func(p *probe) { p.shown = []int{-1} }, CausePeerUnidentified, 7},
		{"the pidfd shows no pid here", func(p *probe) { p.shown = []int{0} }, CausePeerUnidentified, 7},
		{"the pidfd shows another pid", func(p *probe) { p.shown = []int{managerPID + 1} }, CausePeerUnidentified, 7},
		{"the fdinfo cannot be read", func(p *probe) { p.shownErr = ErrNoPidLine }, CausePeerUnidentified, 7},
		{"the peer's cgroup cannot be read", func(p *probe) { p.peerCgErr = syscall.ESRCH }, CausePeerUnidentified, 8},
		{"the peer's cgroup names two paths", func(p *probe) { p.peerCg = []byte("0::/a\n0::/b\n") }, CausePeerUnidentified, 8},
		{"another pid after the read", func(p *probe) { p.shown = []int{managerPID, managerPID + 1} }, CausePeerUnidentified, 9},
		{"reaped during the read", func(p *probe) { p.shown = []int{managerPID, -1} }, CausePeerUnidentified, 9},
		{"exit seen by poll", func(p *probe) { p.exited = true }, CausePeerUnidentified, 10},
		{"poll fails", func(p *probe) { p.pollErr = syscall.EBADF }, CausePeerUnidentified, 10},
		// (c') the path
		{"a listener in an app scope", func(p *probe) { p.peerCg = cg("/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope") }, CausePeerElsewhere, 10},
		{"a listener in a session scope", func(p *probe) { p.peerCg = cg("/user.slice/user-1000.slice/session-3.scope") }, CausePeerElsewhere, 10},
		{"a listener in a run's scope", func(p *probe) {
			p.peerCg = cg("/user.slice/user-1000.slice/user@1000.service/tego.slice/tego-a.slice/run-r.scope")
		}, CausePeerElsewhere, 10},
		{"a listener where WSL puts shells", func(p *probe) { p.peerCg = cg("/non-systemd") }, CausePeerElsewhere, 10},
		{"another uid's manager path", func(p *probe) { p.peerCg = cg(ManagerCgroup(testUID + 1)) }, CausePeerElsewhere, 10},
		{"one more segment", func(p *probe) { p.peerCg = cg(manager + "/x") }, CausePeerElsewhere, 10},
		{"a trailing slash", func(p *probe) { p.peerCg = cg(manager + "/") }, CausePeerElsewhere, 10},
		{"the host's manager seen from a container", func(p *probe) { p.peerCg = cg("/.." + manager) }, CausePeerElsewhere, 10},
	} {
		p := settled()
		c.set(p)
		want(t, c.name, Prove(p, ns, testUID), Unknown, c.cause)
		if !slices.Equal(p.calls, everyProbeRead[:c.reads]) {
			t.Errorf("%s: Prove read %v; want %v", c.name, p.calls, everyProbeRead[:c.reads])
		}
	}
	// A hybrid file (cgroup v1 lines and one 0:: line) passes for pid 1 and for the manager.
	p = settled()
	p.init = []byte("12:pids:/\n1:name=systemd:/init.scope\n" + initFile)
	p.peerCg = append([]byte("5:freezer:/\n"), p.peerCg...)
	want(t, "hybrid files", Prove(p, ns, testUID), Outside, "")
}

// TestCauseWords: every cause has words; the lines a person can act on come first for no systemd, a session that is
// not up and root; and "a governed agent" may be said only when the path shows a run.
func TestCauseWords(t *testing.T) {
	causes := []Cause{CausePathUnreadable, CausePathMalformed, CausePathAboveRoot, CauseGoverned, CauseNSUnreadable,
		CauseMixedIDs, CauseRootCaller, CauseCapabilities, CauseProcUnanchored, CauseUserNamespace,
		CauseInitUnreadable, CauseInitNotAtRoot, CauseNoUserManager, CauseManagerNotListening, CauseManagerBusy,
		CauseSocketRefused, CauseProbeError, CausePeerUID, CausePeerUnidentified, CauseNoPeerPidfd, CausePeerElsewhere,
		CauseProbeTimeout, CauseWSLLauncherUnproven, CauseSystemUnproven}
	if len(causes) != len(causeWords) {
		t.Errorf("%d causes listed, %d have words", len(causes), len(causeWords))
	}
	plain := map[Cause]bool{CauseInitNotAtRoot: true, CauseNoUserManager: true, CauseManagerNotListening: true, CauseRootCaller: true}
	for _, c := range causes {
		a := Answer{verdict: Unknown, cause: c, err: syscall.ENOENT}
		if c == CauseGoverned || strings.HasPrefix(string(c), "path-") {
			a.verdict = Inside
		}
		w := Why(a)
		if causeWords[c] == "" || !strings.Contains(w, causeWords[c]) || !strings.Contains(w, syscall.ENOENT.Error()) {
			t.Errorf("cause %q: words %q", c, w)
		}
		if strings.Contains(strings.ToLower(w), "sandbox") {
			t.Errorf("cause %q: its words say sandbox: %q", c, w)
		}
		if SaysGoverned(a) != (c == CauseGoverned) {
			t.Errorf("cause %q: SaysGoverned = %v", c, SaysGoverned(a))
		}
		if PlainFirst(a) != plain[c] {
			t.Errorf("cause %q: PlainFirst = %v", c, PlainFirst(a))
		}
	}
	if w := Why(Answer{verdict: Outside}); w != "" {
		t.Errorf("outside has words: %q", w)
	}
	if w := Why(Answer{}); w == "" || SaysGoverned(Answer{}) {
		t.Errorf("the zero answer: words %q, governed %v; want words and not governed", w, SaysGoverned(Answer{}))
	}
	if !strings.Contains(causeWords[CauseSystemUnproven], "this kind of system has not been proven") ||
		Advice(Unproven(CauseSystemUnproven, nil)) == "" {
		t.Errorf("the gate's words outside WSL: %q, advice %q", causeWords[CauseSystemUnproven], Advice(Unproven(CauseSystemUnproven, nil)))
	}
	if !strings.Contains(causeWords[CauseWSLLauncherUnproven], "not proven yet") {
		t.Errorf("the WSL gate's words do not say the launcher's refusal is not proven yet: %q", causeWords[CauseWSLLauncherUnproven])
	}
}

// TestFdinfoPid: one Pid: line holding one number, or an error.
func TestFdinfoPid(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int
		ok   bool
	}{
		{"pos:\t0\nflags:\t02000002\nmnt_id:\t16\nino:\t403\nPid:\t403\nNSpid:\t403\n", 403, true},
		{"Pid:\t-1\nNSpid:\t0\n", -1, true},
		{"Pid:\t0\n", 0, true},
		{"Pid: 12", 12, true},
		{"NSpid:\t403\n", 0, false},
		{"Pid:\t403\nPid:\t404\n", 0, false},
		{"Pid:\t403 404\n", 0, false},
		{"Pid:\t\n", 0, false},
		{"Pid:\tx\n", 0, false},
		{"", 0, false},
	} {
		got, err := FdinfoPid([]byte(c.in))
		if got != c.want || (err == nil) != c.ok || err != nil && !errors.Is(err, ErrNoPidLine) {
			t.Errorf("FdinfoPid(%q) = %d, %v; want %d, ok %v", c.in, got, err, c.want, c.ok)
		}
	}
}

// FuzzFdinfoPid: the parser never panics, and a number it returns stood alone on the one Pid: line.
func FuzzFdinfoPid(f *testing.F) {
	for _, s := range []string{"Pid:\t403\n", "Pid:\t-1\nNSpid:\t0\n", "Pid:\t1\nPid:\t2\n", "pos:\t0\n", ""} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := FdinfoPid(b)
		if err != nil {
			if got != 0 || !errors.Is(err, ErrNoPidLine) {
				t.Fatalf("FdinfoPid(%q) = %d, %v", b, got, err)
			}
			return
		}
		if n := strings.Count("\n"+string(b), "\nPid:"); n != 1 {
			t.Fatalf("FdinfoPid(%q) = %d with %d Pid: lines", b, got, n)
		}
	})
}
