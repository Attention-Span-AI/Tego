// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runscope"
)

// hiddenNS is a proc tree whose namespace files are hidden from this process, as an undumpable peer's are, and whose
// proof of why is what the test says: proved, or an error.
type hiddenNS struct {
	dirFS
	proved   bool
	proofErr error
}

func (h hiddenNS) cgroupNS(int) (uint64, error) { return 0, nil }

func (h hiddenNS) undumpable(int, int) (bool, error) { return h.proved, h.proofErr }

// TestUndumpablePeerIsJudgedByTheRest: a peer whose cgroup namespace /proc hides because its dumpable flag is 0 is
// identified with Undumpable set, and Refuse then judges everything else about it exactly as it judges a dumpable
// peer: the uid, the run test over the cgroup path of every thread, the path above this namespace's root, this process's
// own namespace rules. A peer whose namespace is hidden for a reason the kernel's files do not show, and one that shows
// a namespace and claims the flag, is refused as before. (ADR 0100 (7), amended 2026-11-22.)
func TestUndumpablePeerIsJudgedByTheRest(t *testing.T) {
	server, _ := selfConn(t)
	pid := os.Getpid()
	// refuse is pure, so the owner is a fixed ordinary uid: the real euid would be 0 in the root suites, where an
	// undumpable root peer is (rightly) not identified.
	const owner = 1000
	const initial = runscope.InitCgroupNS
	hidden := func(t *testing.T, cgroup string, proved bool, proofErr error) (Peer, error) {
		t.Helper()
		fs, _ := fixtureProc(t, pid, cgroup, 9)
		h := kernel
		h.proc = hiddenNS{dirFS: fs, proved: proved, proofErr: proofErr}
		return h.identify(server)
	}

	for _, c := range []struct {
		name     string
		cgroup   string
		proved   bool
		proofErr error
		want     string // the Refusal code of Identify, "" when it identifies
		refuse   string // Refuse's code once identified
	}{
		{"the person's terminal, undumpable", terminalCgroup, true, nil, "", ""},
		{"a run's agent, undumpable", runCgroup, true, nil, "", CodeRunMember},
		{"an adopted agent, undumpable", "0::/tego.slice/tego-a.slice/adopt-" + testRun + ".scope\n", true, nil, "", CodeRunMember},
		{"a look-alike, undumpable", lookAlikeCgroup, true, nil, "", CodeRunMember},
		{"below a run's scope, undumpable", "0::/user.slice/user-1000.slice/user@1000.service/tego.slice/tego-a.slice/run-" + testRun + ".scope/x\n", true, nil, "", CodeRunMember},
		{"above this namespace's root, undumpable", "0::/../../user.slice/x.scope\n", true, nil, "", CodeCgroupNS},
		{"hidden for a reason the files do not show", terminalCgroup, false, nil, "", CodeCgroupNS},
		{"hidden, and the proof cannot be read", terminalCgroup, false, errors.New("boom"), CodeUnidentified, ""},
	} {
		p, err := hidden(t, c.cgroup, c.proved, c.proofErr)
		if codeOf(err) != c.want || (err == nil) != (c.want == "") {
			t.Errorf("%s: identify = %+v, %v; want code %q", c.name, p, err, c.want)
			continue
		}
		if err != nil {
			continue
		}
		if p.CgroupNS != 0 || p.Undumpable != c.proved {
			t.Errorf("%s: identify = %+v; want namespace 0 and Undumpable %v", c.name, p, c.proved)
		}
		p.UID = owner
		got := refuse(p, owner, initial, nil, neverAsked(t, c.name), notHeld)
		if codeOf(got) != c.refuse || (got == nil) != (c.refuse == "") {
			t.Errorf("%s: refuse = %v, want code %q", c.name, got, c.refuse)
		}
	}

	// The proof is asked for only when the namespace is hidden: a readable one is compared, as ever.
	var asked int
	fs, ino := fixtureProc(t, pid, terminalCgroup, 9)
	h := kernel
	h.proc = proofCounting{dirFS: fs, asked: &asked}
	p, err := h.identify(server)
	if err != nil || p.Undumpable || p.CgroupNS != ino || asked != 0 {
		t.Errorf("identify of a peer with a readable namespace = %+v, %v (proof asked %d times); want it compared, never proved", p, err, asked)
	}
}

// proofCounting is a tree with a readable namespace that counts how often it is asked for the proof.
type proofCounting struct {
	dirFS
	asked *int
}

func (p proofCounting) undumpable(int, int) (bool, error) { *p.asked++; return true, nil }

// TestRefuseUndumpable is Refuse's table over what Identify hands it: the flag stands for the hidden namespace alone,
// the uid, the run test and this process's own namespace answer are judged as for anyone, and the flag with a namespace
// shown is not a peer that was identified.
func TestRefuseUndumpable(t *testing.T) {
	const owner, ns = 1000, runscope.InitCgroupNS
	ok := Peer{UID: owner, PID: 42, Cgroup: userApp + "/app-term.scope", CgroupNS: 0, Undumpable: true, StartBootNS: 1}
	with := func(f func(*Peer)) Peer { p := ok; f(&p); return p }
	for _, c := range []struct {
		name string
		p    Peer
		self uint64
		want string
	}{
		{"the dashboard: undumpable, outside every run", ok, ns, ""},
		{"a pid-fallback peer is served, and disclosed by its caller", with(func(p *Peer) { p.PidfdFallback = true }), ns, ""},
		{"hidden and not shown undumpable", with(func(p *Peer) { p.Undumpable = false }), ns, CodeCgroupNS},
		{"undumpable and a namespace shown", with(func(p *Peer) { p.CgroupNS = ns }), ns, CodeUnidentified},
		{"undumpable in another namespace's number", with(func(p *Peer) { p.CgroupNS = ns + 1 }), ns, CodeUnidentified},
		{"another uid", with(func(p *Peer) { p.UID = 1001 }), ns, CodeUnmappedUID},
		{"root", with(func(p *Peer) { p.UID = 0 }), ns, CodeUnmappedUID},
		{"a run's agent", with(func(p *Peer) { p.Cgroup = runCgroup[3 : len(runCgroup)-1] }), ns, CodeRunMember},
		{"below a run's scope", with(func(p *Peer) { p.Cgroup = runCgroup[3:len(runCgroup)-1] + "/sub.scope" }), ns, CodeRunMember},
		{"an adoption", with(func(p *Peer) { p.Cgroup = "/tego.slice/tego-a.slice/adopt-" + testRun + ".scope" }), ns, CodeRunMember},
		{"a Docker run", with(func(p *Peer) { p.Cgroup = "/tego/a/" + testRun + "/c1" }), ns, CodeRunMember},
		{"a look-alike", with(func(p *Peer) { p.Cgroup = lookAlikeCgroup[3 : len(lookAlikeCgroup)-1] }), ns, CodeRunMember},
		{"above this namespace's root", with(func(p *Peer) { p.Cgroup = "/../../x.scope" }), ns, CodeCgroupNS},
		{"no cgroup", with(func(p *Peer) { p.Cgroup = "" }), ns, CodeUnidentified},
		{"no pid", with(func(p *Peer) { p.PID = 0 }), ns, CodeUnidentified},
		{"this process's namespace unreadable", ok, 0, CodeCgroupNS},
	} {
		err := refuse(c.p, owner, c.self, nil, neverAsked(t, c.name), notHeld)
		if got := codeOf(err); got != c.want || (err == nil) != (c.want == "") {
			t.Errorf("%s: refuse = %v, want code %q", c.name, err, c.want)
		}
	}
	// Root is served beside the socket's owner (the broker's uid rule), but root's per-process files belong to root
	// whether or not it is dumpable, so the kernel's files never show a root process undumpable: the flag on root is
	// no reading of them.
	if err := refuse(with(func(p *Peer) { p.UID = 0; p.Cgroup = "/user.slice/user-0.slice/session-3.scope" }), 0, ns, nil, neverAsked(t, "root"), notHeld); codeOf(err) != CodeUnidentified {
		t.Errorf("an undumpable root peer: %v, want [%s]", err, CodeUnidentified)
	}
	// This process in a cgroup namespace of its own: served only when its own answer is outside, as any peer is.
	const containerNS = ns + 0x10000001
	inside := func() runscope.Answer { return runscope.Answer{} }
	if err := refuse(ok, owner, containerNS, nil, inside, notHeld); codeOf(err) != CodeCgroupNS {
		t.Errorf("an undumpable peer, this process inside a cgroup namespace of its own and not shown outside: %v, want [%s]", err, CodeCgroupNS)
	}
	// On WSL the gate holds every peer, an undumpable one included.
	onWSL := func() (runscope.Cause, bool) { return runscope.CauseWSLLauncherUnproven, true }
	if err := refuse(ok, owner, ns, nil, neverAsked(t, "the gate"), onWSL); codeOf(err) != CodeCgroupNS {
		t.Errorf("an undumpable peer on WSL with the gate holding: %v, want [%s]", err, CodeCgroupNS)
	}
}

// TestStatusHoldsNothing: an undumpable peer is shown so only when its status file has one Uid line of the connecting
// uid four times and one CapPrm line of zero.
func TestStatusHoldsNothing(t *testing.T) {
	status := func(uid, caps string) []byte {
		return []byte("Name:\tx\nUid:\t" + uid + "\nGid:\t1000\t1000\t1000\t1000\nCapInh:\t0000000000000000\nCapPrm:\t" + caps + "\nCapEff:\t" + caps + "\n")
	}
	const four = "1000\t1000\t1000\t1000"
	for _, c := range []struct {
		name    string
		in      []byte
		want    bool
		wantErr bool
	}{
		{"the person's own, no capability", status(four, "0000000000000000"), true, false},
		{"a saved uid that is root", status("1000\t1000\t0\t1000", "0000000000000000"), false, false},
		{"a real uid that is root", status("0\t1000\t1000\t1000", "0000000000000000"), false, false},
		{"a filesystem uid of another user", status("1000\t1000\t1000\t1001", "0000000000000000"), false, false},
		{"another user's", status("1001\t1001\t1001\t1001", "0000000000000000"), false, false},
		{"a capability held", status(four, "0000000000002000"), false, false},
		{"every capability", status(four, "000001ffffffffff"), false, false},
		{"three uids", status("1000\t1000\t1000", "0000000000000000"), false, false},
		{"no Uid line", []byte("Name:\tx\nCapPrm:\t0000000000000000\n"), false, true},
		{"no CapPrm line", []byte("Name:\tx\nUid:\t" + four + "\n"), false, true},
		{"a Uid line twice", append(status(four, "0000000000000000"), []byte("Uid:\t"+four+"\n")...), false, true},
		{"a CapPrm line twice", append(status(four, "0000000000000000"), []byte("CapPrm:\t0000000000000000\n")...), false, true},
		{"a CapPrm that is no number", status(four, "zz"), false, true},
	} {
		got, err := statusHoldsNothing(c.in, 1000)
		if got != c.want || (err != nil) != c.wantErr {
			t.Errorf("%s: statusHoldsNothing = %v, %v; want %v, error %v", c.name, got, err, c.want, c.wantErr)
		}
	}
}

// TestDirFSUndumpableReadsTheKernelsFiles: over a tree of real files this process owns, a peer whose environ is its own
// is dumpable (false, never the status read), a missing environ is an error, and one owned by another uid goes on to the
// status file.
func TestDirFSUndumpableReadsTheKernelsFiles(t *testing.T) {
	fs, _ := fixtureProc(t, 4242, terminalCgroup, 1)
	dir := filepath.Join(string(fs), "4242")
	if err := os.WriteFile(filepath.Join(dir, "environ"), nil, 0o400); err != nil {
		t.Fatal(err)
	}
	uid := os.Geteuid()
	got, err := fs.undumpable(4242, uid)
	if got || err != nil {
		t.Errorf("undumpable over a peer whose environ is its own = %v, %v; want false, nil", got, err)
	}
	// Another uid than the file's: the file reads as another's (what the kernel shows for an undumpable process), and
	// the status file, which the fixture does not have, decides.
	if got, err := fs.undumpable(4242, uid+1); got || err == nil {
		t.Errorf("undumpable with a status file missing = %v, %v; want false and an error", got, err)
	}
	status := "Name:\tx\nUid:\t" + strings.Repeat(itoa(uid+1)+"\t", 3) + itoa(uid+1) + "\nCapPrm:\t0000000000000000\n"
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o444); err != nil {
		t.Fatal(err)
	}
	if got, err := fs.undumpable(4242, uid+1); !got || err != nil {
		t.Errorf("undumpable of a peer whose environ is another's and whose status is clean = %v, %v; want true, nil", got, err)
	}
	if _, err := fs.undumpable(4243, uid); err == nil {
		t.Error("undumpable of a pid with no directory: no error")
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// TestIdentifyAnUndumpableProcess: a real process that made itself undumpable and connected is identified, on the
// kernel's own files and on the fallback below Linux 6.5: its cgroup path is read as anyone's, its namespace is hidden,
// the files show why, and Refuse serves it as it serves a dumpable peer (unless this test itself runs inside a run). The
// same process dumpable is identified with its namespace and no flag.
func TestIdentifyAnUndumpableProcess(t *testing.T) {
	noFDLeak(t)
	fallback := kernel
	fallback.noPeerPidfd = true
	for _, mode := range []string{"stay", undumpableMode} {
		ln, path := listen(t)
		cmd := startClient(t, mode, path)
		conn := accept(t, ln)
		for name, h := range map[string]host{"kernel": kernel, "fallback": fallback} {
			p, err := h.identify(conn)
			if err != nil {
				t.Errorf("%s, %s: identify = %v", mode, name, err)
				continue
			}
			// A caller with CAP_SYS_PTRACE (root) reads the namespace of an undumpable process, so for it nothing is hidden
			// and nothing is proved: the flag is for the unprivileged broker.
			wantFlag := mode == undumpableMode && os.Geteuid() != 0
			if p.PID != cmd.Process.Pid || p.Undumpable != wantFlag || (p.CgroupNS == 0) != wantFlag || p.Cgroup == "" {
				t.Errorf("%s, %s: identify = %+v; want pid %d, Undumpable %v, a namespace exactly when dumpable", mode, name, p, cmd.Process.Pid, wantFlag)
			}
			own := Self()
			if got := Refuse(p, os.Geteuid()); (got == nil) != own.Outside() {
				t.Errorf("%s, %s: Refuse = %v; this process's own answer: %s", mode, name, got, runscope.Describe(own).Verdict)
			}
			if st, err := proc.New().Stat(p.PID); err != nil || st.StartBootNS() != p.StartBootNS {
				t.Errorf("%s, %s: start time %d, stat %+v, %v", mode, name, p.StartBootNS, st, err)
			}
		}
		_ = conn.Close()
	}
}

// TestAPeerInItsOwnCgroupNamespaceIsReadAtItsTruePlace: the peer's cgroup path is printed in the reader's namespace, not the
// peer's, so a process that makes itself undumpable and unshares a user and cgroup namespace (which shows it "0::/" in its
// own view) is identified at the place it really is, and no flag or namespace moves an agent out of its run's path. This is
// what makes the one comparison Refuse skips for an undumpable peer, its namespace's inode, no decision of where it is.
func TestAPeerInItsOwnCgroupNamespaceIsReadAtItsTruePlace(t *testing.T) {
	ln, path := listen(t)
	cmd := exec.Command(os.Args[0], clientArg, undumpableMode, path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWCGROUP}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Skipf("no user and cgroup namespace to start the child in: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	conn := accept(t, ln)
	p, err := Identify(conn)
	if err != nil {
		t.Fatalf("Identify of an undumpable peer in a user and cgroup namespace of its own: %v", err)
	}
	if want := selfFacts(t).Cgroup; p.Cgroup != want || p.Cgroup == "/" {
		t.Errorf("the peer's cgroup is %q, want this process's own %q (the peer's view of itself is \"/\")", p.Cgroup, want)
	}
	// The child exec'd after CLONE_NEWUSER, so it owns its memory in a user namespace this user owns: its namespace files
	// are readable, nothing is hidden and no flag is set, and the comparison Refuse skips for an undumpable peer is the one
	// that refuses it (ADR 0100 (7), amended 2026-11-22, "Why an agent in a run cannot pass it", item 3).
	own, err := selfCgroupNS()
	if err != nil {
		t.Fatal(err)
	}
	if p.CgroupNS == 0 || p.Undumpable || p.CgroupNS == own {
		t.Fatalf("Identify = %+v (this process's namespace %d); want the peer's own namespace shown, no flag", p, own)
	}
	if got := Refuse(p, os.Geteuid()); codeOf(got) != CodeCgroupNS {
		t.Errorf("Refuse of an undumpable peer in a cgroup namespace of its own that it exec'd into = %v; want [%s]", got, CodeCgroupNS)
	}
}
