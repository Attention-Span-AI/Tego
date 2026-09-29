// SPDX-License-Identifier: Apache-2.0

//go:build integration

package observe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// landlockEnv makes the test binary landlockChild: the base directory it is given and the file it reports each
// action's errno to, separated by a newline (an environment variable cannot hold a NUL).
const landlockEnv = "TEGO_OBSERVE_LANDLOCK_CHILD"

// init runs landlockChild when this binary was started as it, on the thread init runs on: Landlock restricts
// the calling thread, so every action it makes is made from that thread, which the lock keeps its goroutine on.
func init() {
	if spec := os.Getenv(landlockEnv); spec != "" {
		goruntime.LockOSThread()
		os.Exit(landlockChild(spec))
	}
	if spec := os.Getenv(heldEnv); spec != "" {
		goruntime.LockOSThread()
		os.Exit(heldChild(spec))
	}
}

// heldEnv makes the test binary heldChild, as landlockEnv makes it landlockChild.
const heldEnv = "TEGO_OBSERVE_HELD_CHILD"

// heldFailedOpen is a regular file whose open security_file_open allows and the filesystem then refuses: kernfs
// refuses a write open of a file with no store (kernfs_fop_open, EACCES) after the LSM chain, and before do_open's
// truncate, so an O_TRUNC open of it is held and never reaches its truncate hook.
const heldFailedOpen = "/sys/kernel/uevent_seqnum"

// heldChild is the agent of TestIntegrationHeldRecordsAreTheirOwnActions: from one thread, with no other hooked
// event between them, an O_TRUNC open that fails after the chain allowed it and then a truncate(2) of another
// file; a mknod(2) of a regular file and then a plain open of it. It reports each action's errno.
func heldChild(spec string) int {
	base, report, ok := strings.Cut(spec, "\n")
	if !ok {
		return 2
	}
	out, err := os.Create(report)
	if err != nil {
		return 3
	}
	defer out.Close()
	for _, a := range []struct {
		name string
		do   func() error
	}{
		{"failed-trunc-open", func() error { return openClose(heldFailedOpen, unix.O_WRONLY|unix.O_TRUNC, 0) }},
		{"truncate", func() error { return unix.Truncate(filepath.Join(base, "allow/t"), 0) }},
		{"mknod", func() error { return unix.Mknod(filepath.Join(base, "allow/m"), unix.S_IFREG|0o600, 0) }},
		{"open-made", func() error { return openClose(filepath.Join(base, "allow/m"), unix.O_RDONLY, 0) }},
	} {
		err := a.do()
		var errno unix.Errno
		if err != nil && !errors.As(err, &errno) {
			errno = unix.EIO
		}
		fmt.Fprintf(out, "%s %d\n", a.name, int(errno))
	}
	return 0
}

// TestIntegrationHeldRecordsAreTheirOwnActions is ADR 0016 (3)'s one action, one line, where a held record's own
// hook never comes. An O_TRUNC open the chain allowed is held for its truncate; when the open then fails (here in
// kernfs's ->open; fanotify from 6.13 and security_file_post_open are the same shape) the task's next truncate, of
// another file, took the hold: its return became the failed open's verdict and the truncate had no line. And a
// mknod(2) of a regular file is held as an O_CREAT open's create would be; a plain open of the file that followed
// dropped it, and the mknod had no line. Each action is its own line. It runs under each build of trace_proc this
// kernel loads (eachTraceReader).
func TestIntegrationHeldRecordsAreTheirOwnActions(t *testing.T) {
	if !bpf.Available() {
		t.Skipf("needs the compiled objects: %v", bpf.ErrNotGenerated)
	}
	if _, err := os.Stat(heldFailedOpen); err != nil {
		t.Skipf("no %s to fail an open in: %v", heldFailedOpen, err)
	}
	eachTraceReader(t, func(t *testing.T, r bpf.Reader) { heldRecordsAreTheirOwnActions(t, r) })
}

func heldRecordsAreTheirOwnActions(t *testing.T, r bpf.Reader) {
	hash := "held-" + string(r)
	root, maps := pinRoot(t, hash)
	coll := loadTraceProcWhereItLoads(t, maps, r)

	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "allow"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "allow/t"), []byte("content"), 0o666); err != nil {
		t.Fatal(err)
	}
	_, fd, cg := childCgroup(t, "held")
	row := bpf.Run{RunIdx: 20, Descendants: 1, Tier: 2, Record: uint8(bpf.RecordFull)}
	placeRunRings(t, coll, row.RunIdx)
	if err := coll.Maps[bpf.MapRunSet].Update(&cg, &row, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = coll.Maps[bpf.MapRunSet].Delete(&cg) })
	rt := &agent.RuleTable{Record: agent.RecordFull, Tier: backend.TierCgroup, FS: []agent.FSRule{
		{Path: filepath.Join(base, "allow"), Kind: agent.FSWrite, Raw: "./allow"},
	}}
	rec, err := New(Options{Rules: rt, BPFHash: hash, PinRoot: root, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	if err := rec.Start(context.Background(), source.RunRef{ID: "r-held", Agent: "a", CgroupID: cg}, sink); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	report := filepath.Join(t.TempDir(), "report")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), heldEnv+"="+base+"\n"+report)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	if b, err := cmd.CombinedOutput(); err != nil {
		r, _ := os.ReadFile(report)
		t.Fatalf("held child: %v: %s\n%s", err, b, r)
	}
	got := childErrnos(t, report)
	for name, errno := range map[string]unix.Errno{"failed-trunc-open": unix.EACCES, "truncate": 0, "mknod": 0,
		"open-made": 0} {
		if got[name] != int(errno) {
			t.Fatalf("the child's %s returned errno %d, want %d: the cell is not what it says", name, got[name], errno)
		}
	}

	waitDrained(t, rec)
	if err := rec.Stop(); err != nil {
		t.Fatal(err)
	}
	lines := map[string][]record.FSPayload{}
	for _, ev := range sink.byKind(record.KindFS) {
		p := payload[record.FSPayload](t, ev)
		rel := strings.TrimPrefix(p.Path, base+"/")
		lines[rel] = append(lines[rel], p)
		t.Logf("%s op=%s flags=%#x verdict=%s errno=%d", rel, p.Op, p.Flags, ev.Verdict, p.Errno)
	}
	if ls := lines[heldFailedOpen]; len(ls) != 1 || ls[0].Op != record.FSOpen || ls[0].Flags&unix.O_TRUNC == 0 {
		t.Errorf("%s: %+v, want the one O_TRUNC open line the chain allowed", heldFailedOpen, ls)
	}
	if ls := lines["allow/t"]; len(ls) != 1 || ls[0].Op != record.FSTruncate || ls[0].Errno != 0 {
		t.Errorf("allow/t: %+v, want its own truncate line: the failed open's hold took it", ls)
	}
	var mknod, opened int
	for _, p := range lines["allow/m"] {
		switch {
		case p.Op == record.FSOpen && p.Flags&unix.O_CREAT != 0:
			mknod++
		case p.Op == record.FSOpen:
			opened++
		}
	}
	if mknod != 1 || opened != 1 {
		t.Errorf("allow/m: %+v, want the mknod(2)'s line (open with O_CREAT) and the open's", lines["allow/m"])
	}
}

// The actions landlockChild makes after it restricted itself, in order, and the path each makes it on,
// relative to the base directory.
var landlockActions = []struct {
	name string
	path string
}{
	{"read-denied", "deny/secret"},
	{"read-allowed", "allow/ok"},
	{"create-denied", "deny/new"},
	{"unlink-denied", "deny/victim"},
	{"trunc-allowed", "allow/trunc"},
	{"trunc-denied", "wt/f"},
	{"create-allowed", "allow/new"},
}

// landlockChild is the agent of TestIntegrationChainReturnIsTheVerdict: a process that enforces its own
// Landlock domain — every file right beneath allow, the same but truncate beneath wt, nothing anywhere else —
// and then makes landlockActions, reporting the errno of each. It stands for the run's inherited domain (and,
// under wt, for a mechanism the contract does not know of).
func landlockChild(spec string) int {
	parts := strings.Split(spec, "\n")
	if len(parts) != 2 {
		return 2
	}
	base, report := parts[0], parts[1]
	out, err := os.Create(report)
	if err != nil {
		return 3
	}
	defer out.Close()
	abi, err := sys.LandlockABI()
	if err != nil {
		fmt.Fprintf(out, "landlock %v\n", err)
		return 4
	}
	handled := uint64(unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE)
	if abi >= 3 {
		handled |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	attr := sys.LandlockRulesetAttr{Handled_access_fs: handled}
	fd, err := sys.LandlockCreateRuleset(&attr, 0)
	if err != nil {
		fmt.Fprintf(out, "ruleset %v\n", err)
		return 5
	}
	for dir, rights := range map[string]uint64{"allow": handled, "wt": handled &^ unix.LANDLOCK_ACCESS_FS_TRUNCATE} {
		d, err := unix.Open(filepath.Join(base, dir), unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil || sys.LandlockAddRule(fd, unix.LANDLOCK_RULE_PATH_BENEATH, unsafe.Pointer(&unix.LandlockPathBeneathAttr{Allowed_access: rights, Parent_fd: int32(d)}), 0) != nil {
			fmt.Fprintf(out, "rule %s %v\n", dir, err)
			return 6
		}
		_ = unix.Close(d)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return 7
	}
	if err := sys.LandlockRestrictSelf(fd, 0); err != nil {
		fmt.Fprintf(out, "restrict %v\n", err)
		return 8
	}
	fmt.Fprintf(out, "abi %d\n", abi)
	for _, a := range landlockActions {
		p := filepath.Join(base, a.path)
		var err error
		switch a.name {
		case "read-denied", "read-allowed":
			err = openClose(p, unix.O_RDONLY, 0)
		case "create-denied", "create-allowed":
			err = openClose(p, unix.O_CREAT|unix.O_WRONLY, 0o644)
		case "unlink-denied":
			err = unix.Unlink(p)
		case "trunc-allowed", "trunc-denied":
			err = openClose(p, unix.O_WRONLY|unix.O_TRUNC, 0)
		}
		var errno unix.Errno
		if err != nil && !errors.As(err, &errno) {
			errno = unix.EIO
		}
		fmt.Fprintf(out, "%s %d\n", a.name, int(errno))
	}
	return 0
}

// openClose opens a path and closes what it opened.
func openClose(path string, flags, mode int) error {
	fd, err := unix.Open(path, flags|unix.O_CLOEXEC, uint32(mode))
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

// TestIntegrationChainReturnIsTheVerdict is ADR 0016 step 2 on the real objects, as root: the recorder's fs line
// is the kernel's own verdict, the return of the LSM chain its fexit programs read after Landlock decided, and
// not the recorder's inference.
//
// A child in the run's cgroup restricts itself with Landlock (landlockChild) and then reads, creates, unlinks and
// truncates. The contract the recorder holds says write: [./allow, ./wt] and deny_read: [./deny]. What Landlock
// refused beneath deny is recorded refused from the chain's -EACCES, with the contract's reason; what it allowed
// is allow; the truncate it refused beneath wt, which the contract grants, is observed with by: other and the
// errno, since no Tego mechanism explains it. Each action is one line: the O_CREAT open's refused create is its
// mknod line, the created file's open drops the create it held, and an O_TRUNC open is one open line with the
// truncate's return. Under record: off the refusals Tego explains are still recorded, and nothing else. It runs
// under each build of trace_proc this kernel loads (eachTraceReader).
func TestIntegrationChainReturnIsTheVerdict(t *testing.T) {
	if !bpf.Available() {
		t.Skipf("needs the compiled objects: %v", bpf.ErrNotGenerated)
	}
	if _, err := sys.LandlockABI(); err != nil {
		t.Skipf("Landlock is not enabled: %v", err)
	}
	eachTraceReader(t, func(t *testing.T, r bpf.Reader) {
		hash := "chain-" + string(r)
		root, maps := pinRoot(t, hash)
		coll := loadTraceProcWhereItLoads(t, maps, r)
		for i, mode := range []agent.RecordMode{agent.RecordFull, agent.RecordOff} {
			t.Run(string(mode), func(t *testing.T) {
				runLandlockChild(t, coll, root, hash, uint32(10+i), mode)
			})
		}
	})
}

// eachTraceReader runs f as a subtest per build of trace_proc (bpf.Readers), skipping the one this kernel cannot
// load: the rdonly build without bpf_rdonly_cast and bpf_loop in BTF, the probe build under lockdown=confidentiality
// (ADR 0024's tier-2 note). The records both builds write must be the same.
func eachTraceReader(t *testing.T, f func(t *testing.T, r bpf.Reader)) {
	choice := bpf.KernelReader()
	for _, r := range bpf.Readers {
		t.Run(string(r), func(t *testing.T) {
			switch {
			case r == bpf.ReaderRdonly && choice.Reader != bpf.ReaderRdonly:
				t.Skip("this kernel cannot load trace_proc's rdonly build: " + choice.Why)
			case r == bpf.ReaderProbe && choice.Confidentiality:
				t.Skip("lockdown=confidentiality refuses the probe build's bpf_probe_read_kernel")
			}
			f(t, r)
		})
	}
}

// loadTraceProcWhereItLoads is loadTraceProc on any kernel: one reader's build of trace_proc without the programs
// whose function the kernel lacks, as the backend loads it (security_file_truncate below 6.2).
func loadTraceProcWhereItLoads(t *testing.T, maps string, r bpf.Reader) *ebpf.Collection {
	t.Helper()
	return loadTraceProcAttaching(t, maps, r, nil)
}

// loadTraceProcAttaching is loadTraceProcWhereItLoads attaching only the programs attach reports (every loaded one
// for a nil attach): a build whose recorder fexit programs are not attached (TIER3-PLAN T9b).
func loadTraceProcAttaching(t *testing.T, maps string, r bpf.Reader, attach func(prog string) bool) *ebpf.Collection {
	t.Helper()
	spec, err := bpf.LoadReader(bpf.ObjectTraceProc, r)
	if err != nil {
		t.Fatal(err)
	}
	kspec, err := btf.LoadKernelSpec()
	if err != nil {
		t.Fatal(err)
	}
	for name, fn := range bpf.OptionalTracePrograms {
		var f *btf.Func
		if kspec.TypeByName(fn, &f) != nil {
			t.Logf("%s is not in this kernel: %s is left out", fn, name)
			delete(spec.Programs, name)
		}
	}
	dropAbsentExecResults(spec)
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: maps}})
	if err != nil {
		t.Fatalf("load %s: %v", bpf.ObjectTraceProc, err)
	}
	t.Cleanup(coll.Close)
	for _, name := range bpf.TracePrograms {
		p := coll.Programs[name]
		if p == nil || (attach != nil && !attach(name)) {
			continue
		}
		l, err := bpf.AttachTrace(name, p)
		if err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
		t.Cleanup(func() { _ = l.Close() })
	}
	return coll
}

// runLandlockChild runs landlockChild once in a run of the given record mode at slot, and checks its lines.
func runLandlockChild(t *testing.T, coll *ebpf.Collection, root, hash string, slot uint32, mode agent.RecordMode) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"allow", "wt", "deny"} {
		if err := os.Mkdir(filepath.Join(base, d), 0o777); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"deny/secret", "allow/ok", "deny/victim", "allow/trunc", "wt/f"} {
		if err := os.WriteFile(filepath.Join(base, f), []byte("content"), 0o666); err != nil {
			t.Fatal(err)
		}
	}
	_, fd, cg := childCgroup(t, "chain-"+string(mode))
	kmode := bpf.RecordFull
	if mode == agent.RecordOff {
		kmode = bpf.RecordOff
	}
	row := bpf.Run{RunIdx: slot, Descendants: 1, Tier: 2, Record: uint8(kmode)}
	placeRunRings(t, coll, row.RunIdx)
	if err := coll.Maps[bpf.MapRunSet].Update(&cg, &row, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = coll.Maps[bpf.MapRunSet].Delete(&cg) })
	rt := &agent.RuleTable{Record: mode, Tier: backend.TierCgroup, FS: []agent.FSRule{
		{Path: filepath.Join(base, "allow"), Kind: agent.FSWrite, Raw: "./allow"},
		{Path: filepath.Join(base, "wt"), Kind: agent.FSWrite, Raw: "./wt"},
		{Path: filepath.Join(base, "deny"), Kind: agent.FSDenyRead, Raw: "./deny"},
	}}
	rec, err := New(Options{Rules: rt, BPFHash: hash, PinRoot: root, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	if err := rec.Start(context.Background(), source.RunRef{ID: "r-chain", Agent: "a", CgroupID: cg}, sink); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	report := filepath.Join(t.TempDir(), "report")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), landlockEnv+"="+base+"\n"+report)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	if b, err := cmd.CombinedOutput(); err != nil {
		r, _ := os.ReadFile(report)
		t.Fatalf("landlock child: %v: %s\n%s", err, b, r)
	}
	got := childErrnos(t, report)
	abi := got["abi"]
	want := map[string]unix.Errno{"read-denied": unix.EACCES, "read-allowed": 0, "create-denied": unix.EACCES,
		"unlink-denied": unix.EACCES, "trunc-allowed": 0, "trunc-denied": unix.EACCES, "create-allowed": 0}
	if abi < 3 {
		want["trunc-denied"] = 0 // Landlock handles truncate from ABI 3 (6.2)
	}
	for name, errno := range want {
		if got[name] != int(errno) {
			t.Fatalf("the child's %s returned errno %d, want %d: the cell is not what it says", name, got[name], errno)
		}
	}

	waitDrained(t, rec)
	if err := rec.Stop(); err != nil {
		t.Fatal(err)
	}
	lines := map[string][]*record.Event{}
	for _, ev := range sink.byKind(record.KindFS) {
		p := payload[record.FSPayload](t, ev)
		if strings.HasPrefix(p.Path, base+"/") {
			rel := strings.TrimPrefix(p.Path, base+"/")
			lines[rel] = append(lines[rel], ev)
			t.Logf("%s op=%s flags=%#x rule=%s verdict=%s reason=%s from=%s by=%s errno=%d created=%v",
				rel, p.Op, p.Flags, ev.Rule, ev.Verdict, ev.Reason, p.VerdictFrom, p.By, p.Errno, p.Created)
		}
	}
	type cell struct {
		op      string
		flags   int // bits the line's flags must have
		verdict record.Verdict
		reason  record.Reason
		rule    string
		errno   int
		created bool
	}
	cells := map[string]cell{
		"deny/secret": {record.FSOpen, 0, record.VerdictRefused, record.ReasonReadDenied, "fs.deny_read[./deny]", 0, false},
		"allow/ok":    {record.FSOpen, 0, record.VerdictAllow, "", "fs.write[./allow]", 0, false},
		"deny/new": {record.FSOpen, unix.O_CREAT, record.VerdictRefused, record.ReasonWriteOutsideContract,
			"fs.deny_read[./deny]", 0, false},
		"deny/victim": {record.FSUnlink, 0, record.VerdictRefused, record.ReasonDeleteOutsideContract,
			"fs.deny_read[./deny]", 0, false},
		"allow/trunc": {record.FSOpen, unix.O_TRUNC, record.VerdictAllow, "", "fs.write[./allow]", 0, false},
		"allow/new":   {record.FSOpen, unix.O_CREAT, record.VerdictAllow, "", "fs.write[./allow]", 0, true},
		"wt/f":        {record.FSOpen, unix.O_TRUNC, record.VerdictAllow, "", "fs.write[./wt]", 0, false},
	}
	if abi >= 3 {
		cells["wt/f"] = cell{record.FSOpen, unix.O_TRUNC, record.VerdictObserved, "", "fs.write[./wt]", int(unix.EACCES), false}
	}
	for rel, c := range cells {
		evs := lines[rel]
		if mode == agent.RecordOff && c.verdict != record.VerdictRefused {
			if len(evs) != 0 {
				t.Errorf("%s: record: off kept a %s line", rel, evs[0].Verdict)
			}
			continue
		}
		if len(evs) != 1 {
			t.Errorf("%s: %d lines, want one line per action (ADR 0016 (3))", rel, len(evs))
			continue
		}
		ev := evs[0]
		p := payload[record.FSPayload](t, ev)
		if p.Op != c.op || p.Flags&c.flags != c.flags || ev.Verdict != c.verdict || ev.Reason != c.reason ||
			ev.Rule != c.rule || p.Errno != c.errno || p.Created != c.created || p.VerdictFrom != record.FSVerdictChain {
			t.Errorf("%s: %s %s flags %#x rule %s reason %q errno %d created %v from %q, want %s %s flags %#x rule %s "+
				"reason %q errno %d created %v from the chain", rel, ev.Verdict, p.Op, p.Flags, ev.Rule, ev.Reason, p.Errno,
				p.Created, p.VerdictFrom, c.verdict, c.op, c.flags, c.rule, c.reason, c.errno, c.created)
		}
		if (c.errno != 0) != (p.By == record.FSByOther) {
			t.Errorf("%s: by %q with errno %d", rel, p.By, p.Errno)
		}
		if err := ev.Validate(); err != nil {
			t.Errorf("%s: %v", rel, err)
		}
	}
}

// childErrnos reads landlockChild's report: each action's errno, and the Landlock ABI under "abi".
func childErrnos(t *testing.T, report string) map[string]int {
	t.Helper()
	b, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		name, v, ok := strings.Cut(line, " ")
		n, err := strconv.Atoi(v)
		if !ok || err != nil {
			t.Fatalf("report line %q", line)
		}
		out[name] = n
	}
	return out
}
