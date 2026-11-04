// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// testKey is a key a test cache reads, as machineRunCacheKey would on some machine.
func testKey() runCacheKey {
	return runCacheKey{Version: runCacheVersion, BootID: "6f0b3a7e-0000-4000-8000-000000000001", Kernel: "6.17.0-test",
		LSM: []string{"lockdown", "capability", "landlock", "bpf"}, Lockdown: "none [integrity] confidentiality",
		BPFHash: "82aa945903cd70a6", Binary: "2049:1234:13496480:1758650000.000000001",
		Process: processPrivilege{CapEff: "000001ffffffffff", Labels: []string{"current=unconfined",
			"apparmor/current=unconfined", "smack/current="}, UserNS: "4:4026531837", MountNS: "4:4026531841",
			Cgroup: "0::/user.slice/user-1000.slice/session-2.scope", CgroupNS: "4:4026531835", UID: 1000}}
}

// testCache is a run-probe cache under a fresh directory this test owns, laid out as /run/tego is: base
// trusted, run/ an ordinary directory, tego/ created on the first store. It is owned by the test's own uid,
// which stands in for root.
func testCache(t *testing.T) (*runCache, string) {
	t.Helper()
	base := t.TempDir()
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(base, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A cache hit reads the kernel's preemption model again (planePreemptCurrent): the kernel these tests' answers
	// were kept under (passingPlane's) is the one it reads, unless a test changes it.
	stubPreempt(t, preemptVoluntary, debugfsPreemptPath)
	k := testKey()
	c := &runCache{base: base, dir: []string{"run", "tego"}, owner: os.Geteuid(),
		key: func(string, int) (runCacheKey, bool) { return k, true }}
	return c, filepath.Join(base, "run", "tego", c.name(k))
}

// vouchingAnswer is D7's tier-2 rows and D8's answer on a machine that gives tier cgroup, with the optional
// unix hooks absent as on a kernel before 6.7.
func vouchingAnswer() (Result, []HookResult, Result, FanotifyState) {
	var rows []HookResult
	for _, h := range tierHooks(backend.TierCgroup) {
		r := HookResult{Hook: h.Name, Tier: h.Tier, BTF: true, Loaded: true, Attached: true}
		if h.optional {
			r = HookResult{Hook: h.Name, Tier: h.Tier, Absent: true, Detail: "needs kernel >= 6.7.0"}
		}
		rows = append(rows, r)
	}
	return programsVerdict(rows), rows, Result{ID: CheckFanotify, OK: true, Detail: "permission marks work"},
		FanotifyState{PermissionMarks: true, Refuses: true}
}

// TestRunCacheReadsOnlyTheAnswerItKeptForThisKey (enforce-cgroup-observe.md E27: a probe taken on one kernel is
// never the answer for a Prepare on another): an answer is read back only under the key it was kept
// with. A change in any part of the key is a machine or a process the answer says nothing about: the format,
// the boot, the kernel, the LSM list, lockdown, the programs, the binary, or the asking process's effective
// capabilities, LSM labels, user or mount namespace, cgroup, cgroup namespace or invoking uid.
func TestRunCacheReadsOnlyTheAnswerItKeptForThisKey(t *testing.T) {
	c, path := testCache(t)
	k := testKey()
	p, rows, fan, fs := vouchingAnswer()
	c.record(k, p, rows, passingPlane(""), nil, fan, fs)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("a vouching answer was not kept: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("entry mode %v, want 0600", st.Mode().Perm())
	}
	e, ok := c.load(k)
	if !ok || !reflect.DeepEqual(e, runCacheEntry{Key: k, Programs: p, Hooks: rows, Plane: passingPlane(""), Fanotify: fan, FanotifyState: fs}) {
		t.Fatalf("load = %+v, %v; want the answer kept", e, ok)
	}
	edits := map[string]func(*runCacheKey){
		"format":   func(k *runCacheKey) { k.Version++ },
		"boot":     func(k *runCacheKey) { k.BootID = "6f0b3a7e-0000-4000-8000-000000000002" },
		"kernel":   func(k *runCacheKey) { k.Kernel = "6.17.1-test" },
		"lsm":      func(k *runCacheKey) { k.LSM = []string{"lockdown", "capability", "landlock"} },
		"lockdown": func(k *runCacheKey) { k.Lockdown = "none integrity [confidentiality]" },
		"binary":   func(k *runCacheKey) { k.Binary = "2049:1235:13496480:1758650001.000000001" },
	}
	// The process's own privilege: a root process whose bounding set lost CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN
	// and CAP_SYS_ADMIN (setpriv --bounding-set, systemd's CapabilityBoundingSet=), a confined LSM domain,
	// another user or mount namespace, another cgroup (a systemd unit with a MemoryMax= its programs' maps do
	// not fit in), the same cgroup path in another cgroup namespace, or another invoking uid.
	process := map[string]func(*runCacheKey){
		"capability set": func(k *runCacheKey) { k.Process.CapEff = "0000013fffdfefff" },
		"lsm label": func(k *runCacheKey) {
			k.Process.Labels = []string{"current=tego-confined (enforce)", "apparmor/current=tego-confined (enforce)", "smack/current="}
		},
		"user namespace":   func(k *runCacheKey) { k.Process.UserNS = "4:4026532100" },
		"mount namespace":  func(k *runCacheKey) { k.Process.MountNS = "4:4026532200" },
		"cgroup":           func(k *runCacheKey) { k.Process.Cgroup = "0::/system.slice/agent-runner.service" },
		"cgroup namespace": func(k *runCacheKey) { k.Process.CgroupNS = "4:4026532201" },
		"invoking uid":     func(k *runCacheKey) { k.Process.UID = 1001 },
	}
	for name, edit := range process {
		edits[name] = edit
	}
	for name, edit := range edits {
		other := testKey()
		edit(&other)
		if _, ok := c.load(other); ok {
			t.Errorf("an answer kept for one key was read under a key with another %s", name)
		}
	}
	// Each set of process privileges keeps its own entry, so a restricted process's probe never removes the
	// answer an unrestricted one keeps, and the two do not evict each other.
	for name, edit := range process {
		other := testKey()
		edit(&other)
		if c.name(other) == c.name(k) {
			t.Errorf("a key with another %s names the same entry", name)
		}
		failing, rows, fan, fs := vouchingAnswer()
		failing.OK = false
		c.record(other, failing, rows, passingPlane(""), nil, fan, fs)
		if _, ok := c.load(k); !ok {
			t.Errorf("a failing answer for a key with another %s removed this key's entry", name)
		}
	}
	// Another build's programs are another file, so two builds keep an answer each.
	other := testKey()
	other.BPFHash = "0123456789abcdef"
	if _, ok := c.load(other); ok || c.name(other) == c.name(k) {
		t.Errorf("another build's key read this build's answer, or names the same file")
	}
	// Two binaries of one build (a copy at another inode, ADR 0021's two-inode condition, or two installs) keep
	// an answer each: under one file, each one's run read the other's entry as a miss, probed cold and replaced
	// it, so on a host running both every run paid the cold probe (test/vm/pairs.sh two-inodes, 2026-10-19).
	other = testKey()
	other.Binary = "2049:1235:13496480:1758650001.000000001"
	if c.name(other) == c.name(k) {
		t.Errorf("another binary of this build names the same entry")
	}
	c.record(other, p, rows, passingPlane(""), nil, fan, fs)
	if _, ok := c.load(k); !ok {
		t.Errorf("another binary's answer removed this binary's entry")
	}
	if _, ok := c.load(other); !ok {
		t.Errorf("another binary's answer was not kept beside this binary's")
	}
}

// TestRunCacheKeepsOnlyAnAnswerThatVouches: the cache holds nothing but an answer that tier cgroup's own
// checks pass, so it can never hide a failure from a run; a fresh answer that does not vouch removes what was
// kept under its own key, so a machine that stopped giving tier cgroup is seen by the next run.
func TestRunCacheKeepsOnlyAnAnswerThatVouches(t *testing.T) {
	type answer struct {
		p    Result
		rows []HookResult
		fan  Result
		fs   FanotifyState
	}
	failing := map[string]func(*answer){
		"D7 failed": func(a *answer) { a.p.OK = false },
		"a hook did not attach": func(a *answer) {
			a.rows[0].Attached = false
			a.p = programsVerdict(a.rows)
		},
		"a hook row is missing": func(a *answer) { a.rows = a.rows[1:] },
		"a capture row among them": func(a *answer) {
			a.rows = append(a.rows, HookResult{Hook: "uprobe/SSL_write", Capture: true, Loaded: true, Attached: true})
		},
		"a required hook absent": func(a *answer) {
			a.rows[0] = HookResult{Hook: a.rows[0].Hook, Tier: a.rows[0].Tier, Absent: true}
		},
		"D8 failed":                       func(a *answer) { a.fan.OK = false },
		"a FAN_DENY that refused nothing": func(a *answer) { a.fs.Refuses = false },
		"D8 skipped as a non-root probe": func(a *answer) {
			a.fan = Result{ID: CheckFanotify, Detail: "requires root to test", Skipped: true}
		},
	}
	for name, edit := range failing {
		c, path := testCache(t)
		k := testKey()
		p, rows, fan, fs := vouchingAnswer()
		c.record(k, p, rows, passingPlane(""), nil, fan, fs)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s: the vouching answer before it was not kept: %v", name, err)
		}
		p, rows, fan, fs = vouchingAnswer()
		a := answer{p, rows, fan, fs}
		edit(&a)
		c.record(k, a.p, a.rows, passingPlane(""), nil, a.fan, a.fs)
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s: a fresh answer that does not vouch for tier cgroup left the old one in place (%v)", name, err)
		}
		// Written by hand, the same answer is refused on the way in as well.
		if err := c.store(runCacheEntry{Key: k, Programs: a.p, Hooks: a.rows, Fanotify: a.fan, FanotifyState: a.fs}); err != nil {
			t.Fatal(err)
		}
		if _, ok := c.load(k); ok {
			t.Errorf("%s: an entry that does not vouch was read as one that does", name)
		}
	}
}

// TestRunCacheRefusesAnEntryItCannotTrust: an entry is read only from a directory and a file that no one but
// its owner (root, in production) could have written, reached without following a link.
func TestRunCacheRefusesAnEntryItCannotTrust(t *testing.T) {
	k := testKey()
	fresh := func(t *testing.T) (*runCache, string) {
		c, path := testCache(t)
		p, rows, fan, fs := vouchingAnswer()
		c.record(k, p, rows, passingPlane(""), nil, fan, fs)
		if _, ok := c.load(k); !ok {
			t.Fatal("the answer just kept is not read back")
		}
		return c, path
	}
	cases := map[string]func(t *testing.T, c *runCache, path string){
		"a file others may read or write": func(t *testing.T, _ *runCache, path string) {
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a file with a second link": func(t *testing.T, _ *runCache, path string) {
			if err := os.Link(path, path+".2"); err != nil {
				t.Fatal(err)
			}
		},
		"a file that is a link": func(t *testing.T, _ *runCache, path string) {
			if err := os.Rename(path, path+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path+".real", path); err != nil {
				t.Fatal(err)
			}
		},
		"a file owned by someone else": func(_ *testing.T, c *runCache, _ string) { c.owner++ },
		"a directory others may write": func(t *testing.T, _ *runCache, path string) {
			if err := os.Chmod(filepath.Dir(path), 0o777); err != nil {
				t.Fatal(err)
			}
		},
		"a directory that is a link": func(t *testing.T, _ *runCache, path string) {
			dir := filepath.Dir(path)
			if err := os.Rename(dir, dir+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(dir+".real", dir); err != nil {
				t.Fatal(err)
			}
		},
		"a parent others may write, not sticky": func(t *testing.T, _ *runCache, path string) {
			if err := os.Chmod(filepath.Dir(filepath.Dir(path)), 0o777); err != nil {
				t.Fatal(err)
			}
		},
		"a field this binary does not know": func(t *testing.T, _ *runCache, path string) {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			b = []byte(strings.Replace(string(b), `{"key":`, `{"planted":true,"key":`, 1))
			if err := os.WriteFile(path, b, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"an entry larger than any answer": func(t *testing.T, _ *runCache, path string) {
			if err := os.WriteFile(path, make([]byte, maxRunCacheBytes+1), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			c, path := fresh(t)
			tamper(t, c, path)
			if _, ok := c.load(k); ok {
				t.Errorf("read an entry from %s", name)
			}
		})
	}
	// A sticky parent that others may write is /tmp's shape: others can add entries to it but not replace the
	// cache's own directory, so it is walked through.
	t.Run("a sticky parent others may write", func(t *testing.T) {
		c, path := fresh(t)
		if err := os.Chmod(filepath.Dir(filepath.Dir(path)), 0o777|os.ModeSticky); err != nil {
			t.Fatal(err)
		}
		if _, ok := c.load(k); !ok {
			t.Error("a sticky parent refused the entry")
		}
	})
}

// TestRunAtReachCgroupReadsTheCacheAsRoot: a root run at reach cgroup probes D7's tier-2 rows and D8 once and
// keeps the answer; the next run reads it and loads no program, and offers and explains every tier as the
// probed run did. A run that is not root, a run at reach landlock and doctor's own scope never read or write
// it.
func TestRunAtReachCgroupReadsTheCacheAsRoot(t *testing.T) {
	c, path := testCache(t)
	var first, second calls
	a := scope{reach: backend.TierCgroup, root: true, checks: passingChecks(&first), cache: c}.run(context.Background())
	if first.n[CheckPrograms] != 1 || first.n[CheckFanotify] != 1 || a.cached != nil {
		t.Fatalf("the first run did not probe D7 and D8 itself: %v, cached=%v", first.n, a.cached != nil)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the first run's answer was not kept: %v", err)
	}
	var seeded map[string]bool
	b := scope{reach: backend.TierCgroup, root: true, checks: passingChecks(&second), cache: c,
		seed: func(m map[string]bool) { seeded = m }}.run(context.Background())
	if second.n[CheckPrograms] != 0 || second.n[CheckFanotify] != 0 || b.cached == nil {
		t.Fatalf("the second run probed D7 or D8 again (%v) or does not say it read the cache", second.n)
	}
	// D2 and the kernel's functions read the kernel's BTF alone, which the key pins (enforce-plane §2.18): the
	// cached run parses none, takes D2's answer as the first run gave it, and seeds its loaders with the functions.
	if second.n[CheckBTF] != 0 || second.funcs != 0 || first.funcs != 1 {
		t.Errorf("BTF: the first run parsed its functions %d times, the cached run probed D2 %d times and parsed "+
			"%d times; want 1, 0, 0", first.funcs, second.n[CheckBTF], second.funcs)
	}
	if !reflect.DeepEqual(b.byID[CheckBTF], a.byID[CheckBTF]) {
		t.Errorf("D2 from the cache %+v, probed %+v", b.byID[CheckBTF], a.byID[CheckBTF])
	}
	if want := (map[string]bool{"bpf_loop": true, "bpf_rdonly_cast": true, "security_file_truncate": false}); !reflect.DeepEqual(seeded, want) {
		t.Errorf("the cached run seeded %v, want %v", seeded, want)
	}
	// Every other check is still probed afresh.
	for _, id := range []CheckID{CheckKernel, CheckCgroupV2, CheckLandlock, CheckSeccomp} {
		if second.n[id] != 1 {
			t.Errorf("the cached run probed %s %d times, want 1", id, second.n[id])
		}
	}
	allBuilt(&a)
	allBuilt(&b)
	ra, rb := a.report(nil, ""), b.report(nil, "")
	if !rb.FromCache() || ra.FromCache() {
		t.Errorf("FromCache: probed %v, cached %v", ra.FromCache(), rb.FromCache())
	}
	for _, tier := range backend.Tiers() {
		if ra.Probe()[tier] != rb.Probe()[tier] || ra.WhyNot(tier) != rb.WhyNot(tier) {
			t.Errorf("tier %s: probed %v %q, cached %v %q", tier, ra.Probe()[tier], ra.WhyNot(tier), rb.Probe()[tier], rb.WhyNot(tier))
		}
	}
	// A run that could not start from the cached answer drops it; the next run probes afresh.
	rb.DiscardCache()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("DiscardCache left the answer in place: %v", err)
	}
	var third calls
	scope{reach: backend.TierCgroup, root: true, checks: passingChecks(&third), cache: c}.run(context.Background())
	if third.n[CheckPrograms] != 1 {
		t.Errorf("the run after a discard did not probe: %v", third.n)
	}
	// A report that was probed, not read, has no answer of its own to discard.
	ra.DiscardCache()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("a probed report's DiscardCache removed the answer another run kept: %v", err)
	}

	for name, s := range map[string]scope{
		"not root":       {reach: backend.TierCgroup, root: false},
		"reach landlock": {reach: backend.TierLandlock, root: true},
		"doctor":         {root: true},
	} {
		c, path := testCache(t)
		var n calls
		s.checks, s.cache = passingChecks(&n), c
		st := s.run(context.Background())
		if _, err := os.Stat(path); !os.IsNotExist(err) || st.cached != nil {
			t.Errorf("%s: wrote the cache (%v) or read it (%v)", name, err, st.cached != nil)
		}
	}
}

// TestRunCacheNeverLendsAnAnswerToAnotherProcess reproduces at the scope what was found as root in the KVM guest on
// 6.17 (R27 "What a run probes", E30): a root process started with CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN and
// CAP_SYS_ADMIN out of its bounding set (setpriv --bounding-set -bpf,-sys_admin,-perfmon,-net_admin) ran after a
// full-root run had kept its answer. With a key of the machine alone it read that answer, was offered tier cgroup, and
// stopped at Prepare with exit 125 on "load program: operation not permitted", each time a full-root run had kept the
// answer again. Its own capabilities are in the key now, so it probes, is offered tier landlock as it was before the
// cache existed, and leaves the full-root answer where it is.
func TestRunCacheNeverLendsAnAnswerToAnotherProcess(t *testing.T) {
	c, fullPath := testCache(t)
	full, restricted := testKey(), testKey()
	restricted.Process.CapEff = "0000013fffdfefff" // CAP_NET_ADMIN, CAP_SYS_ADMIN, CAP_PERFMON and CAP_BPF dropped
	asking := full
	c.key = func(string, int) (runCacheKey, bool) { return asking, true }
	// What the kernel tells the restricted process: every tier-2 load refused, and no fanotify group.
	restrictedChecks := func(n *calls) checks {
		ch := passingChecks(n)
		inner := ch.programs
		ch.programs = func(root bool, uid int, v Version, tier, capture []hook) (Result, []HookResult) {
			_, rows := inner(root, uid, v, tier, capture)
			for i := range rows {
				rows[i].Loaded, rows[i].Attached, rows[i].Detail = false, false, "load program: operation not permitted"
			}
			return programsVerdict(rows), rows
		}
		ch.fanotify = func(bool, Version) (Result, FanotifyState) {
			n.n[CheckFanotify]++
			return Result{ID: CheckFanotify, Detail: "fanotify_init: operation not permitted",
				Fix: "boot a kernel built with CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y"}, FanotifyState{}
		}
		return ch
	}
	run := func(k runCacheKey, mk func(*calls) checks) (probeState, calls) {
		asking = k
		var n calls
		st := scope{reach: backend.TierCgroup, root: true, checks: mk(&n), cache: c}.run(context.Background())
		allBuilt(&st)
		return st, n
	}
	for round := 1; round <= 2; round++ {
		st, n := run(full, passingChecks)
		if !st.probe()[backend.TierCgroup] {
			t.Fatalf("round %d: the full-root run is not offered tier cgroup: %v", round, st.whyNot())
		}
		if _, err := os.Stat(fullPath); err != nil {
			t.Fatalf("round %d: the full-root answer was not kept: %v", round, err)
		}
		if wantProbe := round == 1; (n.n[CheckPrograms] == 1) != wantProbe {
			t.Errorf("round %d: the full-root run probed D7 %d times", round, n.n[CheckPrograms])
		}
		st, n = run(restricted, restrictedChecks)
		if st.cached != nil || n.n[CheckPrograms] != 1 || n.n[CheckFanotify] != 1 {
			t.Errorf("round %d: the restricted run read the cache (%v) or did not probe D7 and D8 itself (%v)",
				round, st.cached != nil, n.n)
		}
		if p := st.probe(); p[backend.TierCgroup] || !p[backend.TierLandlock] {
			t.Errorf("round %d: the restricted run is offered %v, want tier landlock and not tier cgroup", round, p)
		}
		if _, err := os.Stat(fullPath); err != nil {
			t.Errorf("round %d: the restricted run's failing probe removed the full-root answer: %v", round, err)
		}
	}
}

// fakeProc writes a /proc/<pid> directory with the files readProcessPrivilege reads.
func fakeProc(t *testing.T, status string, labels map[string]string) string {
	t.Helper()
	proc := t.TempDir()
	if err := os.WriteFile(filepath.Join(proc, "status"), []byte(status), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, value := range labels {
		path := filepath.Join(proc, "attr", name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(proc, "ns"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, ns := range []string{"user", "mnt", "cgroup"} {
		if err := os.WriteFile(filepath.Join(proc, "ns", ns), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(proc, "cgroup"), []byte(fakeCgroup+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return proc
}

// fakeCgroup is the cgroup file fakeProc writes, as a cgroup v2 kernel prints it.
const fakeCgroup = "0::/user.slice/user-1000.slice/session-2.scope"

// TestProcessPrivilegeIsReadOrTheCacheIsNotUsed: the process half of the key is read from the process's own
// status, attr and cgroup files and its namespaces, a label with its trailing NUL or newline trimmed; a process
// under a seccomp filter, or one whose status lacks the lines the key needs or whose cgroup or namespaces cannot
// be read, gets no key, so it neither reads nor writes the cache.
func TestProcessPrivilegeIsReadOrTheCacheIsNotUsed(t *testing.T) {
	const status = "Name:\ttego\nUid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\nNoNewPrivs:\t0\nSeccomp:\t0\nSeccomp_filters:\t0\n"
	labels := map[string]string{"current": "system_u:system_r:unconfined_t:s0\x00", "apparmor/current": "unconfined\n"}
	p, err := readProcessPrivilege(fakeProc(t, status, labels), 1000)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"current=system_u:system_r:unconfined_t:s0", "apparmor/current=unconfined"}
	if p.CapEff != "000001ffffffffff" || !reflect.DeepEqual(p.Labels, want) || p.UserNS == "" || p.MountNS == "" ||
		p.Cgroup != fakeCgroup || p.CgroupNS == "" || p.UID != 1000 {
		t.Errorf("read %+v, want CapEff 000001ffffffffff, labels %q, a user and a mount namespace, cgroup %q, "+
			"a cgroup namespace and uid 1000", p, want, fakeCgroup)
	}
	if p.UserNS == p.MountNS || p.MountNS == p.CgroupNS || p.UserNS == p.CgroupNS {
		t.Errorf("read one namespace's identity for another: %+v", p)
	}
	edit := func(from, to string) func(string) error {
		return func(proc string) error {
			return os.WriteFile(filepath.Join(proc, "status"), []byte(strings.Replace(status, from, to, 1)), 0o600)
		}
	}
	for name, breakIt := range map[string]func(proc string) error{
		"a seccomp filter": edit("Seccomp:\t0", "Seccomp:\t2"),
		"strict seccomp":   edit("Seccomp:\t0", "Seccomp:\t1"),
		"no Seccomp line":  edit("Seccomp:\t0\n", ""),
		"no CapEff line":   edit("CapEff:\t000001ffffffffff\n", ""),
		"no status":        func(proc string) error { return os.Remove(filepath.Join(proc, "status")) },
		"no user namespace": func(proc string) error {
			return os.Remove(filepath.Join(proc, "ns", "user"))
		},
		"no mount namespace": func(proc string) error {
			return os.Remove(filepath.Join(proc, "ns", "mnt"))
		},
		"no cgroup namespace": func(proc string) error {
			return os.Remove(filepath.Join(proc, "ns", "cgroup"))
		},
		"no cgroup file": func(proc string) error { return os.Remove(filepath.Join(proc, "cgroup")) },
		"an empty cgroup file": func(proc string) error {
			return os.WriteFile(filepath.Join(proc, "cgroup"), []byte("\n"), 0o600)
		},
		// A label that cannot be read for any reason but an LSM without one (EINVAL) is not taken as "".
		"an unreadable label": func(proc string) error {
			current := filepath.Join(proc, "attr", "current")
			if err := os.Remove(current); err != nil {
				return err
			}
			return os.Mkdir(current, 0o700)
		},
	} {
		proc := fakeProc(t, status, labels)
		if err := breakIt(proc); err != nil {
			t.Fatal(err)
		}
		if p, err := readProcessPrivilege(proc, 1000); err == nil {
			t.Errorf("%s: read %+v, want no key", name, p)
		}
	}
	if _, err := readProcessPrivilege(fakeProc(t, strings.Replace(status, "Seccomp:\t0", "Seccomp:\t2", 1), labels), 0); !errors.Is(err, errUnderSeccomp) {
		t.Errorf("a seccomp filter: %v, want errUnderSeccomp", err)
	}
}

// TestProcessPrivilegeIsTheCallingThreads: D5 installs its seccomp filter on a locked goroutine's thread, and
// the key is read after D5 in the same process, so after the real D5 it must still find the process as it
// was. When D5's goroutine ran on the main thread, Go parked that thread for good, filter and all, and a key
// read from /proc/self (the main thread's view) said "Seccomp: 2" for a process none of whose running threads
// had a filter. D5 keeps off the main thread now (TestSeccompProbeLeavesNoThreadFiltered), and the key is read
// from the calling thread's view, which does not depend on that.
func TestProcessPrivilegeIsTheCallingThreads(t *testing.T) {
	before, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		t.Skipf("no /proc/thread-self: %v", err)
	}
	inherited := !strings.Contains(string(before), "\nSeccomp:\t0\n")
	roundTripOrSkip(t)
	for i := 0; i < 3; i++ {
		if _, _, err := probeSeccomp(); err != nil {
			t.Fatalf("D5's round trip failed: %v", err)
		}
		_, err := ownPrivilege(os.Getuid())
		switch {
		case inherited && !errors.Is(err, errUnderSeccomp):
			t.Fatalf("this process inherited a seccomp filter, and the key was read anyway: %v", err)
		case !inherited && err != nil:
			main, _ := os.ReadFile("/proc/self/status")
			t.Fatalf("after D5 the key could not be read: %v (the main thread says %q)", err, seccompLine(main))
		}
	}
}

// seccompLine is status's Seccomp line.
func seccompLine(status []byte) string {
	for _, l := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(l, "Seccomp:") {
			return l
		}
	}
	return ""
}

// TestDiscardCacheLeavesAnotherRunsFreshEntry (enforce-cgroup-observe.md: DiscardCache removes the entry the report
// came from): a run that adopted an entry and then failed at Prepare drops that file, not a newer answer another
// run renamed over the same name meanwhile.
func TestDiscardCacheLeavesAnotherRunsFreshEntry(t *testing.T) {
	c, path := testCache(t)
	k := testKey()
	p, rows, fan, fs := vouchingAnswer()
	c.record(k, p, rows, passingPlane(""), nil, fan, fs)
	_, id, ok := c.loadIdentified(k)
	if !ok {
		t.Fatal("entry not loaded")
	}
	r := &Report{cached: &cachedAnswer{cache: c, key: k, id: id}}

	// Another run replaces the entry: a new file under the same name.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	c.record(k, p, rows, passingPlane(""), nil, fan, fs)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("fresh entry not written: %v", err)
	}
	r.DiscardCache()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("DiscardCache removed another run's fresh entry: %v", err)
	}

	// The entry the report came from is removed.
	_, id, _ = c.loadIdentified(k)
	r.cached.id = id
	r.DiscardCache()
	if _, err := os.Stat(path); err == nil {
		t.Error("DiscardCache kept the entry the report came from")
	}
}

// TestFailedBTFIsNotCachedAndIsProbedAgain: only a passing D2 is kept, as only a vouching D7 is; a run whose D2
// failed leaves the entry without it, the next run probes D2 afresh, and an entry holding a failed D2 is not read.
func TestFailedBTFIsNotCachedAndIsProbedAgain(t *testing.T) {
	c, _ := testCache(t)
	var first, second calls
	failing := passingChecks(&first)
	failing.btf = func() Result { first.n[CheckBTF]++; return Result{ID: CheckBTF, Detail: "lacks a field"} }
	scope{reach: backend.TierCgroup, root: true, checks: failing, cache: c}.run(context.Background())
	if e, ok := c.load(testKey()); !ok || e.BTF != nil {
		t.Fatalf("after a failed D2 the entry was not kept, or kept D2 (read %v)", ok)
	}
	scope{reach: backend.TierCgroup, root: true, checks: passingChecks(&second), cache: c}.run(context.Background())
	if second.n[CheckBTF] != 1 || second.n[CheckPrograms] != 0 {
		t.Errorf("after a failed D2: D2 probed %d times (want 1), D7 %d (want 0, its answer is kept)", second.n[CheckBTF],
			second.n[CheckPrograms])
	}

	k := testKey()
	p, rows, fan, fs := vouchingAnswer()
	failed := Result{ID: CheckBTF, Detail: "lacks a field"}
	if err := c.store(runCacheEntry{Key: k, Programs: p, Hooks: rows, Plane: passingPlane(""), Fanotify: fan,
		FanotifyState: fs, BTF: &failed}); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.load(k); ok {
		t.Error("an entry holding a failed D2 was read")
	}
}
