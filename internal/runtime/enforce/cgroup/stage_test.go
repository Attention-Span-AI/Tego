// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The tests in this file are the tier-2 exec check against the files a real run executes (§5 R8): the kernel
// names each by its canonical path, the child stage's own binary by nothing a contract declares, and a
// contract with no exec: section refuses nothing. Each case here refused an ordinary `tego run --tier
// cgroup` as root in the KVM guest: at clone3 with EPERM (exit 125) for the stage, and with EACCES (exit
// 126) for /bin/sh and every dynamically linked binary.

// writeExec creates an empty file with the execute bit, standing in for a binary.
func writeExec(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, nil, 0o755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// symlink makes link point at target, creating link's directory.
func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(link), err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink %s -> %s: %v", link, target, err)
	}
}

// canonical is the path the kernel reports for a file: every symlink followed, as readlink of an event's
// descriptor gives it.
func canonical(t *testing.T, path string) string {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer unix.Close(fd)
	got, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	return got
}

// TestPolicyDecideExecMatchesTheKernelsPath: an exec entry compiled to a path with a symlink in it (/bin/sh on
// a merged-/usr system, python3 -> python3.13, a directory entry reached through a link) and a PT_INTERP
// loader as the ELF spells it (/lib64/ld-linux-x86-64.so.2) are all executed under their canonical paths,
// which is what the listener reads back from the event. Each must be allowed there, as the inherited
// Landlock ruleset allows the inode it opened following the same links. Another name of a named file (a hard
// link) is not a path the contract wrote, and stays refused.
func TestPolicyDecideExecMatchesTheKernelsPath(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dash := filepath.Join(root, "usr/bin/dash")
	python := filepath.Join(root, "usr/bin/python3.13")
	loader := filepath.Join(root, "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
	tool := filepath.Join(root, "opt/real-tools/build")
	for _, p := range []string{dash, python, loader, tool} {
		writeExec(t, p)
	}
	sh := filepath.Join(root, "bin/sh")
	symlink(t, dash, sh)
	python3 := filepath.Join(root, "usr/bin/python3")
	symlink(t, "python3.13", python3)
	lib64 := filepath.Join(root, "lib64")
	symlink(t, "usr/lib/x86_64-linux-gnu", lib64)
	tools := filepath.Join(root, "opt/tools")
	symlink(t, "real-tools", tools)
	curl := filepath.Join(root, "usr/bin/curl")
	writeExec(t, curl)
	// Another name of the file sh resolves to, as uutils' applets are all names of one binary: the entry
	// names a path, so the other name is not admitted with it (§5 R8, the fail-closed side).
	other := filepath.Join(root, "usr/bin/rm")
	if err := os.Link(dash, other); err != nil {
		t.Fatalf("link: %v", err)
	}

	p := newPolicy(policyTable(nil, []agent.ExecRule{
		{Path: sh, Raw: "sh", Verdict: agent.VerdictAllow},
		{Path: python3, Raw: "python3", Verdict: agent.VerdictAllow,
			Interp: filepath.Join(lib64, "ld-linux-x86-64.so.2")},
		{Path: tools, Raw: "/opt/tools", Verdict: agent.VerdictAllow, IsDir: true},
	}), "/run.scope")

	for _, tc := range []struct {
		name, path string
		allow      bool
		rule       string
	}{
		{"a symlinked binary, as the kernel names it", canonical(t, sh), true, "exec[sh]"},
		{"a relative symlink, as the kernel names it", canonical(t, python3), true, "exec[python3]"},
		{"the loader through a symlinked directory", canonical(t, filepath.Join(lib64, "ld-linux-x86-64.so.2")), true, "exec[python3]"},
		{"a binary under a symlinked directory entry", canonical(t, filepath.Join(tools, "build")), true, "exec[/opt/tools]"},
		{"the compiled spelling still matches", sh, true, "exec[sh]"},
		{"a binary no entry names", canonical(t, curl), false, agent.UnmatchedRule},
		{"a hard link of a named binary", canonical(t, other), false, agent.UnmatchedRule},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := p.decideExec(tc.path)
			if got.allow != tc.allow {
				t.Fatalf("decideExec(%q).allow = %v, want %v", tc.path, got.allow, tc.allow)
			}
			if !tc.allow && (got.rule != tc.rule || got.reason != record.ReasonExecNotAllowed) {
				t.Fatalf("refusal %+v, want rule %q and reason %q", got, tc.rule, record.ReasonExecNotAllowed)
			}
		})
	}
	if e, ok := p.execAllow.match(canonical(t, sh)); !ok || e.rule != "exec[sh]" {
		t.Fatalf("the canonical path matched %+v (found %v), want the entry named exec[sh]", e, ok)
	}
}

// TestPolicyDecideOpenMatchesAResolvedDenyRead: a deny_read entry written through a symlink (~/.aws pointing
// at a secrets volume) governs its target (agent.FSRule.Resolved), and the kernel reports an open there by
// the target's path. Matching the declared name alone never refused it.
func TestPolicyDecideOpenMatchesAResolvedDenyRead(t *testing.T) {
	t.Parallel()
	p := newPolicy(policyTable([]agent.FSRule{
		{Kind: agent.FSDenyRead, Path: "/home/u/.aws", Resolved: "/mnt/secrets/aws", Raw: "~/.aws"},
		{Kind: agent.FSWrite, Path: "/home/u/.aws/cli/cache", Resolved: "/mnt/secrets/aws/cli/cache",
			Raw: "~/.aws/cli/cache"},
	}, nil), "/run.scope")
	if v := p.decideOpen("/mnt/secrets/aws/credentials"); v.allow || v.rule != "fs.deny_read[~/.aws]" {
		t.Fatalf("an open of the deny_read target by its canonical path = %+v, want a refusal naming the entry", v)
	}
	if v := p.decideOpen("/home/u/.aws/credentials"); v.allow {
		t.Fatal("the declared spelling no longer refuses")
	}
	if v := p.decideOpen("/mnt/secrets/aws/cli/cache/x.json"); !v.allow {
		t.Fatalf("a write entry nested in the target, by its canonical path = %+v, want an allow", v)
	}
}

// TestPolicyNoExecSectionRefusesNoExec is SEMANTICS §1 at tier 2: a contract with no exec: section denies
// nothing through its exec rules, which the Landlock builder (execUnrestricted), the supervisor and
// agent.Evaluate all read off Contract.Exec == nil. The fanotify check refused every exec no entry named
// whatever the contract said, so `compile --test` at tier cgroup certified an exec the run refused. A present
// but empty exec: section, and a table with no contract, stay restricted.
func TestPolicyNoExecSectionRefusesNoExec(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cmd := filepath.Join(dir, "agent")
	writeExec(t, cmd)
	rules := []agent.ExecRule{{Path: cmd, Raw: "agent", Source: "command", Verdict: agent.VerdictAllow}}

	open := policyTable(nil, rules)
	open.Contract = &agent.Contract{}
	p := newPolicy(open, "/run.scope")
	if v := p.decideExec("/usr/bin/curl"); !v.allow {
		t.Fatalf("no exec: section, an exec no entry names = %+v, want an allow", v)
	}
	if len(p.mounts) != 0 {
		t.Fatalf("mounts %v: a contract whose exec check refuses nothing needs no exec mark", p.mounts)
	}

	empty := policyTable(nil, rules)
	empty.Contract = &agent.Contract{Exec: &agent.ExecSection{}}
	if v := newPolicy(empty, "/run.scope").decideExec("/usr/bin/curl"); v.allow {
		t.Fatal("an empty exec: section allowed an exec no entry names")
	}
	if v := newPolicy(policyTable(nil, rules), "/run.scope").decideExec("/usr/bin/curl"); v.allow {
		t.Fatal("a table with no contract allowed an exec no entry names")
	}
}

// TestArmIsTheOneArmingPoint is ADR 0021 (2) and (3) on the backend: Prepare leaves nothing that keys on the run
// (no run-set row, no mark), so the child stage's execve, which comes after Prepare, is neither decided nor
// recorded; Arm, which the runtime calls once the stage has exec'd, inserts the row and places the marks with
// the process armed, so a process start is refused while they exist; and Detach removes the marks and releases
// the arm, so the helpers Detach and Close start (ring trim, linger) can start. Not parallel: the arm is the
// process's, and a parallel test's marks would arm it too.
func TestArmIsTheOneArmingPoint(t *testing.T) {
	var marks []string
	f := newFixture(t, func(o *Options) {
		inner := o.newListener
		o.newListener = func(h *Handle) (*fanotifyListener, error) {
			l, err := inner(h)
			if err != nil {
				return nil, err
			}
			l.markMount = func(m string, _ uint64) error {
				if !proc.Armed() {
					t.Errorf("mount %s marked with the process unarmed", m)
				}
				marks = append(marks, m)
				return nil
			}
			return l, nil
		}
	})
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer h.Close()
	if len(marks) != 0 || len(f.kernel.runs) != 0 || proc.Armed() {
		t.Fatalf("after Prepare: marks %v, run-set rows %v, armed %v; want none of them before the stage execs",
			marks, f.kernel.runs, proc.Armed())
	}
	if err := h.Attach(f.run.CgroupID); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if len(f.kernel.runs) != 0 {
		t.Fatal("Attach inserted the run-set row: it binds the network programs only")
	}

	if err := h.Arm(); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if _, ok := f.kernel.runs[f.run.CgroupID]; !ok || len(marks) == 0 {
		t.Fatalf("after Arm: run-set rows %v, marks %v; want the run's row and its mount marked", f.kernel.runs, marks)
	}
	if _, err := proc.Start(proc.Command("/bin/true")); !errors.Is(err, proc.ErrArmed) {
		t.Fatalf("a process start while the run's marks exist = %v, want proc.ErrArmed", err)
	}

	if err := h.Detach(); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if proc.Armed() {
		t.Fatal("the process is still armed after Detach removed the marks")
	}
	if len(f.kernel.runs) != 0 {
		t.Fatalf("run-set rows left after Detach: %v", f.kernel.runs)
	}
	if err := h.Arm(); !errors.Is(err, ErrNotPrepared) {
		t.Fatalf("Arm after Detach = %v, want ErrNotPrepared", err)
	}
}

// TestArmWithoutAGroupArmsNothing: a contract whose rules mark no mount gets no permission group, and its Arm
// inserts the run-set row alone and leaves process starts allowed, since no mark exists to vfork under.
func TestArmWithoutAGroupArmsNothing(t *testing.T) {
	f := newFixture(t)
	unmarked := *f.table
	unmarked.Contract, unmarked.FS, unmarked.NameDeny = &agent.Contract{}, nil, nil
	h, err := f.backend.Prepare(context.Background(), &unmarked, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer h.Close()
	if h.fan != nil {
		t.Fatal("a table that marks no mount got a permission group")
	}
	if err := h.Arm(); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if _, ok := f.kernel.runs[f.run.CgroupID]; !ok {
		t.Fatal("Arm inserted no run-set row")
	}
	if proc.Armed() {
		t.Fatal("Arm with no permission group armed the process")
	}
}

// TestDecideEventAdmitsNoStageExec: the group never sees the child stage's execve, which happens before its
// first mark (Arm), so nothing in it admits an exec no entry names. An exec of the launcher's own binary inside
// the run is the agent's, and the contract refuses it like any other unnamed binary, the first as much as any
// later one; outside the run it is allowed.
func TestDecideEventAdmitsNoStageExec(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tego, named := filepath.Join(dir, "tego"), filepath.Join(dir, "python3")
	writeExec(t, tego)
	writeExec(t, named)
	const runCgroup = "/tego.slice/run-1.scope"
	member := "/user.slice/user-1000.slice/session-2.scope"
	l := &fanotifyListener{
		run: Run{ID: "run-1", Agent: "a", CgroupPath: runCgroup, CgroupID: 99},
		policy: &policy{runCgroup: runCgroup,
			execAllow: newPathSet([]fsEntry{{path: named, rule: "exec[python3]"}})},
		now: time.Now, deadline: time.Second, marks: map[string]uint64{},
	}
	l.cgroupOfPID = func(int) (string, error) { return member, nil }
	exec := func(path string) verdict {
		t.Helper()
		v, err := l.decideEvent(fanEvent{Mask: unix.FAN_OPEN_EXEC_PERM, FD: openForEvent(t, path), PID: 4242})
		if err != nil {
			t.Fatalf("decideEvent on an exec of %s: %v", path, err)
		}
		return v
	}
	if v := exec(tego); !v.allow {
		t.Fatalf("an exec of an unnamed binary outside the run = %+v, want an allow", v)
	}
	member = runCgroup
	for i := range 2 {
		v := exec(tego)
		if v.allow || v.reason != record.ReasonExecNotAllowed || v.rule != agent.UnmatchedRule {
			t.Fatalf("exec %d of the launcher's binary inside the run = %+v, want the contract's refusal", i+1, v)
		}
	}
	if v := exec(named); !v.allow {
		t.Fatalf("an exec the contract names = %+v, want an allow", v)
	}
}
