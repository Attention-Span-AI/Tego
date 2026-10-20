// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// modeGateChmod runs the target under a write entry on the harness directory, a worktree at <dir>/work and the
// filter of a run whose gate scores fs.write, under record: summary; modeGateChmodOff is the same under record: off
// (ADR 0041 Step 2).
const (
	modeGateChmod    = "gatechmod"
	modeGateChmodOff = "gatechmod-off"
)

// gateChmodRuleTable is the harness's rule table for the gate-chmod modes: the whole harness directory writable, so
// that only the gate can refuse a mode change, and the worktree the gate's `fs.write outside worktree` reads.
func gateChmodRuleTable(dir, mode string) *agent.RuleTable {
	rt := &agent.RuleTable{
		FS:      []agent.FSRule{{Path: dir, Kind: agent.FSWrite, Resolved: dir}},
		Workdir: filepath.Join(dir, "work"),
		Record:  agent.RecordSummary, Tier: backend.TierLandlock, Contract: &agent.Contract{},
	}
	if mode == modeGateChmodOff {
		rt.Record = agent.RecordOff
	}
	return rt
}

// gateChmodPrepare makes a file inside the worktree and one outside it, both 0600, and a pair more for the attribute
// checks (gateAttrChecks).
func gateChmodPrepare(t *testing.T) func(dir string) {
	return func(dir string) {
		for _, p := range []string{"work/inside.txt", "outside/secret", "work/acl.txt", "outside/acl"} {
			p = filepath.Join(dir, p)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// gateChmodChecks are the chmod family's ways to change a mode: fchmodat on the file outside the worktree, fchmod on
// a descriptor for it, and fchmodat on the file inside the worktree. Each check's Out is the file's mode after the
// call, as the target reads it.
func gateChmodChecks() []checkResult {
	dir := os.Getenv(helperDir)
	inside, outside := filepath.Join(dir, "work/inside.txt"), filepath.Join(dir, "outside/secret")
	var out []checkResult
	add := func(name, path string, err error) {
		var st unix.Stat_t
		mode := "?"
		if unix.Stat(path, &st) == nil {
			mode = strconv.FormatUint(uint64(st.Mode&0o7777), 8)
		}
		out = append(out, checkResult{Name: name, Err: errText(err), Out: mode})
	}
	add("outside_fchmodat", outside, unix.Fchmodat(unix.AT_FDCWD, outside, 0o777, 0))
	fd, err := unix.Open(outside, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err == nil {
		err = unix.Fchmod(fd, 0o755)
		_ = unix.Close(fd)
	}
	add("outside_fchmod", outside, err)
	add("inside_fchmodat", inside, unix.Fchmodat(unix.AT_FDCWD, inside, 0o640, 0))
	return append(out, gateAttrChecks(dir)...)
}

// accessACL0755 is a minimal POSIX access ACL in the kernel's xattr form (posix_acl_xattr_header, then one
// posix_acl_xattr_entry per entry: tag, perm, id): user::rwx, group::r-x, other::r-x. Setting it as
// system.posix_acl_access makes a file's mode 0755, what `setfacl -m u::rwx,g::r-x,o::r-x` writes.
func accessACL0755() []byte {
	b := binary.LittleEndian.AppendUint32(nil, 2) // POSIX_ACL_XATTR_VERSION
	for _, e := range []struct{ tag, perm uint16 }{{0x01, 7}, {0x04, 5}, {0x20, 5}} {
		b = binary.LittleEndian.AppendUint16(b, e.tag)
		b = binary.LittleEndian.AppendUint16(b, e.perm)
		b = binary.LittleEndian.AppendUint32(b, 0xffffffff) // ACL_UNDEFINED_ID
	}
	return b
}

// gateAttrChecks are the attribute changes beside chmod: a POSIX ACL set
// through setxattr on the file outside the worktree, a user xattr set through fsetxattr and removed through
// lremovexattr there, an fchown of it to its own group, and the ACL and an fchownat on a file inside the worktree.
// Each check's Out is the file's mode after the call.
func gateAttrChecks(dir string) []checkResult {
	inside, outside := filepath.Join(dir, "work/acl.txt"), filepath.Join(dir, "outside/acl")
	var out []checkResult
	add := func(name, path string, err error) {
		var st unix.Stat_t
		mode := "?"
		if unix.Stat(path, &st) == nil {
			mode = strconv.FormatUint(uint64(st.Mode&0o7777), 8)
		}
		out = append(out, checkResult{Name: name, Err: errText(err), Out: mode})
	}
	add("inside_setxattr_acl", inside, unix.Setxattr(inside, "system.posix_acl_access", accessACL0755(), 0))
	add("inside_fchownat", inside, unix.Fchownat(unix.AT_FDCWD, inside, -1, os.Getgid(), 0))
	add("outside_setxattr_acl", outside, unix.Setxattr(outside, "system.posix_acl_access", accessACL0755(), 0))
	fd, err := unix.Open(outside, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err == nil {
		err = unix.Fsetxattr(fd, "user.tego", []byte("1"), 0)
	}
	add("outside_fsetxattr_user", outside, err)
	add("outside_lremovexattr", outside, unix.Lremovexattr(outside, "user.tego"))
	if fd >= 0 {
		err = unix.Fchown(fd, -1, os.Getgid())
		_ = unix.Close(fd)
	}
	add("outside_fchown", outside, err)
	return out
}

// TestWriteGateNotifiesXattrAndChown of GATE-STEP2-ROWS end to end on a real kernel, real
// filter and real Loop, under record: summary and record: off: a gate `fs.write outside worktree: 90` that refuses a
// chmod outside the worktree refuses the same mode change made by setting a POSIX ACL (setxattr
// system.posix_acl_access, what setfacl does), any other xattr set or removal, and a chown there, each with R10's
// errno and one refused line under the gate's authority, the mode left 0600; inside the worktree the ACL and the
// chown are continued and the mode becomes 0755. Before, the filter notified neither family under any option, so
// the ACL made the outside file 0755 with no score and no line.
func TestWriteGateNotifiesXattrAndChown(t *testing.T) {
	g, err := gate.New([]gate.Rule{{Predicate: gate.WriteOutsideWorktree, Score: 90}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{modeGateChmod, modeGateChmodOff} {
		t.Run(mode, func(t *testing.T) {
			h := startHarnessWith(t, harnessOpts{mode: mode, prepare: gateChmodPrepare(t), gate: g})
			h.stop(t)
			if c := h.check(t, "inside_setxattr_acl"); isErrno(c.Err, unix.EOPNOTSUPP) {
				t.Skipf("the test directory's file system takes no POSIX ACL: %+v", c)
			} else if c.Err != "" || c.Out != "755" {
				t.Fatalf("inside_setxattr_acl = %+v, want it continued and the mode 755", c)
			}
			if c := h.check(t, "inside_fchownat"); c.Err != "" {
				t.Errorf("inside_fchownat = %+v, want it continued", c)
			}
			for _, name := range []string{"outside_setxattr_acl", "outside_fsetxattr_user", "outside_lremovexattr", "outside_fchown"} {
				if c := h.check(t, name); !isErrno(c.Err, refusalErrno) || c.Out != "600" {
					t.Errorf("%s = %+v, want R10's errno and the mode left 600", name, c)
				}
			}
			outside := filepath.Join(h.dir, "outside/acl")
			refused := map[string]int{}
			for _, ev := range h.sink.all() {
				if ev.Kind != record.KindFS || ev.Verdict != record.VerdictRefused {
					continue
				}
				var p record.FSPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				if p.Op != record.FSXattr && p.Op != record.FSChown {
					continue
				}
				if p.Path != outside || ev.Authority != record.AuthorityGate || ev.Reason != record.ReasonFSGate {
					t.Errorf("refused %s line %q: authority %s reason %s, want %q under the gate (%s)", p.Op, p.Path,
						ev.Authority, ev.Reason, outside, record.ReasonFSGate)
				}
				refused[p.Op]++
			}
			if refused[record.FSXattr] != 3 || refused[record.FSChown] != 1 {
				t.Errorf("refused lines %v, want 3 xattr (setxattr, fsetxattr, lremovexattr) and 1 chown (fchown)", refused)
			}
		})
	}
}

// TestWriteGateNotifiesChmod is ADR 0041 Step 2 (finding failopen-2) end to end on a real kernel, real filter and
// real Loop, under record: summary and record: off: a gate `fs.write outside worktree: 90` refuses a mode change
// outside the worktree with R10's errno and one refused line under the gate's authority, the mode unchanged, while a
// mode change inside the worktree is continued. The filter used to notify the chmod family under record: full only,
// so at the default record level the kernel made the change with no gate decision and no line: with the filter built
// as before (gateWrite false) both outside checks succeed and the mode becomes 0777, then 0755.
func TestWriteGateNotifiesChmod(t *testing.T) {
	g, err := gate.New([]gate.Rule{{Predicate: gate.WriteOutsideWorktree, Score: 90}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{modeGateChmod, modeGateChmodOff} {
		t.Run(mode, func(t *testing.T) {
			h := startHarnessWith(t, harnessOpts{mode: mode, prepare: gateChmodPrepare(t), gate: g})
			h.stop(t)
			for _, name := range []string{"outside_fchmodat", "outside_fchmod"} {
				if c := h.check(t, name); !isErrno(c.Err, refusalErrno) || c.Out != "600" {
					t.Errorf("%s = %+v, want R10's errno and the mode left 600", name, c)
				}
			}
			if c := h.check(t, "inside_fchmodat"); c.Err != "" || c.Out != "640" {
				t.Errorf("inside_fchmodat = %+v, want it continued and the mode 640", c)
			}
			outside := filepath.Join(h.dir, "outside/secret")
			refused := 0
			for _, ev := range h.sink.all() {
				if ev.Kind != record.KindFS {
					continue
				}
				var p record.FSPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				if p.Op != record.FSChmod || ev.Verdict != record.VerdictRefused {
					continue
				}
				if p.Path != outside || ev.Authority != record.AuthorityGate || ev.Reason != record.ReasonFSGate {
					t.Errorf("refused chmod line %q: authority %s reason %s, want %q under the gate (%s)", p.Path,
						ev.Authority, ev.Reason, outside, record.ReasonFSGate)
				}
				refused++
			}
			if refused != 2 {
				t.Errorf("%d refused chmod lines, want 2 (fchmodat and fchmod outside the worktree)", refused)
			}
		})
	}
}
