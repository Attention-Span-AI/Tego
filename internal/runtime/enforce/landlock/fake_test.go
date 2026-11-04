// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// pathCall and netCall are one logged landlock_add_rule each (I3).
type pathCall struct {
	FD     int
	Access uint64
	Flags  int
}

type netCall struct {
	Access uint64
	Port   uint64
	Flags  int
}

// fakeSyscalls is the Options.syscalls seam for unit tests (§2/§4/§9): it answers the ABI probe
// from abi, logs every rule, hands out a real fd for the ruleset so Close works, and fails where told.
type fakeSyscalls struct {
	abi      int
	probeErr error

	created []unix.LandlockRulesetAttr
	paths   []pathCall
	nets    []netCall

	createErr error
	addErr    error
	addErrAt  int // fail the n-th path rule (1-based) when addErr is set; 0 = first

	rulesets map[int]devIno // what each ruleset number CreateRuleset handed out named then, for ProbeRuleset
}

func (f *fakeSyscalls) CreateRuleset(attr *unix.LandlockRulesetAttr, flags int) (int, error) {
	if attr == nil {
		if f.probeErr != nil {
			return -1, f.probeErr
		}
		if flags != createRulesetVersion {
			return -1, unix.EINVAL
		}
		return f.abi, nil
	}
	if f.createErr != nil {
		return -1, f.createErr
	}
	f.created = append(f.created, *attr)
	// A memfd, not an O_PATH open: the kernel's ruleset lookup does not see O_PATH files, and each memfd
	// has an inode of its own, so no file a test stands at the number can pass for a ruleset.
	fd, err := unix.MemfdCreate("fake-landlock-ruleset", unix.MFD_CLOEXEC)
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if f.rulesets == nil {
		f.rulesets = map[int]devIno{}
	}
	f.rulesets[fd] = devIno{st.Dev, st.Ino}
	return fd, nil
}

// ProbeRuleset gives the kernel's three answers, with "a ruleset" meaning a number that still names the
// memfd CreateRuleset handed out at it: ENOMSG for a ruleset, EBADFD for any other file opened without
// O_PATH, and EBADF for a closed number or an O_PATH file, which the kernel's fdget lookup does not see.
func (f *fakeSyscalls) ProbeRuleset(fd int) error {
	fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	if fl&unix.O_PATH != 0 {
		return unix.EBADF
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if id, ok := f.rulesets[fd]; ok && id == (devIno{st.Dev, st.Ino}) {
		return unix.ENOMSG
	}
	return unix.EBADFD
}

func (f *fakeSyscalls) AddPathRule(_ int, attr *unix.LandlockPathBeneathAttr, flags int) error {
	f.paths = append(f.paths, pathCall{FD: int(attr.Parent_fd), Access: attr.Allowed_access, Flags: flags})
	if f.addErr != nil && len(f.paths) > f.addErrAt {
		return f.addErr
	}
	return nil
}

func (f *fakeSyscalls) AddNetPortRule(_ int, attr *netPortAttr, flags int) error {
	f.nets = append(f.nets, netCall{Access: attr.AllowedAccess, Port: attr.Port, Flags: flags})
	if f.addErr != nil {
		return f.addErr
	}
	return nil
}

// contractWith builds the minimal Contract the builder reads its restriction flags from.
func contractWith(exec, network bool) *agent.Contract {
	c := &agent.Contract{}
	if exec {
		c.Exec = &agent.ExecSection{}
	}
	if network {
		c.Net = &agent.NetSection{}
	}
	return c
}

func fsRule(kind agent.FSKind, path string) agent.FSRule {
	r := agent.FSRule{Path: path, Kind: kind}
	if kind == agent.FSWrite {
		r.Access = agent.AccessWriteSet
	}
	return r
}

// prepare runs Prepare at the given ABI with a fake kernel and returns the concrete handle.
func prepare(t *testing.T, abi int, rt *agent.RuleTable) (*Handle, *fakeSyscalls) {
	t.Helper()
	fake := &fakeSyscalls{abi: abi}
	b := New(Options{syscalls: fake})
	h, err := b.Prepare(context.Background(), rt, Run{})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h, fake
}

// prepareErr runs Prepare expecting failure and returns the error.
func prepareErr(t *testing.T, abi int, rt *agent.RuleTable, fake *fakeSyscalls) error {
	t.Helper()
	if fake == nil {
		fake = &fakeSyscalls{abi: abi}
	}
	fake.abi = abi
	h, err := New(Options{syscalls: fake}).Prepare(context.Background(), rt, Run{})
	if err == nil {
		_ = h.Close()
		t.Fatal("Prepare succeeded, want error")
	}
	return err
}

// entry finds the held entry for path; ok false when none.
func (h *Handle) entry(path string) (openPath, bool) {
	for _, p := range h.fds.open {
		if p.Path == path {
			return p, true
		}
	}
	return openPath{}, false
}

// entriesUnder counts held entries of kind directly under dir.
func (h *Handle) entriesUnder(dir string, kind entryKind) int {
	n := 0
	for _, p := range h.fds.open {
		if p.Kind == kind && filepath.Dir(p.Path) == dir {
			n++
		}
	}
	return n
}

// openFDs counts the process's open fds, for leak checks.
func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	return len(ents)
}

// mkTree creates dirs (trailing slash) and files under root.
func mkTree(t *testing.T, root string, paths ...string) {
	t.Helper()
	for _, p := range paths {
		full := filepath.Join(root, p)
		if p[len(p)-1] == '/' {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// staticELF writes a minimal ELF64 header with no program headers: ReadInterp sees a static binary.
func staticELF(t *testing.T, path string) {
	t.Helper()
	hdr := make([]byte, 64)
	copy(hdr, "\x7fELF")
	hdr[4], hdr[5], hdr[6] = 2, 1, 1
	le := binary.LittleEndian
	le.PutUint16(hdr[16:], 2)  // ET_EXEC
	le.PutUint16(hdr[18:], 62) // x86_64
	le.PutUint64(hdr[32:], 64) // phoff
	le.PutUint16(hdr[52:], 64) // ehsize
	le.PutUint16(hdr[54:], 56) // phentsize
	le.PutUint16(hdr[56:], 0)  // phnum
	if err := os.WriteFile(path, hdr, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mkdirAll(p string) error { return os.MkdirAll(p, 0o755) }

func writeFile(p string) error { return os.WriteFile(p, []byte("x"), 0o644) }

// dynamicELF writes a minimal ELF64 carrying a single PT_INTERP program header that names interp, so
// ReadInterp returns exactly that string: the loader path the file's own bytes choose (R5, E29).
func dynamicELF(t *testing.T, path, interp string) {
	t.Helper()
	const phoff, phentsize, stroff = 64, 56, 120
	buf := make([]byte, stroff+len(interp)+1)
	copy(buf, "\x7fELF")
	buf[4], buf[5], buf[6] = 2, 1, 1
	le := binary.LittleEndian
	le.PutUint16(buf[16:], 2)  // ET_EXEC
	le.PutUint16(buf[18:], 62) // x86_64
	le.PutUint64(buf[32:], phoff)
	le.PutUint16(buf[52:], 64)
	le.PutUint16(buf[54:], phentsize)
	le.PutUint16(buf[56:], 1)    // one program header
	le.PutUint32(buf[phoff:], 3) // PT_INTERP
	le.PutUint64(buf[phoff+8:], stroff)
	le.PutUint64(buf[phoff+32:], uint64(len(interp)+1))
	copy(buf[stroff:], interp)
	if err := os.WriteFile(path, buf, 0o755); err != nil {
		t.Fatal(err)
	}
}

// tempDir is a private directory resolved, with a short prefix so its unix socket fixtures fit sockaddr_un.
// The builder opens every entry through its symlinks and compares entries at
// their resolved paths (E8, enumerate's ancestor set), so under a TMPDIR that is or holds a symlink the
// unresolved spelling is not what it reports, and a test's expectations built from it would name another
// path than the one Prepare held.
func tempDir(t testing.TB) string {
	t.Helper()
	base, err := os.MkdirTemp("", "ll-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(base); err != nil {
			t.Error(err)
		}
	})
	// Keep a parent to clean up roots a test renames to a sibling, as t.TempDir does.
	dir := filepath.Join(base, "r")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	d, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// shortTempDir keeps socket fixtures below sockaddr_un's path bound without
// moving them out of TMPDIR when testing's name-based directory is too long.
func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "ll")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	d, err = filepath.EvalSymlinks(d)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
