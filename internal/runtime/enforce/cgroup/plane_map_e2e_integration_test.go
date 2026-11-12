// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// planeMapContract is step C's end-to-end contract: a write directory, an exec.allow directory inside it, python3.
const planeMapContract = `version: 0
name: plane-map-e2e
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
exec:
  allow: ["python3", "./out/lib/"]
net:
  allow: []
env:
  pass: ["PATH", "HOME"]
record: summary
`

// planeMapAgent maps code the way a native extension, a JIT or a dropper would, and reports each outcome as
// "RESULT <name> <outcome>". Every map is made through libc, so the errno is the kernel's.
const planeMapAgent = `import ctypes, os, shutil

libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
libc.personality.argtypes = [ctypes.c_ulong]
PR, PW, PX, PRIVATE = 1, 2, 4, 2
PAGE = os.sysconf("SC_PAGE_SIZE")
FAILED = ctypes.c_void_p(-1).value

def result(name, outcome):
    print("RESULT", name, outcome, flush=True)

def attempt(name, fn):
    try:
        fn()
        result(name, "ok")
    except OSError as e:
        if e.errno is None:
            result(name, "refused dlopen")
        else:
            result(name, "refused errno=%d" % e.errno)

def mapfd(fd, prot):
    a = libc.mmap(None, PAGE, prot, PRIVATE, fd, 0)
    if a is None or a == FAILED:
        raise OSError(ctypes.get_errno(), "mmap")
    return a

def map_file(path, prot):
    fd = os.open(path, os.O_RDONLY)
    try:
        libc.munmap(mapfd(fd, prot), PAGE)
    finally:
        os.close(fd)

def mprotect_file(path, p0, p1, dirty=False):
    fd = os.open(path, os.O_RDONLY)
    try:
        a = mapfd(fd, p0)
        try:
            if dirty:
                ctypes.memset(a, 0, 1)
            if libc.mprotect(a, PAGE, p1) != 0:
                raise OSError(ctypes.get_errno(), "mprotect")
        finally:
            libc.munmap(a, PAGE)
    finally:
        os.close(fd)

def memfd_map(flags, prot):
    fd = os.memfd_create("tego-e2e", flags)
    try:
        os.ftruncate(fd, PAGE)
        libc.munmap(mapfd(fd, prot), PAGE)
    finally:
        os.close(fd)

def memfd_any_map(prot):
    try:
        memfd_map(os.MFD_CLOEXEC | 8, prot)  # MFD_NOEXEC_SEAL, where the kernel has it
    except OSError as e:
        if e.errno != 22:
            raise
        memfd_map(os.MFD_CLOEXEC, prot)

libm = ctypes.CDLL("libm.so.6")
path = [l.split()[-1] for l in open("/proc/self/maps") if "libm" in l and "/" in l][0]
shutil.copyfile(path, "out/libm-dropped.so")
shutil.copyfile(path, "out/lib/libm-listed.so")
with open("out/drop.so", "wb") as f:
    f.write(b"\x7fELF" + bytes(PAGE))

attempt("map-dropped", lambda: map_file("out/drop.so", PR | PX))
attempt("map-dropped-read", lambda: map_file("out/drop.so", PR))
attempt("mprotect-dropped", lambda: mprotect_file("out/drop.so", PR, PR | PX))
attempt("map-exec-dir", lambda: map_file("out/lib/libm-listed.so", PR | PX))
attempt("map-system", lambda: map_file(path, PR | PX))
attempt("ctypes-system-lib", lambda: ctypes.CDLL(path, mode=os.RTLD_NOW))
attempt("dlopen-dropped-lib", lambda: ctypes.CDLL(os.path.abspath("out/libm-dropped.so")))
attempt("dlopen-exec-dir-lib", lambda: ctypes.CDLL(os.path.abspath("out/lib/libm-listed.so")))
attempt("execmod", lambda: mprotect_file(path, PR | PW, PR | PX, dirty=True))
attempt("memfd-create", lambda: os.close(os.memfd_create("tego-e2e", 0)))
attempt("memfd-map-exec", lambda: memfd_any_map(PR | PX))
attempt("memfd-map-read", lambda: memfd_any_map(PR))
libc.personality(0x0400000)  # READ_IMPLIES_EXEC, for what remains
attempt("rie-map-dropped", lambda: map_file("out/drop.so", PR))
`

// machineExecmod is this machine's own answer, outside any run, to execmod: a private writable map of a file,
// written, then made executable, as the agent's execmod attempt does. "ok", or "refused errno=N" as the agent writes
// it. An LSM can refuse it to every process: SELinux enforcing on AlmaLinux 9.8 answers EACCES (2026-11-10).
func machineExecmod(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "execmod-probe")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	page := os.Getpagesize()
	if _, err := f.Write(make([]byte, page)); err != nil {
		t.Fatal(err)
	}
	b, err := unix.Mmap(int(f.Fd()), 0, page, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Munmap(b) }()
	b[0] = 1
	var errno unix.Errno
	if err := unix.Mprotect(b, unix.PROT_READ|unix.PROT_EXEC); errors.As(err, &errno) {
		return fmt.Sprintf("refused errno=%d", int(errno))
	} else if err != nil {
		t.Fatal(err)
	}
	return "ok"
}

// TestPlaneExecMapRunEndToEnd is TIER3-PLAN T14's acceptance through `tego run` (enforce-plane R26, R27): in each
// plane mode this machine passes, a python3 agent whose contract has an exec: section maps code as native
// extensions, JITs and droppers do. python3 itself, its libraries and a system library it loads with ctypes map as
// before; a file it drops under its write entry does not map executable (mmap, mprotect, dlopen, and a PROT_READ map
// under READ_IMPLIES_EXEC), while one under an exec.allow directory inside that entry does; a dirtied private map of a
// system library made executable (execmod) is refused; and a memfd is created where the kernel lacks
// MFD_NOEXEC_SEAL, the filter's refusing arm dropped (R27), yet never maps executable. The same run on the fanotify
// listener is the contrast: every map passes, and memfd_create is refused as before.
func TestPlaneExecMapRunEndToEnd(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	seal := true
	if fd, err := unix.MemfdCreate("tego-seal-probe", unix.MFD_CLOEXEC|0x8); errors.Is(err, unix.EINVAL) {
		seal = false
	} else if err == nil {
		_ = unix.Close(fd)
	}
	t.Logf("MFD_NOEXEC_SEAL honoured: %v", seal)
	execmod := machineExecmod(t)
	t.Logf("this machine's own answer to execmod, outside any run: %s", execmod)
	for _, mode := range append(modes, PlaneFanotify) {
		t.Run(mode, func(t *testing.T) {
			p := newPlaneProject(t, uid, gid, map[string]string{"agent.py": planeMapAgent, "agent.yaml": planeMapContract},
				[]string{"out", "out/lib"}, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			var out bytes.Buffer
			cmd := p.runAt(ctx, bin, "cgroup", "agent.yaml", mode, &out)
			err := cmd.Run()
			t.Logf("tego run (%s): %v\n%s", mode, err, out.String())
			if err != nil {
				t.Fatalf("the run did not complete: %v", err)
			}
			res := agentResults(t, out.String())
			want := map[string]string{
				"map-dropped-read": "ok", "map-exec-dir": "ok", "map-system": "ok", "ctypes-system-lib": "ok",
				"dlopen-exec-dir-lib": "ok", "memfd-map-read": "ok",
			}
			if mode == PlaneFanotify {
				for _, c := range []string{"map-dropped", "mprotect-dropped", "dlopen-dropped-lib", "execmod", "rie-map-dropped"} {
					want[c] = "ok"
				}
				// The listener decides no map: where the machine itself refuses execmod (SELinux enforcing on
				// AlmaLinux 9.8, selinuxuser_execmod off), the agent gets the machine's answer.
				want["execmod"] = execmod
				if seal {
					want["memfd-create"], want["memfd-map-exec"] = "refused errno=13", "ok"
				} else {
					want["memfd-create"], want["memfd-map-exec"], want["memfd-map-read"] =
						"refused errno=38", "refused errno=38", "refused errno=38"
				}
			} else {
				for _, c := range []string{"map-dropped", "mprotect-dropped", "execmod", "rie-map-dropped", "memfd-map-exec"} {
					want[c] = "refused errno=13"
				}
				want["dlopen-dropped-lib"] = "refused dlopen"
				if seal {
					want["memfd-create"] = "refused errno=13" // the sealing arm stays (R27)
				} else {
					want["memfd-create"] = "ok" // the refusing arm is dropped where the plane maps (R27)
				}
			}
			for name, w := range want {
				if res[name] != w {
					t.Errorf("%s: %q, want %q", name, res[name], w)
				}
			}
			if mode == PlaneFanotify {
				return
			}
			// Each refused map is the plane's own refused line.
			events := runEvents(t, p.ledger)
			for _, op := range []string{"mmap", "mprotect"} {
				if findEvent(events, func(e map[string]any) bool {
					return e["kind"] == "refused" && e["op"] == op && e["rule"] == "exec-map" &&
						e["reason"] == "exec-not-allowed" && strings.HasSuffix(fmt.Sprint(e["target"]), "/out/drop.so")
				}) == nil {
					t.Errorf("no refused %s line with rule exec-map for out/drop.so", op)
				}
			}
		})
	}
}
