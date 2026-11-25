// SPDX-License-Identifier: Apache-2.0

//go:build integration && linux

package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// planeBlockDeep and planeBlockDeepDirs are the overflow phase's blocks: that many files, each at the end of its own
// chain of folders, so their rows (each folder a guard) pass the slot's 1024 while the overlay holds at most
// liveblock.MaxBlocks blocks.
const (
	planeBlockDeep     = 56
	planeBlockDeepDirs = 20
)

// xattrsWork is whether the filesystem holding p takes a user extended attribute (asked as root, outside the run), so
// a probe's "skipped" is the filesystem's answer and not a refusal that went unseen.
func xattrsWork(t *testing.T, p string) bool {
	t.Helper()
	err := unix.Setxattr(p, "user.tego-probe", []byte("1"), 0)
	if err == nil {
		_ = unix.Removexattr(p, "user.tego-probe")
		return true
	}
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
		return false
	}
	t.Fatalf("setxattr %s: %v", p, err)
	return false
}

// awaitLine waits for a line of the file at p that starts with prefix and decodes the JSON after it, or fails.
func awaitLine(t *testing.T, p, prefix string, ended <-chan error) map[string]any {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		raw, _ := os.ReadFile(p)
		for _, line := range strings.Split(string(raw), "\n") {
			if rest, ok := strings.CutPrefix(line, prefix); ok && json.Valid([]byte(rest)) {
				var got map[string]any
				if err := json.Unmarshal([]byte(rest), &got); err != nil {
					t.Fatal(err)
				}
				return got
			}
		}
		select {
		case err := <-ended:
			t.Fatalf("the run ended before its %s line: %v\n%s", prefix, err, raw)
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no %s line in 60s", prefix)
	return nil
}

// ADR 0124's amendment of 2026-11-21 on the real kernel: a live path or write block on a run whose decision plane
// decides file changes in the kernel (tiers cgroup and bpflsm, plane modes lsm and fmod_ret) refuses the changes, and a
// path block the reads, that the plane decides with no notification to the supervisor. Before it a write block there
// refused only what still reached the supervisor: every write open, create, delete, rename and truncate the plane
// decides went through.

// planeBlockProbe waits for each phase's word in out/, runs that phase's actions and writes what each came to, as
// errno names, to out/<phase>.json. The test places and removes blocks between the phases.
const planeBlockProbe = `import ctypes, errno, json, os, subprocess, sys, threading, time
P = os.path.join(os.getcwd(), "out")
def wait(word):
    while not os.path.exists(os.path.join(P, word)):
        time.sleep(0.02)
def attempt(res, name, f):
    try:
        r = f()
        res[name] = "ok" if r is None else r
    except OSError as e:
        res[name] = errno.errorcode.get(e.errno, str(e.errno))
def write_open(p, flags=os.O_WRONLY):
    fd = os.open(p, flags, 0o644)
    os.close(fd)
def read_open(p):
    with open(p) as f:
        f.read()
def setx(p):
    try:
        os.setxattr(p, "user.tego", b"1")
    except OSError as e:
        if e.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            return "skipped"
        raise
def rmx(p):
    try:
        os.removexattr(p, "user.tego")
    except OSError as e:
        if e.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            return "skipped"
        raise
libc = ctypes.CDLL(None, use_errno=True)
def exchange(a, b):
    if libc.renameat2(-100, a.encode(), -100, b.encode(), 2) != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
def tmpfile(d):
    return os.open(d, os.O_TMPFILE | os.O_WRONLY, 0o600)
def tmplink(dst):
    fd = tmpfile(P)
    try:
        os.link("/proc/self/fd/%d" % fd, dst)
    finally:
        os.close(fd)
def report(word, res):
    print(word + " " + json.dumps(res), flush=True)
B = os.path.join(P, "mid", "blk")
CHILD = "import errno, os, sys\ntry:\n    fd = os.open(sys.argv[1], os.O_WRONLY)\n    os.close(fd)\n    print('ok')\nexcept OSError as e:\n    print(errno.errorcode.get(e.errno, str(e.errno)))\n"
early = os.open(os.path.join(B, "early.txt"), os.O_RDWR)
early_path = os.open(os.path.join(B, "f.txt"), os.O_PATH)
open(os.path.join(P, "ready"), "w").close()
wait("go1")
res = {}
attempt(res, "write_open", lambda: write_open(os.path.join(B, "f.txt")))
attempt(res, "rdwr_open", lambda: write_open(os.path.join(B, "f.txt"), os.O_RDWR))
attempt(res, "trunc_open", lambda: write_open(os.path.join(B, "f.txt"), os.O_WRONLY | os.O_TRUNC))
attempt(res, "create", lambda: write_open(os.path.join(B, "new.txt"), os.O_WRONLY | os.O_CREAT))
res["create_left_file"] = os.path.exists(os.path.join(B, "new.txt"))
attempt(res, "deep_write", lambda: write_open(os.path.join(B, "sub", "g.txt")))
attempt(res, "deep_create", lambda: write_open(os.path.join(B, "sub", "n.txt"), os.O_WRONLY | os.O_CREAT))
attempt(res, "unlink", lambda: os.unlink(os.path.join(B, "f.txt")))
attempt(res, "rmdir", lambda: os.rmdir(os.path.join(B, "empty")))
attempt(res, "rename_out", lambda: os.rename(os.path.join(B, "f.txt"), os.path.join(P, "moved.txt")))
attempt(res, "rename_in", lambda: os.rename(os.path.join(P, "free.txt"), os.path.join(B, "in.txt")))
attempt(res, "rename_over", lambda: os.rename(os.path.join(P, "free.txt"), os.path.join(B, "f.txt")))
attempt(res, "rename_inside", lambda: os.rename(os.path.join(B, "sub"), os.path.join(B, "sub3")))
attempt(res, "link_out", lambda: os.link(os.path.join(B, "f.txt"), os.path.join(P, "hl2")))
attempt(res, "link_in", lambda: os.link(os.path.join(P, "free.txt"), os.path.join(B, "hl")))
attempt(res, "mkdir", lambda: os.mkdir(os.path.join(B, "d")))
attempt(res, "symlink", lambda: os.symlink("x", os.path.join(B, "sl")))
attempt(res, "truncate", lambda: os.truncate(os.path.join(B, "f.txt"), 0))
attempt(res, "ftruncate_early", lambda: os.ftruncate(early, 0))
attempt(res, "write_early", lambda: (os.write(early, b"still"), None)[1])
attempt(res, "chmod", lambda: os.chmod(os.path.join(B, "f.txt"), 0o600))
attempt(res, "setxattr", lambda: setx(os.path.join(B, "f.txt")))
attempt(res, "hardlink_before", lambda: write_open(os.path.join(P, "hl_solo")))
attempt(res, "hardlink_into_folder", lambda: write_open(os.path.join(P, "hl_folder")))
attempt(res, "rename_ancestor", lambda: os.rename(os.path.join(P, "mid"), os.path.join(P, "mid2")))
attempt(res, "absent_create", lambda: write_open(os.path.join(P, "absent.txt"), os.O_WRONLY | os.O_CREAT))
res["absent_left_file"] = os.path.exists(os.path.join(P, "absent.txt"))
attempt(res, "free_write", lambda: write_open(os.path.join(P, "free.txt")))
attempt(res, "free_create", lambda: write_open(os.path.join(P, "free2.txt"), os.O_WRONLY | os.O_CREAT))
attempt(res, "read_blocked_by_write", lambda: read_open(os.path.join(B, "f.txt")))
t = {}
th = threading.Thread(target=lambda: attempt(t, "x", lambda: write_open(os.path.join(B, "f.txt"))))
th.start(); th.join()
res["thread_write"] = t["x"]
pid = os.fork()
if pid == 0:
    try:
        write_open(os.path.join(B, "f.txt"))
        os._exit(0)
    except OSError as e:
        os._exit(e.errno)
_, status = os.waitpid(pid, 0)
code = os.waitstatus_to_exitcode(status)
res["fork_write"] = "ok" if code == 0 else errno.errorcode.get(code, str(code))
p = subprocess.run([sys.executable, "-c", CHILD, os.path.join(B, "f.txt")], capture_output=True, text=True)
res["exec_write"] = p.stdout.strip() if p.returncode == 0 else "failed " + p.stderr[-200:]
attempt(res, "path_read", lambda: read_open(os.path.join(P, "rd", "r.txt")))
attempt(res, "path_write", lambda: write_open(os.path.join(P, "rd", "r.txt")))
attempt(res, "rename_exchange", lambda: exchange(os.path.join(P, "free.txt"), os.path.join(B, "f.txt")))
attempt(res, "tmpfile_in", lambda: os.close(tmpfile(B)))
attempt(res, "tmpfile_free", lambda: os.close(tmpfile(P)))
attempt(res, "tmpfile_link_in", lambda: tmplink(os.path.join(B, "tl")))
attempt(res, "tmpfile_link_absent", lambda: tmplink(os.path.join(P, "absent.txt")))
res["tmplink_left_file"] = os.path.exists(os.path.join(B, "tl")) or os.path.exists(os.path.join(P, "absent.txt"))
attempt(res, "proc_reopen", lambda: write_open("/proc/self/fd/%d" % early_path))
rfd = os.open(os.path.join(B, "f.txt"), os.O_RDONLY)
attempt(res, "fchmod", lambda: os.fchmod(rfd, 0o600))
attempt(res, "fchown", lambda: os.fchown(rfd, os.getuid(), -1))
attempt(res, "removexattr", lambda: rmx(os.path.join(B, "f.txt")))
attempt(res, "mnt_write", lambda: write_open(os.path.join(B, "mnt", "m.txt")))
attempt(res, "mnt_create", lambda: write_open(os.path.join(B, "mnt", "n.txt"), os.O_WRONLY | os.O_CREAT))
attempt(res, "mnt_setxattr", lambda: setx(os.path.join(B, "mnt", "m.txt")))
json.dump(res, open(os.path.join(P, "phase1.json"), "w"))
wait("gomv")
mv = {}
HM = os.path.join(P, "hostmid", "blk")
attempt(mv, "moved_write", lambda: write_open(os.path.join(HM, "f.txt")))
attempt(mv, "moved_create", lambda: write_open(os.path.join(HM, "made.txt"), os.O_WRONLY | os.O_CREAT))
attempt(mv, "moved_solo_link", lambda: write_open(os.path.join(P, "hl_solo")))
json.dump(mv, open(os.path.join(P, "moved.json"), "w"))
wait("go2")
res = {}
attempt(res, "write_open", lambda: write_open(os.path.join(B, "f.txt")))
attempt(res, "create", lambda: write_open(os.path.join(B, "new2.txt"), os.O_WRONLY | os.O_CREAT))
attempt(res, "absent_create", lambda: write_open(os.path.join(P, "absent.txt"), os.O_WRONLY | os.O_CREAT))
attempt(res, "path_read", lambda: read_open(os.path.join(P, "rd", "r.txt")))
attempt(res, "rename_ancestor", lambda: os.rename(os.path.join(P, "mid"), os.path.join(P, "mid2")))
json.dump(res, open(os.path.join(P, "phase2.json"), "w"))
wait("go3")
res = {}
attempt(res, "free_write", lambda: write_open(os.path.join(P, "free.txt")))
attempt(res, "free_read", lambda: read_open(os.path.join(P, "free.txt")))
report("PHASE3", res)
wait("go4")
res = {}
attempt(res, "free_write", lambda: write_open(os.path.join(P, "free.txt")))
report("PHASE4", res)
`

// newPlaneBlockScene is a root run of planeBlockProbe pinned to tier and plane: fs.write on ./out/, nothing else, so a
// live block is the only refusal under it.
func newPlaneBlockScene(t *testing.T, bin, tier, plane, python string, allow []string) *askReadScene {
	t.Helper()
	if _, _, ok := agentUID(t); !ok {
		t.Skip("needs SUDO_UID naming the invoking user, as `sudo go test` and test/vm/root-suites.sh give")
	}
	q := func(ss []string) string {
		out := make([]string, 0, len(ss))
		for _, s := range ss {
			out = append(out, fmt.Sprintf("%q", s))
		}
		return "[" + strings.Join(out, ", ") + "]"
	}
	contract := fmt.Sprintf(`version: 0
name: rootplaneblock
command: %s
tier: landlock
fs:
  write: ["./out/"]
exec:
  allow: %s
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 64
record: summary
`, q([]string{python}), q(allow))
	s := &askReadScene{bin: bin}
	s.f = newFixture(t, contract)
	pinned := strings.Replace(contract, "tier: landlock\n", "tier: "+tier+"\n", 1)
	if err := os.WriteFile(filepath.Join(s.f.dir, "agent.yaml"), []byte(pinned), 0o600); err != nil {
		t.Fatal(err)
	}
	owned := []string{filepath.Join(s.f.dir, "agent.yaml")}
	files := map[string]string{
		"probe.py":              planeBlockProbe,
		"out/mid/blk/f.txt":     "f",
		"out/mid/blk/early.txt": "early",
		"out/mid/blk/sub/g.txt": "g",
		"out/mid/blk/empty/.mk": "",
		"out/free.txt":          "free",
		"out/rd/r.txt":          "r",
		"out/solo/solo.txt":     "solo",
	}
	for name, body := range files {
		p := filepath.Join(s.f.dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// empty/ must be empty for its rmdir; .mk only made it.
	if err := os.Remove(filepath.Join(s.f.dir, "out/mid/blk/empty/.mk")); err != nil {
		t.Fatal(err)
	}
	// Hard links made before any block. out/hl_solo names out/solo/solo.txt, which a block names itself: on a plane run
	// the block follows the file, so it is refused by this name too. out/hl_folder names a file inside a blocked folder: another
	// name in another folder, which no row above it keys, so it is not refused (as the supervisor's path match does not
	// refuse it either).
	if err := os.Link(filepath.Join(s.f.dir, "out/solo/solo.txt"), filepath.Join(s.f.dir, "out/hl_solo")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(s.f.dir, "out/mid/blk/f.txt"), filepath.Join(s.f.dir, "out/hl_folder")); err != nil {
		t.Fatal(err)
	}
	agentOwnsTree(t, filepath.Join(s.f.dir, "out"))
	agentOwns(t, append(owned, filepath.Join(s.f.dir, "probe.py"))...)
	s.env = isolatedEnv(t, s.f)
	if plane != "" {
		s.env = append(s.env, "TEGO_TEST_PLANE="+plane)
	}
	return s
}

// awaitGap waits until the run's ledger in dir holds n lines whose text holds word, or fails.
func awaitGap(t *testing.T, dir, word string, n int, ended <-chan error) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
		if err == nil && strings.Count(string(raw), word) >= n {
			return
		}
		select {
		case err := <-ended:
			t.Fatalf("the run ended before %d %s lines: %v", n, word, err)
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no %d %s lines in 30s", n, word)
}

// TestRootLiveBlockInPlane is A35 on the real kernel. While the run runs, a write block on out/mid/blk and on the absent
// out/absent.txt, and a path block on out/rd, are placed through the run's overlay, as `tego block` places them; once
// the launcher's live-block-added lines are in, the probe tries every class of change at and beneath the blocked folder.
// Each is refused EACCES (truncate(2) also EPERM where Landlock is below ABI 3: planeBlockRefusals), in the kernel,
// with nothing left behind: a write, read-write and truncating open, a create (deep too), unlink, rmdir, rename out of it, into it and over a file in it, a rename inside it, a link out of it and
// into it, mkdir, symlink, truncate and ftruncate, chmod, setxattr and removexattr (on a filesystem with no user
// xattrs too: the plane's hook is asked before the filesystem's handler), the file
// under a hard link made before a block on that file, the rename of the folder above it, the creation of the absent blocked name,
// from a thread, a forked child and an exec'd program alike; a plain read of the write-blocked file is not refused, and
// the path block refuses a read and a write under out/rd. What lies outside the blocks is untouched. A descriptor opened
// for writing before the block keeps writing (the stated residual), though its ftruncate is refused. The refused lines
// name the block's rule. After the blocks are removed the same actions go through.
func TestRootLiveBlockInPlane(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: tiers cgroup and bpflsm")
	}
	bin := tegoBPFBinary(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range strictPlanes {
		t.Run(tc.tier+"/"+tc.plane, func(t *testing.T) {
			s := newPlaneBlockScene(t, bin, tc.tier, tc.plane, python, []string{python, resolved})
			requireStrictPlane(t, s, tc.tier, tc.plane)
			// A tmpfs mounted beneath the write-blocked folder before the run: its root is a MOUNT_ONLY row for the
			// attribute hooks' walk inside its superblock, and a path walk crosses it to the block.
			mnt := filepath.Join(s.f.out, "mid", "blk", "mnt")
			if err := os.MkdirAll(mnt, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mount("tmpfs", mnt, "tmpfs", 0, "size=1m,mode=0755"); err != nil {
				t.Fatalf("mount a tmpfs beneath the block: %v", err)
			}
			t.Cleanup(func() {
				for _, at := range []string{"mid", "mid2", "hostmid"} {
					_ = unix.Unmount(filepath.Join(s.f.out, at, "blk", "mnt"), unix.MNT_DETACH)
				}
			})
			if err := os.WriteFile(filepath.Join(mnt, "m.txt"), []byte("m"), 0o644); err != nil {
				t.Fatal(err)
			}
			// The overflow phase's chains of folders.
			var deep []string
			for i := 0; i < planeBlockDeep; i++ {
				d := filepath.Join(s.f.out, "deep", fmt.Sprintf("b%02d", i))
				for j := 0; j < planeBlockDeepDirs; j++ {
					d = filepath.Join(d, fmt.Sprintf("d%02d", j))
				}
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
				f := filepath.Join(d, "f.txt")
				if err := os.WriteFile(f, nil, 0o644); err != nil {
					t.Fatal(err)
				}
				deep = append(deep, f)
			}
			agentOwnsTree(t, mnt, filepath.Join(s.f.out, "deep"))
			abi, err := sys.LandlockABI()
			if err != nil {
				t.Fatalf("the Landlock ABI of this machine: %v", err)
			}
			xattrs := xattrsWork(t, filepath.Join(s.f.out, "free.txt"))
			mntXattrs := xattrsWork(t, filepath.Join(mnt, "m.txt"))
			cmd := s.tego(t, "run", filepath.Join(s.f.dir, "agent.yaml"), "--", python, "probe.py")
			cmd.Dir = s.f.dir
			var out strings.Builder
			// The probe reports its overflow phases on stdout: under a write overflow it can write no file.
			stdout := filepath.Join(t.TempDir(), "stdout")
			so, err := os.Create(stdout)
			if err != nil {
				t.Fatal(err)
			}
			defer so.Close()
			cmd.Stdout, cmd.Stderr = so, &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			ended := make(chan error, 1)
			go func() { ended <- cmd.Wait() }()
			t.Cleanup(func() { _ = cmd.Process.Kill() }) // a no-op once the run has ended
			dir := liveRunDir(t, s.f.root, ended, time.Now().Add(30*time.Second), 10*time.Millisecond)
			id := filepath.Base(dir)
			// The probe holds its early descriptor open before any block lands.
			awaitFile(t, filepath.Join(s.f.out, "ready"), ended, &out)
			blocks := []struct {
				kind  liveblock.Kind
				value string
			}{
				{liveblock.KindWrite, filepath.Join(s.f.out, "mid", "blk")},
				{liveblock.KindWrite, filepath.Join(s.f.out, "absent.txt")},
				{liveblock.KindPath, filepath.Join(s.f.out, "rd")},
				{liveblock.KindWrite, filepath.Join(s.f.out, "solo", "solo.txt")},
			}
			updateOverlay(t, dir, id, func(o *liveblock.Overlay) error {
				for _, b := range blocks {
					if _, _, err := o.Add(b.kind, b.value, "uid:0 pid:1 cli", time.Now()); err != nil {
						return err
					}
				}
				return nil
			})
			awaitGap(t, dir, record.GapLiveBlockAdded, len(blocks), ended)
			if err := os.WriteFile(filepath.Join(s.f.out, "go1"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			phase1 := awaitJSON(t, filepath.Join(s.f.out, "phase1.json"), ended, &out)
			t.Logf("phase 1 (Landlock ABI %d, user xattrs on the run's filesystem %v, on the tmpfs %v): %v", abi, xattrs, mntXattrs, phase1)
			// A host-side move of the blocked folder's parent (an IDE, a checkout): the objects the blocks landed on stay
			// blocked under their new path. The launcher re-walks every half second; two ticks pass before the probe
			// tries, so a re-walk that dropped what moved would show.
			if err := os.Rename(filepath.Join(s.f.out, "mid"), filepath.Join(s.f.out, "hostmid")); err != nil {
				t.Fatal(err)
			}
			time.Sleep(1500 * time.Millisecond)
			if err := os.WriteFile(filepath.Join(s.f.out, "gomv"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			moved := awaitJSON(t, filepath.Join(s.f.out, "moved.json"), ended, &out)
			for _, k := range []string{"moved_write", "moved_create", "moved_solo_link"} {
				if moved[k] != "EACCES" {
					t.Errorf("after the host-side move %s = %v, want EACCES (all: %v)", k, moved[k], moved)
				}
			}
			if err := os.Rename(filepath.Join(s.f.out, "hostmid"), filepath.Join(s.f.out, "mid")); err != nil {
				t.Fatal(err)
			}
			updateOverlay(t, dir, id, func(o *liveblock.Overlay) error {
				for _, b := range blocks {
					if _, _, err := o.Remove(b.kind, b.value, "uid:0 pid:1 cli", time.Now()); err != nil {
						return err
					}
				}
				return nil
			})
			awaitGap(t, dir, record.GapLiveBlockRemoved, len(blocks), ended)
			if err := os.WriteFile(filepath.Join(s.f.out, "go2"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			phase2 := awaitJSON(t, filepath.Join(s.f.out, "phase2.json"), ended, &out)
			// Overflow: blocks whose rows pass the slot's map refuse their class whole, broader than asked; once they
			// are removed the class is no longer refused.
			updateOverlay(t, dir, id, func(o *liveblock.Overlay) error {
				for _, f := range deep {
					if _, _, err := o.Add(liveblock.KindWrite, f, "uid:0 pid:1 cli", time.Now()); err != nil {
						return err
					}
				}
				return nil
			})
			awaitGap(t, dir, record.GapLiveBlockAdded, len(blocks)+len(deep), ended)
			if err := os.WriteFile(filepath.Join(s.f.out, "go3"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			phase3 := awaitLine(t, stdout, "PHASE3 ", ended)
			updateOverlay(t, dir, id, func(o *liveblock.Overlay) error {
				for _, f := range deep {
					if _, _, err := o.Remove(liveblock.KindWrite, f, "uid:0 pid:1 cli", time.Now()); err != nil {
						return err
					}
				}
				return nil
			})
			awaitGap(t, dir, record.GapLiveBlockRemoved, len(blocks)+len(deep), ended)
			if err := os.WriteFile(filepath.Join(s.f.out, "go4"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			phase4 := awaitLine(t, stdout, "PHASE4 ", ended)
			if phase3["free_write"] != "EACCES" || phase3["free_read"] != "ok" {
				t.Errorf("under a write overflow free_write = %v (want EACCES) and free_read = %v (want ok)",
					phase3["free_write"], phase3["free_read"])
			}
			if phase4["free_write"] != "ok" {
				t.Errorf("after the overflowing blocks were removed free_write = %v, want ok", phase4["free_write"])
			}
			select {
			case err := <-ended:
				if code := exitCodeOf(t, err); code != 0 {
					t.Fatalf("tego run exited %d:\n%s", code, out.String())
				}
			case <-time.After(60 * time.Second):
				t.Fatalf("tego run did not end:\n%s", out.String())
			}
			evs := events(t, dir)
			if got := runPlane(t, evs); got != tc.plane {
				t.Fatalf("the run's decision plane is %q, want %q", got, tc.plane)
			}
			// The xattr changes are refused whether or not the filesystem takes user xattrs: the kernel asks the LSM
			// hooks (security_inode_setxattr, _removexattr) before the filesystem's handler can answer "not
			// supported", on every kernel, so a filesystem without them (tmpfs below 6.6, as on Amazon Linux 2023's
			// 6.1) shows the plane's EACCES, never the probe's "skipped".
			refused := []string{"write_open", "rdwr_open", "trunc_open", "create", "deep_write", "deep_create", "unlink",
				"rmdir", "rename_out", "rename_in", "rename_over", "rename_inside", "link_out", "link_in", "mkdir", "symlink",
				"truncate", "ftruncate_early", "chmod", "hardlink_before", "rename_ancestor", "absent_create",
				"thread_write", "fork_write", "exec_write", "path_read", "path_write",
				"rename_exchange", "tmpfile_in", "proc_reopen", "fchmod", "fchown", "mnt_write", "mnt_create",
				"setxattr", "removexattr", "mnt_setxattr"}
			// An O_TMPFILE linked through /proc/self/fd into the blocked folder or onto the absent name: Landlock's
			// refer check refuses the link EXDEV before any LSM hook (seen on 6.17, both boots; the unlinked file has no
			// folder to refer from), so the plane is not asked; it must be refused either way and leave no file.
			for _, k := range []string{"tmpfile_link_in", "tmpfile_link_absent"} {
				if x := phase1[k]; x != "EACCES" && x != "EXDEV" {
					t.Errorf("phase 1 %s = %v, want EACCES or EXDEV (all: %v)", k, x, phase1)
				}
			}
			for _, k := range refused {
				if !planeBlockRefused(k, phase1[k], abi) {
					t.Errorf("phase 1 %s = %v, want %s (Landlock ABI %d; all: %v)", k, phase1[k],
						strings.Join(planeBlockRefusals(k, abi), " or "), abi, phase1)
				}
			}
			for _, k := range []string{"write_early", "free_write", "free_create", "read_blocked_by_write", "hardlink_into_folder",
				"tmpfile_free"} {
				if phase1[k] != "ok" {
					t.Errorf("phase 1 %s = %v, want ok (all: %v)", k, phase1[k], phase1)
				}
			}
			for _, k := range []string{"create_left_file", "absent_left_file", "tmplink_left_file"} {
				if phase1[k] != false {
					t.Errorf("phase 1 %s = %v, want false: a refused create leaves no file", k, phase1[k])
				}
			}
			for _, k := range []string{"write_open", "create", "absent_create", "path_read", "rename_ancestor"} {
				if phase2[k] != "ok" {
					t.Errorf("phase 2 (blocks removed) %s = %v, want ok (all: %v)", k, phase2[k], phase2)
				}
			}
			// The plane's refusals name the block whose rule refused them.
			want := map[string]bool{
				liveblock.Rule(liveblock.KindWrite, filepath.Join(s.f.out, "mid", "blk")): false,
				liveblock.Rule(liveblock.KindWrite, filepath.Join(s.f.out, "absent.txt")): false,
				liveblock.Rule(liveblock.KindPath, filepath.Join(s.f.out, "rd")):          false,
				// hardlink_before: the file's own block, met through its other name.
				liveblock.Rule(liveblock.KindWrite, filepath.Join(s.f.out, "solo", "solo.txt")): false,
			}
			// The overflow's refusals name one of the blocks that overflowed.
			deepRules := map[string]bool{}
			for _, f := range deep {
				deepRules[liveblock.Rule(liveblock.KindWrite, f)] = true
			}
			overflowNamed := false
			for _, e := range evs {
				if e.Verdict == record.VerdictRefused {
					if _, ok := want[e.Rule]; ok {
						want[e.Rule] = true
					}
					overflowNamed = overflowNamed || deepRules[e.Rule]
				}
			}
			if !overflowNamed {
				t.Error("no refused line names a block of the overflow")
			}
			for rule, seen := range want {
				if !seen {
					t.Errorf("no refused line names %s", rule)
				}
			}
		})
	}
}

// awaitFile waits for p to exist, or fails with the run's output.
func awaitFile(t *testing.T, p string, ended <-chan error, out *strings.Builder) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(p); err == nil {
			return
		}
		select {
		case err := <-ended:
			t.Fatalf("the run ended before %s: %v\n%s", filepath.Base(p), err, out.String())
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no %s in 60s\n%s", filepath.Base(p), out.String())
}

// awaitJSON waits for the probe's JSON file p and decodes it, or fails with the run's output.
func awaitJSON(t *testing.T, p string, ended <-chan error, out *strings.Builder) map[string]any {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if raw, err := os.ReadFile(p); err == nil && len(raw) > 0 && json.Valid(raw) {
			var got map[string]any
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			return got
		}
		select {
		case err := <-ended:
			t.Fatalf("the run ended before %s: %v\n%s", filepath.Base(p), err, out.String())
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no %s in 60s\n%s", filepath.Base(p), out.String())
	return nil
}
