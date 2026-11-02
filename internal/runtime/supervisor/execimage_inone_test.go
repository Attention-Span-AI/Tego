// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// componentWalkOnly turns lookupInOne off for the test, so the component walk answers every image walk.
func componentWalkOnly(t *testing.T) {
	t.Helper()
	prev := lookupInOneOn
	t.Cleanup(func() { lookupInOneOn = prev })
	lookupInOneOn = false
}

// inOneAnswers reports whether lookupInOne answers q, as walkImage asks it (w.named set as there), the descriptor it
// reached closed. Its RCU-only first lookup is EAGAIN whenever a mount or a rename anywhere on the host moves
// mount_lock or rename_lock meanwhile (a test that has just detached a debugfs does, and a freshly booted guest), so a
// decline is asked again, up to tries times a millisecond apart, before it counts: patient where the lookup must answer,
// once where any answer is wrong.
func inOneAnswers(t *testing.T, q pathQuery, tries int) (fileID, bool) {
	t.Helper()
	for i := range tries {
		if i > 0 {
			time.Sleep(time.Millisecond)
		}
		w, _, done, err := newWalk(q)
		if err != nil {
			return fileID{}, false
		}
		w.search = searchChecked()
		w.image = true
		w.named = namedByWalk(q)
		fd, ok := w.lookupInOne()
		done()
		if ok {
			var st unix.Stat_t
			err := unix.Fstat(fd, &st)
			_ = unix.Close(fd)
			if err != nil {
				t.Fatal(err)
			}
			return fileID{dev: st.Dev, ino: st.Ino}, true
		}
	}
	return fileID{}, false
}

// rawInOne makes lookupInOne's two lookups of p from task's root by hand, their flags spelt out rather than taken from
// the code under test: RESOLVE_CACHED|RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS, then
// RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV.
func rawInOne(t *testing.T, task int, p string) (rcuErr, xdevErr error) {
	t.Helper()
	root, err := unix.Open("/proc/"+strconv.Itoa(task)+"/root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(root) //nolint:errcheck // a descriptor this test opened
	lookup := func(resolve uint64) error {
		fd, err := unix.Openat2(root, p, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: resolve})
		if err == nil {
			_ = unix.Close(fd)
		}
		return err
	}
	return lookup(unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS | 0x20), lookup(unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV)
}

// mountID is the mount p lies on (its final symlink not followed).
func mountID(t *testing.T, p string) uint64 {
	t.Helper()
	var stx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, p, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &stx); err != nil {
		t.Fatalf("statx %s: %v", p, err)
	}
	return stx.Mnt_id
}

// TestLookupInOneIsTheComponentWalks holds lookupInOne, the image walk's one-call lookup (ADR 0048 C8), to the
// component walk it stands in for: over symlinks relative and absolute, chains, loops, dangling links, "." and ".."
// (spelled, which only the walk names, and inside a link's body), trailing slashes, procfs paths and mount crossings,
// ExecImage answers alike with and without it, errno, image and name alike. The task is another process, so a lookup
// that resolved procfs's "self" as this process would show: a symlink to /proc/self/task/<one of this process's
// threads>/../../../.. reaches the file for this process and not for the task, whose own lookup fails ENOENT there, and
// lookupInOne declines it (a mount is crossed at /proc). Where the test's directory lies on the root's mount,
// lookupInOne must answer the paths that stay on it and that the walk does not name, /bin/sh among them when it does
// too: the one-call lookup is what C8's #! case pays.
func TestLookupInOneIsTheComponentWalks(t *testing.T) {
	if searchChecked() {
		t.Skip("this process holds a DAC capability: image walks check the task's search permission and never ask lookupInOne")
	}
	dir := t.TempDir()
	task := spawnTask(t, dir)
	me := selfTask(t)
	f := filepath.Join(dir, "f")
	if err := os.WriteFile(f, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "d", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	viaProc := "/proc/self/task/" + strconv.Itoa(me) + "/../../../.." + f
	for link, to := range map[string]string{
		"rel": "f", "abs": f, "chain": "rel", "loop1": "loop2", "loop2": "loop1",
		"dangling": filepath.Join(dir, "none"), "dirlink": "d", "esc": "/../../.." + f, "updown": "d/sub/../../f",
		"toproc": "/proc/self/exe", "tofd": "/dev/fd/0", "empty-target-dir": "d/", "viaproc": viaProc,
	} {
		if err := os.Symlink(to, filepath.Join(dir, link)); err != nil {
			t.Fatal(err)
		}
	}
	onRoot := mountID(t, dir) == mountID(t, "/")
	if !onRoot {
		t.Logf("%s is not on the root's mount: lookupInOne declines every path under it (EXDEV)", dir)
	}
	shOnRoot := false
	if sh, err := filepath.EvalSymlinks("/bin/sh"); err == nil {
		shOnRoot = mountID(t, sh) == mountID(t, "/") && mountID(t, "/bin") == mountID(t, "/")
	}
	cases := []struct {
		path    string
		answers bool // lookupInOne must answer it (when its directory is on the root's mount)
	}{
		{f, true}, {filepath.Join(dir, "rel"), true}, {filepath.Join(dir, "abs"), true},
		{filepath.Join(dir, "chain"), true}, {filepath.Join(dir, "esc"), true}, {filepath.Join(dir, "updown"), true},
		{filepath.Join(dir, "empty-target-dir"), true}, {"/", true},
		// A spelled ".." or a final ".": the walk takes the line's name, so it answers.
		{dir + "/d/../f", false}, {filepath.Join(dir, "dirlink") + "/../f", false},
		{filepath.Join(dir, "d", "sub") + "/../../f", false}, {"/../../.." + f, false}, {dir + "/.", false},
		{filepath.Join(dir, "loop1"), false}, {filepath.Join(dir, "dangling"), false}, {f + "/", false},
		{f + "/.", false}, {filepath.Join(dir, "none"), false}, {filepath.Join(dir, "toproc"), false},
		{filepath.Join(dir, "tofd"), false}, {"/proc/self/exe", false}, {"/dev/fd/0", false},
		{filepath.Join(dir, "viaproc"), false}, {viaProc, false}, {"/proc/.." + f, false},
		{"/bin/sh", shOnRoot}, {"/bin/sh/", false},
	}
	// The procfs cases prove something only where this process's own lookup of them reaches f: a lookup that resolved
	// "self" as this process would answer them, and only the refusal of the mount crossing at /proc leaves them to the
	// component walk.
	if _, err := os.Stat(filepath.Join(dir, "viaproc")); err != nil {
		t.Fatal(err)
	}
	componentWalkOnly(t)
	for _, c := range cases {
		for _, head := range []bool{false, true} {
			q := pathQuery{tid: task, dirfd: atFDCWD, path: c.path, joined: c.path, head: head}
			lookupInOneOn = false
			want, wantErr := sysKernel{}.ExecImage(q)
			lookupInOneOn = true
			got, gotErr := sysKernel{}.ExecImage(q)
			if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || got.id != want.id || got.link != want.link ||
				got.regular != want.regular || got.linked != want.linked || got.unsure != want.unsure ||
				got.name != want.name || string(got.head) != string(want.head) || (gotErr == nil) != (wantErr == nil) {
				t.Errorf("%s (head %v): with lookupInOne %+v, %v; the component walk %+v, %v", c.path, head, got, gotErr,
					want, wantErr)
			}
			tries := 1
			if c.answers {
				tries = 50
			}
			id, answered := inOneAnswers(t, q, tries)
			switch {
			case answered && (wantErr != nil || id != want.id):
				t.Errorf("%s: lookupInOne answered %v where the component walk answers %v, %v", c.path, id, want.id, wantErr)
			case answered && !c.answers:
				t.Errorf("%s: lookupInOne answered; it must leave it to the component walk", c.path)
			case !answered && c.answers && (onRoot || c.path == "/" || c.path == "/bin/sh"):
				// The kernel's RCU walk alone cannot reach every path on every host (a symlink whose atime is due, an
				// overlayfs symlink, a filesystem that revalidates): the decline is lookupInOne's fault only where the
				// two lookups it makes, asked here with their flags spelt out, both reach the file now.
				if rcuErr, xdevErr := rawInOne(t, task, c.path); rcuErr == nil && xdevErr == nil {
					t.Errorf("%s: lookupInOne declined a path on the root's mount that both its lookups reach", c.path)
				} else {
					t.Logf("%s: this host's lookups do not reach it (RESOLVE_CACHED: %v, RESOLVE_NO_XDEV: %v): left to the component walk",
						c.path, rcuErr, xdevErr)
				}
			}
		}
	}
	if !shOnRoot {
		t.Logf("/bin/sh is not on the root's mount here: C8's #! case takes the component walk")
	}
}

// TestLookupInOneLeavesWhatOnlyTheWalkAnswers holds lookupInOne to the queries it must never answer, whatever the
// path: a search-checked walk (its lookup's permissions would be this process's, not the task's), a final symlink not
// followed, a relative pathname, and a walk that takes the line's name.
func TestLookupInOneLeavesWhatOnlyTheWalkAnswers(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "f")
	if err := os.WriteFile(f, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("f", filepath.Join(dir, "l")); err != nil {
		t.Fatal(err)
	}
	tid := selfTask(t)
	for _, c := range []struct {
		name   string
		q      pathQuery
		search bool
	}{
		{"search checked", pathQuery{tid: tid, dirfd: atFDCWD, path: f}, true},
		{"not followed", pathQuery{tid: tid, dirfd: atFDCWD, path: filepath.Join(dir, "l"), nofollow: true}, false},
		{"relative", pathQuery{tid: tid, dirfd: atFDCWD, path: "f"}, false},
		{"named", pathQuery{tid: tid, dirfd: atFDCWD, path: dir + "/../" + filepath.Base(dir) + "/f"}, false},
	} {
		w, _, done, err := newWalk(c.q)
		if err != nil {
			t.Fatal(err)
		}
		w.search, w.image, w.named = c.search, true, namedByWalk(c.q)
		if fd, ok := w.lookupInOne(); ok {
			_ = unix.Close(fd)
			t.Errorf("%s: lookupInOne answered", c.name)
		}
		done()
	}
}

// BenchmarkExecImageInterpreter is a #! interpreter's walk, the share of ADR 0048 C8's #! case that lookupInOne cuts:
// walk (no head), head (the head read too, as a run with command rules asks), held (from a held task root, as an exec's
// later walks start), components (lookupInOne off, the component walk alone).
func BenchmarkExecImageInterpreter(b *testing.B) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tid := unix.Gettid()
	for _, v := range []struct {
		name             string
		head, held, comp bool
	}{{"walk", false, false, false}, {"head", true, false, false}, {"held", true, true, false}, {"components", true, false, true}} {
		b.Run(v.name, func(b *testing.B) {
			q := pathQuery{tid: tid, dirfd: atFDCWD, path: "/bin/sh", joined: "/bin/sh", head: v.head}
			if v.held {
				q.root = new(taskRoot)
				defer q.root.close()
			}
			prev := lookupInOneOn
			defer func() { lookupInOneOn = prev }()
			lookupInOneOn = !v.comp
			if img, err := (sysKernel{}).ExecImage(q); err != nil || v.head && len(img.head) == 0 {
				b.Fatalf("walking /bin/sh: %v, head %q", err, img.head)
			}
			b.ReportAllocs()
			for b.Loop() {
				_, _ = sysKernel{}.ExecImage(q)
			}
		})
	}
}
