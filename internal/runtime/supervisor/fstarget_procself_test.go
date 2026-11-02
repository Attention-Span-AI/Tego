// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestFSTargetResolvesProcSelfAsTheTask: a symlink whose body goes through procfs's "self" or "thread-self" lands where
// the task's own lookup lands it. fsTargetInRoot's openat2 runs as this process, where "self" is this process: a link to
// /proc/self/task/<the task's tid>/../../../../<dir>/secret misses here (the tid is no thread of this process) and lands
// on <dir>/secret for the task. That miss was read as a missing final name and answered with the link's own name, so the
// verdict and the line were taken on <dir>/x while the kernel opened <dir>/secret (at tier landlock, an open for writing
// past a deny_write: TestIntegrationDenyWrite's config_write_through_proc_self). The task is another process: as the
// test process, "self" would be the same for both lookups and the case would prove nothing. Each case runs with the
// query alone, which the walk answers, and with R6's joined spelling, which lets the one-lookup paths answer where they
// can; both must land alike. A name missing for both lookups still takes fsTargetInRoot's one lookup.
func TestFSTargetResolvesProcSelfAsTheTask(t *testing.T) {
	dir := realDir(t, t.TempDir())
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"secret", "sub/inner"} {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pid := spawnTask(t, dir)
	task := strconv.Itoa(pid)
	// Each body through procfs climbs back out of it to dir: /proc/<tgid>/task/<tid> is four levels below "/", and
	// /proc/thread-self/.. is /proc/<tgid>/task, in which <tid> is that same place. al is a plain link to a directory: a
	// name missing beneath it is the shape the one lookup answers in FSTarget, where fsTargetIsSpelling answers a path
	// with no symlink on the way first.
	for link, body := range map[string]string{
		"x":  "/proc/self/task/" + task + "/../../../.." + dir + "/secret",
		"ts": "/proc/thread-self/../" + task + "/../../../.." + dir + "/secret",
		"l":  "/proc/self/task/" + task + "/../../../.." + dir + "/sub",
		"al": "sub",
	} {
		if err := os.Symlink(body, filepath.Join(dir, link)); err != nil {
			t.Fatal(err)
		}
	}
	// The premise: this process's own lookup of each link misses, since "self" is this process here.
	for _, p := range []string{"x", "ts", "l/inner"} {
		if _, err := os.Stat(filepath.Join(dir, p)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("stat %s here: %v, want a miss: the test cannot tell this process's lookup from the task's", p, err)
		}
	}
	for _, tc := range []struct {
		name string
		q    pathQuery
		want string
	}{
		{"a final link through the task's /proc/self/task", pathQuery{path: "x"}, filepath.Join(dir, "secret")},
		{"a final link through /proc/thread-self", pathQuery{path: "ts"}, filepath.Join(dir, "secret")},
		{"an O_CREAT open of a final link through /proc/self/task", pathQuery{path: "x", create: true}, filepath.Join(dir, "secret")},
		{"an intermediate link through /proc/self/task", pathQuery{path: "l/inner"}, filepath.Join(dir, "sub", "inner")},
		{"an unfollowed final link is the entry itself", pathQuery{path: "x", nofollow: true}, filepath.Join(dir, "x")},
		{"a name missing for both lookups", pathQuery{path: "none"}, filepath.Join(dir, "none")},
		{"a name missing for both lookups beneath a linked directory", pathQuery{path: "al/none"}, filepath.Join(dir, "sub", "none")},
	} {
		for _, joined := range []bool{false, true} {
			t.Run(tc.name+"/joined="+strconv.FormatBool(joined), func(t *testing.T) {
				q := tc.q
				q.tid, q.dirfd = pid, atFDCWD
				if joined {
					q.joined = filepath.Join(dir, q.path)
				}
				landing, err := sysKernel{}.FSTarget(q)
				if err != nil {
					t.Fatalf("FSTarget: %v", err)
				}
				if landing.at != tc.want {
					t.Errorf("landed %q, want %q (the task's own lookup)", landing.at, tc.want)
				}
			})
		}
	}
	// The one lookup declines the links it cannot follow as the task, and still answers a name missing for both.
	q := func(p string) pathQuery {
		return pathQuery{tid: pid, dirfd: atFDCWD, path: filepath.Join(dir, p), joined: filepath.Join(dir, p)}
	}
	for _, p := range []string{"x", "ts", "l/inner"} {
		if at, ok, err := fsTargetInRoot(q(p)); ok {
			t.Errorf("fsTargetInRoot(%s) = %q, %v: answered where only the walk resolves \"self\" as the task", p, at, err)
		}
	}
	for p, want := range map[string]string{"none": filepath.Join(dir, "none"), "al/none": filepath.Join(dir, "sub", "none")} {
		if at, ok, err := fsTargetInRoot(q(p)); !ok || err != nil || at != want {
			t.Errorf("fsTargetInRoot(%s) = %q, %v, %v; want %q, true, nil: a missing name keeps the one lookup", p, at, ok, err, want)
		}
	}
}
