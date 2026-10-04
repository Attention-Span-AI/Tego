// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// walkRaceAgent makes and removes a directory under two parents while a thread of its own renames the first parent's
// ancestor back and forth (out/r/p1 <-> out/r/p2), and while the test moves the mount the second parent is on between
// two other mounts (out/mv/x/m <-> out/mv/y/m). Each loop ends after three seconds or after its count of attempts,
// whichever comes first: each attempt is a ledger line or two, and the count, not the machine's speed, bounds how
// many lines the run writes and the test reads.
const walkRaceAgent = `import os, threading, time

end = time.time() + 3
ROUNDS = 100000

renames = 0

def renamer():
    global renames
    i = 0
    while i < ROUNDS and time.time() < end:
        i += 1
        for a, b in (("out/r/p1", "out/r/p2"), ("out/r/p2", "out/r/p1")):
            renames += 1
            try:
                os.rename(a, b)
            except OSError:
                pass

t = threading.Thread(target=renamer)
t.start()
n = mkdirs = 0
i = 0
while i < ROUNDS and time.time() < end:
    i += 1
    for p in ("out/r/p1/c/d", "out/r/p2/c/d", "out/mv/x/m/d", "out/mv/y/m/d"):
        mkdirs += 1
        try:
            os.mkdir(p)
            os.rmdir(p)
            n += 1
        except OSError:
            pass
t.join()
print("RESULT ops", n, "mkdirs", mkdirs, "renames", renames, flush=True)
`

// TestPlaneRunNamesTrueUnderRenamesAndMountMoves is enforce-plane §2.15's "never a wrong path" under the two races the
// kernel's directory walk guards against: an ancestor renamed while it is walked (each level's d_seq, compared on a
// second pass) and a mount moved while it is crossed (each crossing's parent mount and mountpoint, compared on the
// second pass). In each plane mode, every mkdir and rmdir line of the agent's loop names one of the paths the
// directory could have had, or is the marked dev:ino/name of a walk that could not prove its path, never anything
// else, and some lines are named by path.
func TestPlaneRunNamesTrueUnderRenamesAndMountMoves(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the plane needs root: run as `sudo go test -tags integration,tegobpf` or `make vm-root-test`")
	}
	uid, gid, ok := sudoIDs()
	if !ok {
		t.Skip("a root `tego run` drops the agent to the sudo caller and refuses without SUDO_UID and SUDO_GID")
	}
	if _, err := bpfHash(); err != nil {
		t.Skipf("this test binary carries no BPF objects; the run belongs to the tegobpf suite: %v", err)
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skipf("the agent is a python3 script: %v", err)
	}
	dir := t.TempDir()
	bin := buildPlaneTego(t, dir)
	requireTier(t, bin, "cgroup")
	modes := planeModesHere(t, bin)
	if len(modes) == 0 {
		t.Skip("no plane mode passes doctor's probe here")
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) { walkRaceCell(t, bin, uid, gid, mode) })
	}
}

func walkRaceCell(t *testing.T, bin string, uid, gid int, mode string) {
	tool, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Skipf("the project's binary is a copy of /bin/true: %v", err)
	}
	files := map[string]string{"agent.py": walkRaceAgent, "agent.yaml": dropContract, "bin/tool": string(tool)}
	p := newPlaneProject(t, uid, gid, files, []string{"out/r/p1/c", "out/mv/x", "out/mv/y", "out/secret"}, nil)
	mv := filepath.Join(p.project, "out", "mv")
	x, y := filepath.Join(mv, "x"), filepath.Join(mv, "y")
	// Two mounts, x and y, each with a directory m, and a third mounted on x/m: every mount private, so a move
	// propagates nowhere.
	for _, d := range []string{x, y} {
		if err := unix.Mount("tmpfs", d, "tmpfs", 0, "mode=0777"); err != nil {
			t.Skipf("tmpfs at %s: %v", d, err)
		}
		t.Cleanup(func() { _ = unix.Unmount(d, unix.MNT_DETACH) })
		if err := unix.Mount("", d, "", unix.MS_PRIVATE, ""); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(d, "m"), 0o777); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Mount("tmpfs", filepath.Join(x, "m"), "tmpfs", 0, "mode=0777"); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("", filepath.Join(x, "m"), "", unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{x, y, filepath.Join(x, "m"), filepath.Join(y, "m")} {
		_ = os.Chown(d, uid, gid)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	moves := 0
	wg.Add(1)
	go func() { // the mount on m moves between x and y until the run ends
		defer wg.Done()
		from, to := filepath.Join(x, "m"), filepath.Join(y, "m")
		for {
			select {
			case <-stop:
				return
			default:
			}
			if unix.Mount(from, to, "", unix.MS_MOVE, "") == nil {
				from, to = to, from
				moves++
			}
			time.Sleep(time.Millisecond)
		}
	}()
	t.Cleanup(func() {
		_ = unix.Unmount(filepath.Join(x, "m"), unix.MNT_DETACH)
		_ = unix.Unmount(filepath.Join(y, "m"), unix.MNT_DETACH)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var out bytes.Buffer
	runErr := p.run(ctx, bin, "agent.yaml", mode, &out).Run()
	close(stop)
	wg.Wait()
	t.Logf("tego run (%s): %v, %d mount moves\n%s", mode, runErr, moves, out.String())
	if runErr != nil {
		t.Fatalf("the run did not complete: %v", runErr)
	}
	r := filepath.Join(p.project, "out", "r")
	valid := map[string]bool{
		filepath.Join(r, "p1", "c", "d"): true, filepath.Join(r, "p2", "c", "d"): true,
		filepath.Join(x, "m", "d"): true, filepath.Join(y, "m", "d"): true,
		filepath.Join(r, "p1"): true, filepath.Join(r, "p2"): true,
	}
	// The ledger is read a line at a time, and only the first wrong lines are quoted: the loop writes hundreds of
	// thousands of lines, and neither they nor a failure's quotes of them may outgrow the guest's memory.
	const quoted = 20
	lines, named, marked, wrong := 0, 0, 0, 0
	eachRunEvent(t, p.ledger, func(e map[string]any) {
		lines++
		if e["kind"] != "fs" {
			return
		}
		path := fmt.Sprint(e["path"])
		if !strings.Contains(path, "/out/r/") && !strings.Contains(path, "/out/mv/") && strings.HasPrefix(path, "/") {
			return
		}
		switch {
		case !strings.HasPrefix(path, "/"):
			marked++ // a walk that could not prove its path: the marked identifier
		case valid[path]:
			named++
		default:
			if wrong++; wrong <= quoted {
				t.Errorf("a line names %q, a path the directory never had: %v", path, e)
			}
		}
	})
	if wrong > quoted {
		t.Errorf("%d lines in all name a path the directory never had (the first %d quoted above)", wrong, quoted)
	}
	t.Logf("%d ledger lines, %d of the loop's named by path, %d marked", lines, named, marked)
	if named == 0 {
		t.Error("no line of the loop is named by path")
	}
}
