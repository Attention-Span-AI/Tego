// SPDX-License-Identifier: Apache-2.0

package adopt

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

// fakeStatLine is a /proc/<pid>/stat line with the given state, num_threads and start time (fields 3, 20 and 22).
func fakeStatLine(pid int, state byte, threads int) string {
	return fakeStatLineAt(pid, state, threads, 100)
}

func fakeStatLineAt(pid int, state byte, threads int, start uint64) string {
	f := make([]string, 50)
	for i := range f {
		f[i] = "0"
	}
	f[0], f[1], f[2], f[3] = fmt.Sprint(pid), "(agent)", string(state), "1"
	f[19], f[21] = fmt.Sprint(threads), fmt.Sprint(start)
	return strings.Join(f, " ") + "\n"
}

// leaderExitedProc writes a /proc tree under a temporary root in which process 42's leader has exited while its
// thread 43 runs, as a guest of 6.17 showed it: the leader's stat says Z and counts two tasks, its smaps and fd
// directory are empty, and /proc/43 answers for the process (its program, status, cgroup and memory).
func leaderExitedProc(t *testing.T, smaps string) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	status := func(pid int) string {
		return fmt.Sprintf("Name:\tagent\nTgid:\t%d\nPid:\t%d\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n", 42, pid)
	}
	write("42/stat", fakeStatLineAt(42, 'Z', 2, 100))
	write("42/status", status(42))
	write("42/smaps", "")
	write("42/cmdline", "")
	write("42/cgroup", "0::/old\n")
	write("42/task/42/stat", fakeStatLineAt(42, 'Z', 2, 100))
	write("42/task/43/stat", fakeStatLineAt(43, 'S', 2, 101))
	write("43/stat", fakeStatLineAt(43, 'S', 2, 101))
	write("43/status", status(43))
	write("43/smaps", smaps)
	write("43/cmdline", "agent\x00--serve\x00")
	write("43/cgroup", "0::/moved\n")
	if err := os.MkdirAll(filepath.Join(root, "42", "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/proc/self/exe", filepath.Join(root, "43", "exe")); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestMapsReadsAProcessWhoseLeaderExitedThroughItsThread: the exited leader has let go of the memory its threads
// share, so its own smaps lists nothing; Maps reads the process's mappings through a thread that runs, so a file the
// process maps shared and writable is not missed.
func TestMapsReadsAProcessWhoseLeaderExitedThroughItsThread(t *testing.T) {
	smaps := "7f00-7f10 rw-s 00000000 08:01 77 /home/u/secret.db\nVmFlags: rd wr sh mr mw me ms\n"
	fs := NewFS(leaderExitedProc(t, smaps))
	fs.internal = func() map[devID]bool { return nil }
	fs.mounts = nil
	ms, err := fs.Maps(42)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].Path != "/home/u/secret.db" || !ms[0].SharedWritable {
		t.Errorf("Maps(42) = %+v, want the shared writable mapping of /home/u/secret.db its thread 43 shows", ms)
	}
	cg, err := CgroupOf(fs, 42)
	if err != nil || cg != "/moved" {
		t.Errorf("CgroupOf(42) = %q, %v; want /moved, its live thread's (the exited leader stays in /old)", cg, err)
	}
	p, err := Identify(fs, 42)
	if err != nil {
		t.Fatal(err)
	}
	if p.Cgroup != "/moved" || len(p.Argv) != 2 || p.Argv[0] != "agent" || p.Start != 100 || p.UID[0] != 1000 {
		t.Errorf("Identify(42) = %+v, want the thread's cgroup and argv under the leader's identity", p)
	}
	// The group has ended: the leader is a zombie that counts itself only, and nothing answers for it.
	if err := os.WriteFile(filepath.Join(fs.root, "42", "stat"), []byte(fakeStatLineAt(42, 'Z', 1, 100)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Maps(42); err == nil {
		t.Error("Maps of a zombie whose group has ended: no error, want ErrGone")
	}
}

// TestMapsNamesAProcessWhoseLeaderExitedThroughItsThread: the mount each mapping is held through is read from the
// map_files of the thread the mappings were read from; the exited leader's lists nothing, so read there every
// mapping of the process would be unnamed.
func TestMapsNamesAProcessWhoseLeaderExitedThroughItsThread(t *testing.T) {
	held := filepath.Join(t.TempDir(), "held.db")
	if err := os.WriteFile(held, make([]byte, 8192), 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := statHeld(held)
	if err != nil {
		t.Fatal(err)
	}
	if !id.mntKnown {
		t.Skip("this kernel's statx gives no mount id (STATX_MNT_ID, Linux 5.8)")
	}
	root := leaderExitedProc(t, fmt.Sprintf("7f00-7f10 rw-s 00000000 08:01 %d %s\nVmFlags: rd wr sh mr mw me ms\n", id.ino, held))
	for _, d := range []string{"42/map_files", "43/map_files"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(held, filepath.Join(root, "43", "map_files", "7f00-7f10")); err != nil {
		t.Fatal(err)
	}
	fs := NewFS(root)
	fs.internal = func() map[devID]bool { return nil }
	fs.mounts = func() (mountTable, error) { return mountTable{id.mnt: {dev: devID{8, 1}, root: "/", at: "/"}}, nil }
	ms, err := fs.Maps(42)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].Path != held || ms[0].Unnamed || !ms[0].SharedWritable {
		t.Errorf("Maps(42) = %+v, want %s named and shared writable, through thread 43's map_files", ms, held)
	}
}

// TestALeaderExitedProcessIsReadOnlyThroughAThreadOfIt: the thread a process whose leader exited is read through
// must be one of that process when it is chosen and still the same task once the reads are done; a thread id is
// reused by any process once its thread is released, and a read through it would describe that process (mutants M6
// and M7).
func TestALeaderExitedProcessIsReadOnlyThroughAThreadOfIt(t *testing.T) {
	t.Run("a task of another process", func(t *testing.T) {
		root := leaderExitedProc(t, "")
		other := "Name:\tother\nTgid:\t99\nPid:\t43\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n"
		if err := os.WriteFile(filepath.Join(root, "43", "status"), []byte(other), 0o644); err != nil {
			t.Fatal(err)
		}
		if p, err := Identify(NewFS(root), 42); !errors.Is(err, ErrGone) {
			t.Errorf("Identify(42) through a task whose status names process 99 = %+v, %v; want ErrGone", p, err)
		}
		// Another task of process 42 runs: it is the one read through, not the foreign one listed first.
		for rel, body := range map[string]string{
			"42/task/44/stat": fakeStatLineAt(44, 'S', 3, 102),
			"44/stat":         fakeStatLineAt(44, 'S', 3, 102),
			"44/status":       "Name:\tagent\nTgid:\t42\nPid:\t44\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n",
			"44/cmdline":      "agent\x00",
			"44/cgroup":       "0::/thread44\n",
		} {
			if err := os.MkdirAll(filepath.Dir(filepath.Join(root, rel)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, rel), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if p, err := Identify(NewFS(root), 42); err != nil || p.Cgroup != "/thread44" {
			t.Errorf("Identify(42) with its own task 44 listed after a foreign one = %+v, %v; want read through 44", p, err)
		}
	})
	t.Run("the task reused while it was read", func(t *testing.T) {
		m := leaderExitedTree()
		m.statHook = func(m *machine, pid int) {
			m.mu.Lock()
			defer m.mu.Unlock()
			if pid == 2031 && m.statCalls[2031] == 1 {
				m.procs[2031].start += 100 // thread 2031 exited after it was chosen, and its id names a new task
			}
		}
		if p, err := Identify(m, 203); !errors.Is(err, ErrGone) {
			t.Errorf("Identify(203) through a thread reused mid-read = %+v, %v; want ErrGone", p, err)
		}
	})
}

// TestIdentifyOfAReleasedLineIsNotGone: a stat line with process group -1 (fs/proc/array.c's do_task_stat could not
// take the task's sighand lock; internal/platform/proc's releasedStatLine gives the source lines) is written for a
// process reaped during the read and for a live one whose old leader an execve from another thread released. A
// file that keeps it through every read is a stat Identify cannot read, never ErrGone: as ErrGone, a live process
// mid-exec read as gone, and a boundary adoption counted nothing it could not read (GapAdoptionUnread).
func TestIdentifyOfAReleasedLineIsNotGone(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "842314"), 0o755); err != nil {
		t.Fatal(err)
	}
	released := "842314 (exe) Z 0 -1 -1 0 -1 4228108 40251 0 0 0 4 27 0 0 20 0 0 0 82606841" + strings.Repeat(" 0", 12) +
		" 1 0 0 -1 6" + strings.Repeat(" 0", 13) + "\n"
	if err := os.WriteFile(filepath.Join(root, "842314", "stat"), []byte(released), 0o644); err != nil {
		t.Fatal(err)
	}
	if p, err := Identify(NewFS(root), 842314); !errors.Is(err, proc.ErrStat) || errors.Is(err, ErrGone) {
		t.Fatalf("Identify(released) = %+v, %v; want proc.ErrStat and not ErrGone", p, err)
	}
}
