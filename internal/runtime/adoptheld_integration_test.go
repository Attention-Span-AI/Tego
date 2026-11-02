// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"bufio"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestIntegrationAdoptCountsAFileHeldThroughAnotherMount: what a boundary adoption counts of the files the agent held
// across a rule when it was adopted (adoption-open-descriptors) or could not read (adoption-descriptors-unread), for
// a key under a deny_read directory held read-only, by a descriptor and by a read mapping, through a mount other than
// the one tego's namespace names it by. The decision plane decides by the dentries (bpf/decide.bpf.c
// tego_walk_step), so it refuses a fresh open of the key through each of them; the count must not take the name
// /proc gives the file for a path the rows can be asked about when it is not one:
//   - through a detached clone of the key's parent (open_tree OPEN_TREE_CLONE), and through a bind of it that was then
//     lazily unmounted, /proc names the key relative to the detached mount's root ("/.ssh/id_ed25519"), which is no
//     path of tego's namespace: the process is counted unread, never taken as holding nothing across a rule;
//   - through a bind of the parent that is still mounted elsewhere, the name is a path, but the rows asked by it alone
//     allow what the plane refuses: the key is counted, by its name through the other mount of its filesystem.
//
// The key is held by a child (TestHeldFileHolderHelper) whose only other files are pipes and its own executable, so
// each row's counts are the key's alone: unread counts processes, and the test binary itself may hold a file that is
// already unread (the guest's stdio is the initramfs's /dev/console, which devtmpfs was mounted over since).
// It mounts and clones mounts, so it needs root: root-suites.sh runs it in a KVM guest.
func TestIntegrationAdoptCountsAFileHeldThroughAnotherMount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: bind mounts, lazily unmounts and clones mounts (root-suites.sh)")
	}
	base := t.TempDir()
	home := filepath.Join(base, "home")
	ssh := filepath.Join(home, ".ssh")
	key := filepath.Join(ssh, "id_ed25519")
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatal(err)
	}
	// home is a mount of its own, so a clone of it and a bind of it are mounts of one filesystem the guest's / is not.
	if err := unix.Mount("tmpfs", home, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "size=1m"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount(home, unix.MNT_DETACH) })
	if err := os.Mkdir(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	rt := &agent.RuleTable{Contract: &agent.Contract{Name: "held"}, Record: agent.RecordFull,
		FS: []agent.FSRule{{Path: ssh, Resolved: ssh, Kind: agent.FSDenyRead, Raw: ssh}}}
	fs := adopt.NewFS("")
	// count adopts pid alone under a boundary of rt and returns what openDescriptors found it holding.
	count := func(t *testing.T, pid int) heldFiles {
		t.Helper()
		p, err := adopt.Identify(fs, pid)
		if err != nil {
			t.Fatal(err)
		}
		a := &adoption{r: &runner{rt: rt, log: slog.New(slog.NewTextHandler(io.Discard, nil))}, spec: AdoptSpec{Boundary: true},
			env: adopt.Env{Proc: fs}, moved: adopt.MoveResult{Moved: []adopt.Process{p}}}
		return a.openDescriptors()
	}
	// unnamed lists, for a failure's message, what of pid's files the count could not ask the rows about.
	unnamed := func(pid int) []string {
		var out []string
		fds, _ := fs.FDs(pid)
		for _, fd := range fds {
			if fd.Unnamed {
				out = append(out, "fd "+fd.Target)
			}
		}
		ms, _ := fs.Maps(pid)
		for _, m := range ms {
			if m.Unnamed {
				out = append(out, "map "+m.Path)
			}
		}
		return out
	}
	idle := startHolder(t, nil, false)
	if got := count(t, idle); got.files != 0 || got.unread != 0 {
		t.Fatalf("the holder holding nothing: %d held across a rule, %d unread (unnamed: %q); want 0 and 0, or no row "+
			"below says anything", got.files, got.unread, unnamed(idle))
	}

	clone := func(t *testing.T) int {
		t.Helper()
		fd, err := unix.OpenTree(unix.AT_FDCWD, home, unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC)
		if err != nil {
			t.Fatalf("open_tree %s: %v", home, err)
		}
		t.Cleanup(func() { _ = unix.Close(fd) })
		return fd
	}
	// bind mounts home at a new directory and returns a descriptor of it; lazy unmounts the bind at once.
	bind := func(t *testing.T, lazy bool) int {
		t.Helper()
		at := filepath.Join(t.TempDir(), "bind")
		if err := os.Mkdir(at, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mount(home, at, "", unix.MS_BIND, ""); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Open(at, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unix.Close(fd) })
		if lazy {
			if err := unix.Unmount(at, unix.MNT_DETACH); err != nil {
				t.Fatal(err)
			}
		} else {
			t.Cleanup(func() { _ = unix.Unmount(at, unix.MNT_DETACH) })
		}
		return fd
	}
	for _, c := range []struct {
		name          string
		dir           func(t *testing.T) int
		files, unread int
	}{
		{"direct", func(*testing.T) int { return unix.AT_FDCWD }, 1, 0},
		{"detached clone", clone, 0, 1},
		{"lazily unmounted bind", func(t *testing.T) int { return bind(t, true) }, 0, 1},
		{"mounted bind", func(t *testing.T) int { return bind(t, false) }, 1, 0},
	} {
		for _, mapping := range []bool{false, true} {
			name := c.name + "/descriptor"
			if mapping {
				name = c.name + "/mapping"
			}
			t.Run(name, func(t *testing.T) {
				dir := c.dir(t)
				rel := ".ssh/id_ed25519"
				if dir == unix.AT_FDCWD {
					rel = key
				}
				fd, err := unix.Openat(dir, rel, unix.O_RDONLY|unix.O_CLOEXEC, 0)
				if err != nil {
					t.Fatalf("open %s: %v", rel, err)
				}
				f := os.NewFile(uintptr(fd), rel)
				pid := startHolder(t, f, mapping)
				_ = f.Close() // the holder has its own descriptor, or, for a mapping, closed it once mapped
				got := count(t, pid)
				if got.files != c.files || got.unread != c.unread {
					t.Errorf("the key held read-only through %s: %d held across a rule and %d unread (unnamed: %q), want "+
						"%d and %d (the plane refuses a read of it through every mount)", name, got.files, got.unread,
						unnamed(pid), c.files, c.unread)
				}
			})
		}
	}
}

// TestIntegrationAdoptCountsAHardLinkOfAKeyedFile: the decision plane keys a file entry's row on the file's inode
// (bpf/decide.bpf.c tego_walk_step looks up the object's own inode first), so it refuses a read of a deny_read file,
// or a write of a deny_write target, by every name the inode has: a hard link the agent made in its workspace before
// it was adopted included (docs/p0/enforce-plane.md, "another name of a keyed file"). /proc names the held file by the
// link, which no rule names, so the count must ask the rows by the inode too: the link
// held by a descriptor, and as root by a read mapping alone (map_files, which only root may follow), is one file held
// across a rule, never none. A file of the workspace held the same way is not.
func TestIntegrationAdoptCountsAHardLinkOfAKeyedFile(t *testing.T) {
	base := t.TempDir()
	netrc := filepath.Join(base, ".netrc")
	work := filepath.Join(base, "work")
	link := filepath.Join(work, "n")
	plain := filepath.Join(work, "plain")
	if err := os.Mkdir(work, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{netrc, plain} {
		if err := os.WriteFile(p, make([]byte, 4096), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(netrc, link); err != nil {
		t.Fatal(err)
	}
	rt := &agent.RuleTable{Contract: &agent.Contract{Name: "held"}, Record: agent.RecordFull,
		FS: []agent.FSRule{{Path: netrc, Resolved: netrc, Kind: agent.FSDenyRead, Raw: netrc},
			{Path: work, Resolved: work, Kind: agent.FSWrite, Raw: work}}}
	fs := adopt.NewFS("")
	// Unprivileged, the holder's own mappings (its executable) cannot be followed through map_files, so it is counted
	// unread whatever it holds: the descriptor rows still say whether the link is counted.
	hows, unread := []bool{false}, 1
	if os.Geteuid() == 0 {
		hows, unread = append(hows, true), 0
	} else {
		t.Log("the mapping rows need root to follow /proc/<pid>/map_files: root-suites.sh runs them")
	}
	for _, c := range []struct {
		path  string
		files int
	}{{link, 1}, {plain, 0}} {
		for _, mapping := range hows {
			f, err := os.Open(c.path)
			if err != nil {
				t.Fatal(err)
			}
			pid := startHolder(t, f, mapping)
			_ = f.Close()
			p, err := adopt.Identify(fs, pid)
			if err != nil {
				t.Fatal(err)
			}
			a := &adoption{r: &runner{rt: rt, log: slog.New(slog.NewTextHandler(io.Discard, nil))}, spec: AdoptSpec{Boundary: true},
				env: adopt.Env{Proc: fs}, moved: adopt.MoveResult{Moved: []adopt.Process{p}}}
			if got := a.openDescriptors(); got.files != c.files || got.unread != unread {
				t.Errorf("%s held read-only (mapping %v): %d held across a rule, %d unread; want %d and %d (the plane "+
					"refuses a read of %s by every name of its inode)", c.path, mapping, got.files, got.unread, c.files,
					unread, netrc)
			}
		}
	}
	// The link at a path longer than PATH_MAX in the workspace: /proc cannot name the held file (readlink of its fd
	// link is refused, ENAMETOOLONG), so the count cannot ask the rows about it, and its process is counted unread,
	// never taken as holding nothing.
	deep := deepDir(t, work)
	if err := unix.Linkat(unix.AT_FDCWD, netrc, deep, "n", 0); err != nil {
		t.Fatal(err)
	}
	for _, mapping := range hows {
		fd, err := unix.Openat(deep, "n", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		f := os.NewFile(uintptr(fd), "n")
		pid := startHolder(t, f, mapping)
		_ = f.Close()
		p, err := adopt.Identify(fs, pid)
		if err != nil {
			t.Fatal(err)
		}
		a := &adoption{r: &runner{rt: rt, log: slog.New(slog.NewTextHandler(io.Discard, nil))}, spec: AdoptSpec{Boundary: true},
			env: adopt.Env{Proc: fs}, moved: adopt.MoveResult{Moved: []adopt.Process{p}}}
		if got := a.openDescriptors(); got.files != 0 || got.unread != 1 {
			t.Errorf("a link of %s at a path past PATH_MAX held read-only (mapping %v): %d held across a rule, %d unread; "+
				"want 0 and 1 (no name of it can be asked about)", netrc, mapping, got.files, got.unread)
		}
	}
}

// deepDir makes a chain of directories under dir whose path is longer than PATH_MAX (4096 bytes) and returns an
// O_PATH descriptor of the last, closed with the test.
func deepDir(t *testing.T, dir string) int {
	t.Helper()
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	comp := strings.Repeat("d", 200)
	for range 25 { // 25 components of 201 bytes
		if err := unix.Mkdirat(fd, comp, 0o755); err != nil {
			t.Fatal(err)
		}
		next, err := unix.Openat(fd, comp, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if err != nil {
			t.Fatal(err)
		}
		fd = next
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

// startHolder starts the helper (TestHeldFileHolderHelper) holding f (nil: nothing) as a descriptor or, with mapping,
// by a read mapping alone, and returns its pid once it holds it; the helper ends with the test.
func startHolder(t *testing.T, f *os.File, mapping bool) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHeldFileHolderHelper$", "-test.timeout=60s")
	how := "nothing"
	if f != nil {
		cmd.ExtraFiles = []*os.File{f}
		how = "descriptor"
		if mapping {
			how = "mapping"
		}
	}
	cmd.Env = append(os.Environ(), "TEGO_TEST_HOLD_FILE="+how)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "held\n" {
		t.Fatalf("the holder: %q %v", line, err)
	}
	return cmd.Process.Pid
}

// TestHeldFileHolderHelper is the process TestIntegrationAdoptCountsAFileHeldThroughAnotherMount counts: with
// TEGO_TEST_HOLD_FILE=descriptor it keeps descriptor 3, with mapping it maps descriptor 3 shared read-only and closes
// it, with nothing it holds nothing; it says "held" on stdout and waits for stdin to close.
func TestHeldFileHolderHelper(t *testing.T) {
	how := os.Getenv("TEGO_TEST_HOLD_FILE")
	if how == "" {
		t.Skip("helper process only")
	}
	if how == "mapping" {
		m, err := syscall.Mmap(3, 0, 4096, syscall.PROT_READ, syscall.MAP_SHARED)
		if err != nil {
			t.Fatal(err)
		}
		defer syscall.Munmap(m) //nolint:errcheck // the process ends next
		if err := syscall.Close(3); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stdout.WriteString("held\n"); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
}
