// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
)

var (
	bpfBinOnce sync.Once
	bpfBinPath string
	bpfBinErr  error
)

// tegoBPFBinary is tegoBinary with the BPF objects, for a root run at tier cgroup (the guest's go shim serves the
// prebuilt tego.tegobpf.testhooks).
func tegoBPFBinary(t *testing.T) string {
	t.Helper()
	bpfBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "tego-bpfbin-")
		if err != nil {
			bpfBinErr = err
			return
		}
		bpfBinPath = filepath.Join(dir, "tego")
		cmd := exec.Command("go", "build", "-tags", "tegobpf,tegotesthooks", "-trimpath", "-o", bpfBinPath, "github.com/attention-span-ai/tego/cmd/tego")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			bpfBinErr = fmt.Errorf("go build: %v: %s", err, out)
		}
	})
	if bpfBinErr != nil {
		t.Fatalf("cannot build tego with the BPF objects: %v", bpfBinErr)
	}
	return bpfBinPath
}

// etcGroup is the group database ensureGroup edits.
const etcGroup = "/etc/group"

// disposableHost names the throwaway machine this process runs on, or is "" on any other. test/vm/root-suites.sh
// sets TEGO_DISPOSABLE_HOST in its KVM guests and, under VM_HOST=sudo, on a GitHub Actions runner (or when its
// caller set it); GitHub Actions sets GITHUB_ACTIONS=true on its runners for a `sudo -E go test` there.
func disposableHost() string {
	if v := os.Getenv("TEGO_DISPOSABLE_HOST"); v != "" {
		return v
	}
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		return "github-actions"
	}
	return ""
}

// ensureGroup makes sure /etc/group has a group of this name with no members and returns its gid. A group of the
// name that has members is refused: making /run/tego root:<name> 1770 would let them write root's host state
// while the test runs. A line it adds is taken out again when the test ends. Both edits replace the file
// atomically (replaceEtcGroup), and the removal takes out only that line, so an edit another process made
// meanwhile is kept; when nothing else changed the file, it is restored byte for byte.
func ensureGroup(t *testing.T, name string) int {
	t.Helper()
	data, err := os.ReadFile(etcGroup)
	if err != nil {
		t.Fatal(err)
	}
	used := map[int]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 3 {
			continue
		}
		gid, _ := strconv.Atoi(f[2])
		if f[0] == name {
			if len(f) > 3 && strings.TrimSpace(f[3]) != "" {
				t.Fatalf("%s has a group %q with members (%s); this test would hand them /run/tego for its duration, so it does not run here",
					etcGroup, name, f[3])
			}
			return gid
		}
		used[gid] = true
	}
	gid := 4242
	for used[gid] {
		gid++
	}
	line := fmt.Sprintf("%s:x:%d:\n", name, gid)
	written := string(data)
	if written != "" && !strings.HasSuffix(written, "\n") {
		written += "\n"
	}
	written += line
	if err := replaceEtcGroup([]byte(written)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cur, err := os.ReadFile(etcGroup)
		if err != nil {
			t.Errorf("cannot read %s to take out %q: %v", etcGroup, line, err)
			return
		}
		restore := data
		if string(cur) != written {
			i := strings.Index("\n"+string(cur), "\n"+line)
			if i < 0 {
				t.Errorf("%s no longer holds the line %q this test added; left as it is", etcGroup, line)
				return
			}
			restore = []byte(string(cur[:i]) + string(cur[i+len(line):]))
		}
		if err := replaceEtcGroup(restore); err != nil {
			t.Errorf("cannot take %q out of %s: %v", line, etcGroup, err)
		}
	})
	return gid
}

// replaceEtcGroup replaces /etc/group with data the way vigr and the shadow tools do: a new file in /etc with the
// old one's mode and owner, synced, then renamed over it, so a test killed at any point leaves the whole old file
// or the whole new one, never a truncated database.
func replaceEtcGroup(data []byte) error {
	var st unix.Stat_t
	if err := unix.Stat(etcGroup, &st); err != nil {
		return err
	}
	dir := filepath.Dir(etcGroup)
	f, err := os.CreateTemp(dir, ".group.tego-test-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Chown(int(st.Uid), int(st.Gid))
	}
	if err == nil {
		err = f.Chmod(os.FileMode(st.Mode & 0o777))
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, etcGroup)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace %s: %w", etcGroup, err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// hostStateNames lists /run/tego.
func hostStateNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(hoststate.Path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// TestRootLauncherRefusesGroupHostState is ADR 0042 (3)(b): a root launcher accepts /run/tego only as root 0700.
// The root:tego 1770 form ADR 0034 provisioned (a hand-installed tmpfiles line) is refused with ErrHostState and
// the one-line fix, and the launcher creates nothing in it. The tego group is added first, so that before the
// change the 1770 directory was accepted and this test failed. With 0700 restored the same run passes. It needs
// root and the invoking user sudo names, and it changes the host's own /run/tego and /etc/group for its duration
// (hoststate.Path is a constant the detached helpers' argv carries), so it runs only on a disposable host: the KVM
// guests of test/vm/root-suites.sh and CI's runner (disposableHost), never on a developer's machine through
// VM_HOST=sudo, where it skips and says why. A killed run there leaves at worst /run/tego 1770 and the added
// group line; /etc/group itself is never left truncated.
func TestRootLauncherRefusesGroupHostState(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: /run/tego is root's")
	}
	if disposableHost() == "" {
		t.Skip("changes this host's /run/tego and /etc/group: runs only where TEGO_DISPOSABLE_HOST is set (test/vm/root-suites.sh's KVM guests) or GITHUB_ACTIONS=true")
	}
	if _, _, ok := agentUID(t); !ok {
		t.Skip("needs SUDO_UID naming the invoking user, as `sudo go test` and test/vm/root-suites.sh give")
	}
	requireLandlock(t)
	bin := tegoBPFBinary(t)
	agentReaches(t, bin)
	c := newPrivpathCase(t, -1, -1)
	agentReaches(t, c.out)
	agentOwns(t, c.out)
	contract := filepath.Join(c.dir, "agent.yaml")
	group := ensureGroup(t, "tego")

	if err := unix.Mkdir(hoststate.Path, 0o700); err != nil && err != unix.EEXIST {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Lchown(hoststate.Path, 0, 0)
		_ = unix.Chmod(hoststate.Path, 0o700)
	})
	before := hostStateNames(t)
	if err := os.Lchown(hoststate.Path, 0, group); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chmod(hoststate.Path, 0o1770); err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(hoststate.Path, &st); err != nil || st.Mode&0o7777 != 0o1770 || int(st.Gid) != group {
		t.Fatalf("could not make %s root:tego 1770: %+v %v", hoststate.Path, st, err)
	}

	code, out := c.exec(t, exec.Command(bin, "run", "--tier", "cgroup", contract, "--", "/bin/sh", "-c", "touch out/ran"))
	if code != 125 || !strings.Contains(out, hoststate.Fix) || c.ran() {
		t.Errorf("a root launcher with a 1770 root:tego %s: exit %d, ran %v; want 125 with the fix %q:\n%s",
			hoststate.Path, code, c.ran(), hoststate.Fix, out)
	}
	if after := hostStateNames(t); !slices.Equal(before, after) {
		t.Errorf("the refused launcher created state in %s: %v, was %v", hoststate.Path, after, before)
	}

	if err := os.Lchown(hoststate.Path, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chmod(hoststate.Path, 0o700); err != nil {
		t.Fatal(err)
	}
	code, out = c.exec(t, exec.Command(bin, "run", "--tier", "cgroup", contract, "--", "/bin/sh", "-c", "touch out/ran"))
	if code != 0 || !c.ran() {
		t.Errorf("a root launcher with a root 0700 %s: exit %d, ran %v; want 0:\n%s", hoststate.Path, code, c.ran(), out)
	}
}
