// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// Separate execs give every Go thread the same security credentials. Peers stay
// alive until the viewer has read their labels; no recycled PID is compared.
func init() {
	if len(os.Args) < 3 {
		return
	}
	switch os.Args[1] {
	case "--open-label-selinux-peer", "--open-label-smack-peer":
		if len(os.Args) != 4 {
			os.Exit(2)
		}
		runtime.LockOSThread()
		if os.Args[1] == "--open-label-selinux-peer" {
			if os.Args[3] != "default" {
				if err := os.WriteFile("/proc/thread-self/attr/fscreate", []byte(os.Args[3]), 0); err != nil {
					fmt.Println("SETUP", err)
					os.Exit(2)
				}
			}
		} else {
			if err := os.WriteFile("/proc/thread-self/attr/smack/current", []byte("tego_subject"), 0); err != nil {
				fmt.Println("SETUP", err)
				os.Exit(2)
			}
			// CAP_MAC_OVERRIDE would hide the process-rule denial in a root test.
			// Only this locked thread performs the native open. Clear its
			// capabilities directly; Go's all-thread setuid rendezvous can require
			// inter-label signals while other runtime threads retain their old label.
			caps := [2]unix.CapUserData{}
			hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
			if err := unix.Capset(&hdr, &caps[0]); err != nil {
				fmt.Println("SETUP caps", err)
				os.Exit(2)
			}
			if os.Args[3] == "restricted" {
				if err := os.WriteFile("/sys/fs/smackfs/load-self2", []byte("tego_subject tego_object -"), 0); err != nil {
					fmt.Println("SETUP", err)
					os.Exit(2)
				}
			}

		}
		flags := unix.O_RDONLY
		if os.Args[1] == "--open-label-selinux-peer" {
			flags = unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL
		}
		fd, err := unix.Open(os.Args[2], flags|unix.O_CLOEXEC, 0o600)
		if err == nil {
			_ = unix.Close(fd)
		}
		fmt.Printf("OPEN %v\n", err)
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		os.Exit(0)

	case "--open-label-peer":
		fd, err := unix.Open(os.Args[2], unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err == nil {
			_ = unix.Close(fd)
		}
		fmt.Printf("OPEN %v\n", err)
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		os.Exit(0)
	case "--open-label-viewer":
		if len(os.Args) != 4 {
			os.Exit(2)
		}
		task, e1 := strconv.Atoi(os.Args[2])
		opener, e2 := strconv.Atoi(os.Args[3])
		if e1 != nil || e2 != nil {
			os.Exit(2)
		}
		a, e1 := os.ReadFile(fmt.Sprintf("/proc/%d/attr/apparmor/current", task))
		b, e2 := os.ReadFile(fmt.Sprintf("/proc/%d/attr/apparmor/current", opener))
		fmt.Printf("VISIBLE %q %q\n", a, b)
		if e1 != nil || e2 != nil || string(a) != string(b) || !strings.Contains(string(a), "local") {
			os.Exit(2)
		}
		if err := checkOpenLabel(task, opener, unix.O_RDONLY, readOpenLabelFile, sys.LSMListModules); err == nil {
			fmt.Println("UNSAFE: equal visible components authorized different ancestor profiles")
			os.Exit(1)
		} else {
			fmt.Printf("REFUSED %v\n", err)
		}
		if err := (sysKernel{assumeAppArmorRoot: true}).CheckOpenLabel(task, opener, unix.O_RDONLY); err == nil {
			fmt.Println("UNSAFE: assertion overrode known child namespace depth")
			os.Exit(1)
		}
		os.Exit(0)
	}
}

func requireOpenLabelLSM(t *testing.T, lsm string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root only: installs disposable LSM policy")
	}
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(","+strings.TrimSpace(string(b))+",", ","+lsm+",") {
		t.Skip(lsm + " is not active")
	}
}

// Run by the disposable Docker harness, with its actual docker-default profile.
// Securityfs must really be unreadable; the active module syscall is still needed.
func TestOpenLabelDockerAppArmor(t *testing.T) {
	if os.Getenv("TEGO_TEST_DOCKER_LABELS") != "1" {
		t.Skip("dedicated Docker container with docker-default required")
	}
	label, err := os.ReadFile("/proc/self/attr/apparmor/current")
	if err != nil || string(label) != "docker-default (enforce)\n" {
		t.Fatalf("actual Docker label %q: %v", label, err)
	}
	if b, err := os.ReadFile("/sys/kernel/security/apparmor/.ns_level"); err == nil {
		t.Fatalf("namespace depth unexpectedly readable: %q", b)
	}
	if _, err := sys.LSMListModules(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("native read"), 0o600); err != nil {
		t.Fatal(err)
	}
	peer := startOpenLabelPeer(t, "--open-label-peer", path, "unused", "OPEN <nil>")
	for _, flags := range []int{unix.O_RDONLY, unix.O_WRONLY | unix.O_TRUNC, unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL} {
		err := (sysKernel{}).CheckOpenLabel(os.Getpid(), peer.Process.Pid, flags)
		if err == nil {
			t.Fatalf("default refusal: %v", err)
		}
		if err := (sysKernel{assumeAppArmorRoot: true}).CheckOpenLabel(os.Getpid(), peer.Process.Pid, flags); err != nil {
			t.Fatalf("explicit assertion: %v", err)
		}
		if !strings.Contains(err.Error(), "fs.apparmor_assume_root_namespace: true") {
			t.Fatalf("default refusal lacks fix: %v", err)
		}
	}
}

func TestOpenLabelAppArmorHiddenAncestors(t *testing.T) {
	requireOpenLabelLSM(t, "apparmor")
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	ns := fmt.Sprintf("tego_label_%d", os.Getpid())
	a, b := ns+"_denied", ns+"_allowed"
	policy := filepath.Join(dir, "policy")
	text := fmt.Sprintf(`profile %s flags=(attach_disconnected) {
 /** rwmlkix,
 capability,
 signal,
 ptrace,
 network,
 change_profile,
 deny %q r,
}
profile %s flags=(attach_disconnected) {
 /** rwmlkix,
 capability,
 signal,
 ptrace,
 network,
 change_profile,
}
profile :%s://local flags=(attach_disconnected) {
 /** rwmlkix,
 capability,
 signal,
 ptrace,
 network,
 change_profile,
}
`, a, secret, b, ns)
	if err := os.WriteFile(policy, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("apparmor_parser", "-a", policy).CombinedOutput(); err != nil {
		t.Fatalf("load: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("apparmor_parser", "-R", policy).CombinedOutput(); err != nil {
			t.Errorf("remove: %v\n%s", err, out)
		}
	})
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := func(ancestor string, args ...string) *exec.Cmd {
		// Positional arguments keep policy names and paths out of shell source.
		argv := []string{"-c", `printf 'changeprofile %s' "$1" > /proc/self/attr/apparmor/current || exit 2
printf 'stack :%s://local' "$2" > /proc/self/attr/apparmor/current || exit 2
shift 2
exec "$@"`, "label", ancestor, ns, self}
		return exec.Command("/bin/sh", append(argv, args...)...)
	}
	peer := func(ancestor, want string) *exec.Cmd {
		cmd := command(ancestor, "--open-label-peer", secret)
		in, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = in.Close()
			if err := cmd.Wait(); err != nil {
				t.Errorf("peer: %v", err)
			}
		})
		scan := bufio.NewScanner(out)
		if !scan.Scan() || scan.Text() != want {
			t.Fatalf("native open: %q, want %q", scan.Text(), want)
		}
		full, err := os.ReadFile(fmt.Sprintf("/proc/%d/attr/apparmor/current", cmd.Process.Pid))
		if err != nil || !strings.Contains(string(full), ancestor) || !strings.Contains(string(full), ":"+ns+":local") {
			t.Fatalf("root view %q: %v", full, err)
		}
		t.Logf("root view: %s", full)
		return cmd
	}
	task := peer(a, "OPEN permission denied")
	opener := peer(b, "OPEN <nil>")
	out, err := command(b, "--open-label-viewer", strconv.Itoa(task.Process.Pid), strconv.Itoa(opener.Process.Pid)).CombinedOutput()
	t.Logf("child namespace: %s", out)
	if err != nil {
		t.Fatalf("hidden ancestor check: %v", err)
	}
}

func TestOpenLabelWithoutSecurityFSList(t *testing.T) {
	requireOpenLabelLSM(t, "apparmor")
	if _, err := sys.LSMListModules(); err != nil {
		t.Skip("masked-list control requires lsm_list_modules: " + err.Error())
	}
	// A container can mask the LSM list while leaving AppArmor namespace facts
	// visible. Discover the complete active list independently of securityfs.
	read := func(p string) ([]byte, error) {
		if p == "/sys/kernel/security/lsm" {
			return nil, unix.EACCES
		}
		return readOpenLabelFile(p)
	}
	if err := checkOpenLabel(os.Getpid(), os.Getpid(), unix.O_RDONLY, read, sys.LSMListModules); err != nil {
		t.Fatalf("matching container labels: %v", err)
	}
	hidden := func(p string) ([]byte, error) {
		if strings.HasPrefix(p, "/sys/kernel/security/") {
			return nil, unix.EACCES
		}
		return readOpenLabelFile(p)
	}
	if err := checkOpenLabel(os.Getpid(), os.Getpid(), unix.O_RDONLY, hidden, sys.LSMListModules); err == nil || !strings.Contains(err.Error(), "namespace depth") {
		t.Fatalf("hidden namespace depth must refuse: %v", err)
	}
}

// startOpenLabelPeer retains the task while its independent authority facts are
// queried. A native denial is a required control, not inferred from policy text.
func startOpenLabelPeer(t *testing.T, mode, path, context, want string) *exec.Cmd {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, mode, path, context)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = in.Close()
		if err := cmd.Wait(); err != nil {
			t.Errorf("peer: %v", err)
		}
	})
	scan := bufio.NewScanner(out)
	if !scan.Scan() || scan.Text() != want {
		t.Fatalf("native open=%q want %q", scan.Text(), want)
	}
	return cmd
}

func TestOpenLabelSELinuxCreation(t *testing.T) {
	requireOpenLabelLSM(t, "selinux")
	current, err := os.ReadFile("/proc/self/attr/current")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSuffix(string(current), "\x00") != "user_u:base_r:base_t" {
		t.Skip("needs the disposable SEC08 SELinux policy guest")
	}
	enforcing, err := os.ReadFile("/sys/fs/selinux/enforce")
	if err != nil || string(enforcing) != "1" {
		t.Fatalf("SELinux must enforce: %q %v", enforcing, err)
	}
	dir := t.TempDir()
	task := startOpenLabelPeer(t, "--open-label-selinux-peer", filepath.Join(dir, "restricted"), "user_u:object_r:restricted_t", "OPEN permission denied")
	opener := startOpenLabelPeer(t, "--open-label-selinux-peer", filepath.Join(dir, "default"), "default", "OPEN <nil>")
	a, b := task.Process.Pid, opener.Process.Pid
	for _, pid := range []int{a, b} {
		value, err := os.ReadFile(fmt.Sprintf("/proc/%d/attr/current", pid))
		if err != nil || string(value) != string(current) {
			t.Fatalf("current=%q %v", value, err)
		}
	}
	if err := checkOpenLabel(a, b, unix.O_CREAT|unix.O_WRONLY, readOpenLabelFile, sys.LSMListModules); err == nil {
		t.Error("different fscreate contexts authorized creation")
	} else {
		t.Logf("create refused: %v", err)
	}
	if err := checkOpenLabel(a, b, unix.O_RDONLY, readOpenLabelFile, sys.LSMListModules); err != nil {
		t.Errorf("fscreate must not prevent a read: %v", err)
	}
	if err := checkOpenLabel(a, a, unix.O_CREAT|unix.O_WRONLY, readOpenLabelFile, sys.LSMListModules); err != nil {
		t.Errorf("equal explicit creation contexts: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "restricted")); !os.IsNotExist(err) {
		t.Errorf("restricted leaf exists: %v", err)
	}
}

func TestOpenLabelSmackProcessRules(t *testing.T) {
	requireOpenLabelLSM(t, "smack")
	// This test runs only in a disposable Smack guest. Put the fixture directly
	// beneath its traversable temp root; never chmod ancestors of t.TempDir.
	dir, err := os.MkdirTemp(os.TempDir(), "tego-smack-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(secret, "security.SMACK64", []byte("tego_object"), 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/sys/fs/smackfs/load2", []byte("tego_subject tego_object rwx\ntego_subject _ rwxat\n_ tego_subject rwxat"), 0); err != nil {
		t.Fatal(err)
	}
	task := startOpenLabelPeer(t, "--open-label-smack-peer", secret, "restricted", "OPEN permission denied")
	opener := startOpenLabelPeer(t, "--open-label-smack-peer", secret, "default", "OPEN <nil>")
	for _, pid := range []int{task.Process.Pid, opener.Process.Pid} {
		value, err := os.ReadFile(fmt.Sprintf("/proc/%d/attr/smack/current", pid))
		if err != nil || string(value) != "tego_subject" {
			t.Fatalf("current=%q %v", value, err)
		}
	}
	if err := checkOpenLabel(task.Process.Pid, opener.Process.Pid, unix.O_RDONLY, readOpenLabelFile, sys.LSMListModules); err == nil {
		t.Error("equal Smack labels authorized an open with different process rules")
	} else {
		t.Logf("Smack refused: %v", err)
	}
}
