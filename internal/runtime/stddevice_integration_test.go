// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// stdDevicesProbe is the agent's whole job: open each place for writing the way a shell redirect does and say what the
// kernel answered. $1 is the case's directory, which holds root-made look-alikes of /dev/null and /dev/zero (character
// devices with their numbers, mode 0666, on a mount of their own that opens device nodes: see stdDevicesNodes) and a link
// to another file, all in folders no write entry reaches; every place is one the agent's uid may open for writing by
// file mode, so a refusal is the run's.
const stdDevicesProbe = `d=$1
t() {
	if e=$( (: >"$2") 2>&1 ); then echo "RESULT $1 ok"; else
		case $e in *"Permission denied"*) echo "RESULT $1 denied" ;; *) echo "RESULT $1 error:$e" ;; esac
	fi
}
t dev-null /dev/null
t dev-zero /dev/zero
t dev-full /dev/full
t dev-random /dev/random
t dev-urandom /dev/urandom
if e=$( (: <>/dev/null) 2>&1 ); then echo "RESULT dev-null-rw ok"; else echo "RESULT dev-null-rw error:$e"; fi
t link-to-null "$d/ro/tonull"
t out-file "$d/out/file"
t lookalike-null "$d/nodes/null"
t lookalike-zero "$d/nodes/zero"
t link-to-other-file "$d/ro/lnk"
t outside-new-file "$d/other/new"
t shm-new-file /dev/shm/tego-stddevices
`

// stdDevicesWant is what each place must answer under a run of the product with no entry for the devices.
var stdDevicesWant = map[string]string{
	"dev-null": "ok", "dev-zero": "ok", "dev-full": "ok", "dev-random": "ok", "dev-urandom": "ok", "dev-null-rw": "ok",
	"link-to-null": "ok", "out-file": "ok",
	"lookalike-null": "denied", "lookalike-zero": "denied", "link-to-other-file": "denied", "outside-new-file": "denied",
	"shm-new-file": "denied",
}

// stdDevicesNodes makes dir a mount of its own (a tmpfs, root's, mode 0755) that opens device nodes, for the look-alikes.
// A look-alike has to be a node the agent's uid could open by file mode, or its refusal under tego shows nothing; the
// kernel refuses every open of a device node on a nodev mount (EACCES, whatever the mode), and the temporary folder
// can be on one: the KVM guests' own init (test/vm/guest-init.sh) mounts /tmp, /dev/shm and /run nosuid,nodev, and
// systemd's tmp.mount does the same on many distributions, so no folder is picked by name here. A mount made here has
// no nodev whatever the machine's own mounts say, and is checked to have none. The mount, and every node on it, goes
// when the test ends, however it ends.
func stdDevicesNodes(t *testing.T, dir string) {
	t.Helper()
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", dir, "tmpfs", unix.MS_NOSUID, "mode=0755"); err != nil {
		t.Fatalf("mount a tmpfs at %s for the device look-alikes: %v", dir, err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(dir, 0); err != nil {
			_ = unix.Unmount(dir, unix.MNT_DETACH)
		}
	})
	if ok, err := mountOpensDevices(dir); err != nil || !ok {
		t.Fatalf("the tmpfs at %s does not open device nodes (nodev: %v, error %v): the look-alikes would be refused by the kernel before tego", dir, !ok, err)
	}
}

// stdDevicesCase is a case with the probe, the look-alikes and the contract written, owned by the agent's uid.
func stdDevicesCase(t *testing.T, uid, gid int, extraFS string) *privpathCase {
	t.Helper()
	c := newPrivpathCase(t, uid, gid)
	// Every folder is opened up by chmod, not by the mode asked of mkdir: a root test under umask 077 makes 0700, and the
	// agent's uid could not pass through it.
	for _, d := range []string{"ro", "other"} {
		p := filepath.Join(c.dir, d)
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The look-alikes are root's: a character device with /dev/null's numbers, and with /dev/zero's, on a mount of
	// their own in a folder the contract does not name; and a link to a file in another folder the contract does not name.
	stdDevicesNodes(t, filepath.Join(c.dir, "nodes"))
	for name, dev := range map[string]int{"null": int(unix.Mkdev(1, 3)), "zero": int(unix.Mkdev(1, 5))} {
		p := filepath.Join(c.dir, "nodes", name)
		if err := unix.Mknod(p, unix.S_IFCHR|0o666, dev); err != nil {
			t.Fatalf("mknod %s: %v", p, err)
		}
		if err := os.Chmod(p, 0o666); err != nil {
			t.Fatal(err)
		}
	}
	other := filepath.Join(c.dir, "other", "file")
	if err := os.WriteFile(other, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(other, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(c.dir, "other"), 0o777); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{"lnk": other, "tonull": "/dev/null"} {
		if err := os.Symlink(target, filepath.Join(c.dir, "ro", link)); err != nil {
			t.Fatal(err)
		}
	}
	probe := filepath.Join(c.dir, "devs.sh")
	if err := os.WriteFile(probe, []byte(stdDevicesProbe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(probe, 0o755); err != nil { // root's file, read by the agent's uid whatever the umask
		t.Fatal(err)
	}
	contract := fmt.Sprintf(`version: 0
name: stddevices
command: ["/bin/sh", "./devs.sh", %q]
fs:
  write: ["./out/"]
%sexec:
  allow: ["/bin/sh"]
env:
  pass: ["PATH"]
record: full
`, c.dir, extraFS)
	if err := os.WriteFile(filepath.Join(c.dir, "agent.yaml"), []byte(contract), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(c.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return c
}

func parseResults(out string) map[string]string {
	got := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.SplitN(strings.TrimSpace(line), " ", 3)
		if len(f) == 3 && f[0] == "RESULT" {
			got[f[1]] = f[2]
		}
	}
	return got
}

// stdDevicesControl runs the probe as the agent's own uid outside any run: every place must answer ok, so a refusal
// under tego is tego's, never file mode's, and the look-alikes and the link are writable by that uid.
func stdDevicesControl(t *testing.T, c *privpathCase, uid, gid int) {
	t.Helper()
	// The probe makes a file in /dev/shm, which a failing test must not leave there.
	t.Cleanup(func() { _ = os.Remove("/dev/shm/tego-stddevices") })
	cmd := asUser(exec.Command("/bin/sh", filepath.Join(c.dir, "devs.sh"), c.dir), uid, gid, -1)
	cmd.Dir = c.dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the control probe without tego: %v\n%s", err, out)
	}
	var refused []string
	for name, got := range parseResults(string(out)) {
		if got != "ok" {
			refused = append(refused, name+" = "+got)
		}
	}
	sort.Strings(refused)
	if len(refused) > 0 {
		t.Fatalf("control (no tego, the agent's own uid): %s, want ok: the case's files are not writable by file mode, so a refusal under tego would prove nothing\n%s",
			strings.Join(refused, ", "), out)
	}
	if n := len(parseResults(string(out))); n != len(stdDevicesWant) {
		t.Fatalf("control answered %d places, want %d\n%s", n, len(stdDevicesWant), out)
	}
	t.Logf("the control probe without tego: all %d places answered ok to uid %d, so the refusals below are the run's", len(stdDevicesWant), uid)
	_ = os.Remove("/dev/shm/tego-stddevices")
	_ = os.Remove(filepath.Join(c.dir, "out", "file"))
	_ = os.Remove(filepath.Join(c.dir, "other", "new"))
}

// runStdDevices runs the case's agent at tier, as root (the root tiers) or as the user with a delegated cgroup
// (landlock), and returns what the agent saw.
func runStdDevices(t *testing.T, bin, tier string, c *privpathCase, uid, gid int) (map[string]string, string) {
	t.Helper()
	contract := filepath.Join(c.dir, "agent.yaml")
	var code int
	var out string
	if tier == "landlock" {
		code, out = c.exec(t, asUser(exec.Command(bin, "run", "--tier", tier, contract), uid, gid, userLeaf(t, uid, gid)))
	} else {
		code, out = c.exec(t, exec.Command(bin, "run", "--tier", tier, contract))
	}
	if code != 0 {
		t.Fatalf("tego run --tier %s: exit %d:\n%s", tier, code, out)
	}
	return parseResults(out), out
}

// deviceLines reads the run's ledger and returns each fs line that names one of the five devices as "path verdict rule".
func deviceLines(t *testing.T, root string) []string {
	t.Helper()
	dirs := runDirs(t, root)
	if len(dirs) != 1 {
		t.Fatalf("%d runs under %s, want 1", len(dirs), root)
	}
	f, err := os.Open(filepath.Join(dirs[0], ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<22)
	for sc.Scan() {
		var e struct {
			Kind    string `json:"kind"`
			Path    string `json:"path"`
			Verdict string `json:"verdict"`
			Rule    string `json:"rule"`
		}
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.Kind != "fs" {
			continue
		}
		for _, d := range agent.StandardDevices() {
			if e.Path == d.Path {
				out = append(out, e.Path+" "+e.Verdict+" "+e.Rule)
			}
		}
	}
	return out
}

// checkStdDevices is one tier's proof: with no entry for the devices, each opens for writing; a look-alike made with
// mknod, a link to another file and everything else outside the write entry is refused; the record names the grant.
func checkStdDevices(t *testing.T, bin, tier string, uid, gid int) {
	t.Helper()
	// The agent's uid launches the binary at tier landlock, and a root launcher starts its child stage from it: its folder
	// (MkdirTemp's 0700) must be one that uid can search.
	agentReaches(t, bin)
	c := stdDevicesCase(t, uid, gid, "")
	stdDevicesControl(t, c, uid, gid)
	got, out := runStdDevices(t, bin, tier, c, uid, gid)
	for name, want := range stdDevicesWant {
		if got[name] != want {
			t.Errorf("tier %s: %s = %q, want %q", tier, name, got[name], want)
		}
	}
	if len(got) != len(stdDevicesWant) {
		t.Errorf("tier %s: the agent answered %d places, want %d:\n%s", tier, len(got), len(stdDevicesWant), out)
	}
	lines := deviceLines(t, c.root)
	for _, l := range lines {
		path, rest, _ := strings.Cut(l, " ")
		verdict, rule, _ := strings.Cut(rest, " ")
		if verdict == "allow" && rule != agent.BuiltinStandardDevices {
			t.Errorf("tier %s: %q: an allowed open of %s names the rule %q, want %q", tier, l, path, rule, agent.BuiltinStandardDevices)
		}
		if verdict == "refused" {
			t.Errorf("tier %s: %q: a standard device was refused", tier, l)
		}
	}
	t.Logf("tier %s recorded %d lines for the devices: %v", tier, len(lines), lines)

	// An explicit entry wins: with deny_write on /dev/null that one device is refused and the others are not.
	d := stdDevicesCase(t, uid, gid, "  deny_write: [\"/dev/null\"]\n")
	got, out = runStdDevices(t, bin, tier, d, uid, gid)
	if got["dev-null"] != "denied" || got["dev-null-rw"] == "ok" || got["link-to-null"] != "denied" {
		t.Errorf("tier %s: with fs.deny_write [/dev/null], dev-null = %q, dev-null-rw = %q, link-to-null = %q, want denied, an error and denied:\n%s",
			tier, got["dev-null"], got["dev-null-rw"], got["link-to-null"], out)
	}
	for _, name := range []string{"dev-zero", "dev-full", "dev-random", "dev-urandom"} {
		if got[name] != "ok" {
			t.Errorf("tier %s: with fs.deny_write [/dev/null], %s = %q, want ok", tier, name, got[name])
		}
	}

	// A host whose file at the name is not the device: a regular file bound over /dev/null. The run is compiled
	// against what is there, and the name alone grants nothing. (Another one of the five devices bound there is that
	// device: the grant is on the inode and holds under every name, so it is not a refusal case.) Only in a guest of
	// our own: on a CI runner the host's /dev/null would be another file for the seconds the run takes.
	if os.Getenv("TEGO_DISPOSABLE_HOST") != "kvm" {
		t.Logf("tier %s: the bind-over-/dev/null cases run only in a KVM guest (TEGO_DISPOSABLE_HOST=kvm), not on %q", tier, disposableHost())
		return
	}
	src := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(src, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(src, 0o666); err != nil {
		t.Fatal(err)
	}
	agentReaches(t, src)
	if err := unix.Mount(src, "/dev/null", "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("bind %s over /dev/null: %v", src, err)
	}
	t.Cleanup(func() { _ = unix.Unmount("/dev/null", unix.MNT_DETACH) })
	e := stdDevicesCase(t, uid, gid, "")
	got, out = runStdDevices(t, bin, tier, e, uid, gid)
	if err := unix.Unmount("/dev/null", unix.MNT_DETACH); err != nil {
		t.Fatalf("unbind /dev/null: %v", err)
	}
	if got["dev-null"] != "denied" || got["dev-null-rw"] == "ok" || got["link-to-null"] != "denied" {
		t.Errorf("tier %s: with a regular file bound over /dev/null, dev-null = %q, dev-null-rw = %q, link-to-null = %q, want the name refused:\n%s",
			tier, got["dev-null"], got["dev-null-rw"], got["link-to-null"], out)
	}
	for _, name := range []string{"dev-zero", "dev-full", "dev-random", "dev-urandom"} {
		if got[name] != "ok" {
			t.Errorf("tier %s: with a regular file bound over /dev/null, %s = %q, want ok", tier, name, got[name])
		}
	}
	t.Logf("tier %s: the bind-over-/dev/null cases ran", tier)
}

// TestIntegrationStandardDevicesLandlock is ADR 0158 at tier landlock, from the user's own launcher: each of the five
// devices opens for writing under a contract with no entry for them; a character device with /dev/null's numbers made
// with mknod, and a link to another file, are refused (they are writable by file mode: the control run shows it);
// /dev/shm is refused; an fs.deny_write on /dev/null still refuses it; and with a regular file bound at
// /dev/null's name the name grants nothing. It needs root for mknod and mount, and the invoking user for the
// run.
func TestIntegrationStandardDevicesLandlock(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: mknod and a bind mount over /dev/null")
	}
	if disposableHost() == "" {
		t.Skip("makes device nodes and a run at a root tier: runs only where TEGO_DISPOSABLE_HOST is set (test/vm/root-suites.sh's KVM guests) or GITHUB_ACTIONS=true")
	}
	uid, gid, ok := agentUID(t)
	if !ok {
		t.Skip("needs SUDO_UID naming the invoking user, as `sudo go test` and test/vm/root-suites.sh give")
	}
	requireLandlock(t)
	checkStdDevices(t, tegoBinary(t), "landlock", uid, gid)
}

// TestRootStandardDevices is the same at the root tiers, from a root launcher with the agent dropped to the invoking
// user: tier cgroup, and tier bpflsm where doctor says the machine has it.
func TestRootStandardDevices(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: tiers cgroup and bpflsm")
	}
	if disposableHost() == "" {
		t.Skip("makes device nodes and a run at a root tier: runs only where TEGO_DISPOSABLE_HOST is set (test/vm/root-suites.sh's KVM guests) or GITHUB_ACTIONS=true")
	}
	uid, gid, ok := agentUID(t)
	if !ok {
		t.Skip("needs SUDO_UID naming the invoking user, as `sudo go test` and test/vm/root-suites.sh give")
	}
	bin := tegoBPFBinary(t)
	for _, tier := range []string{"cgroup", "bpflsm"} {
		t.Run(tier, func(t *testing.T) {
			probe := newPrivpathCase(t, uid, gid)
			cmd := exec.Command(bin, "doctor", "--require", tier)
			cmd.Dir = probe.dir
			cmd.Env = probe.env
			testutil.RequireTier(t, cmd, tier)
			checkStdDevices(t, bin, tier, uid, gid)
		})
	}
}
