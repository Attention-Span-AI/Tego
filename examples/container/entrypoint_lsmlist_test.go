// SPDX-License-Identifier: Apache-2.0

package container

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/lsmlist"
)

const bootID = "5f1c0f1e-0f0c-4a64-8e4b-1f4f7e0a9c11"

// listRig is a stand-in for what the entrypoint reads and writes: the kernel's own list file (absent unless a test makes
// it), the directory the list is written to, the boot id and the place securityfs would be mounted.
type listRig struct {
	dir, out, kernel, secfs, boot string
}

func newListRig(t *testing.T) listRig {
	t.Helper()
	d := t.TempDir()
	r := listRig{dir: d, out: filepath.Join(d, "run", "tego-lsm", "lsm-list"), kernel: filepath.Join(d, "sys-lsm"),
		secfs: filepath.Join(d, "run", "tego-lsm", ".securityfs"), boot: filepath.Join(d, "boot_id")}
	if err := os.WriteFile(r.boot, []byte(bootID+"\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	return r
}

// run calls hand_in_lsm_list; mount and umount are the test's own (the default mount refuses, as a container without
// CAP_SYS_ADMIN does).
func (r listRig) run(t *testing.T, mode, prelude string) (string, int) {
	t.Helper()
	_, stderr, code := lib(t, r.dir, prelude+`
hand_in_lsm_list "$OUT" "$KERNEL" "$SECFS" "$BOOT" `+mode,
		"OUT="+r.out, "KERNEL="+r.kernel, "SECFS="+r.secfs, "BOOT="+r.boot)
	return stderr, code
}

func (r listRig) wrote(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(r.out)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestEntrypointHandsInTheListFromTheKernelsFile: where the kernel's file can be read, the entrypoint writes the list in
// the format tego reads (the same bytes lsmlist parses for this boot), mode 0644, in a 0755 directory, handed to root, and
// leaves no temporary file behind.
func TestEntrypointHandsInTheListFromTheKernelsFile(t *testing.T) {
	r := newListRig(t)
	if err := os.WriteFile(r.kernel, []byte("lockdown,capability,landlock,yama,apparmor,bpf\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	stderr, code := r.run(t, "auto", "")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	got := r.wrote(t)
	list, why := lsmlist.ParseHandedIn([]byte(got), bootID)
	if why != "" || lsmlist.ListProblem(list) != "" || list != "lockdown,capability,landlock,yama,apparmor,bpf" {
		t.Fatalf("what the entrypoint wrote is not the list tego reads: %q (list %q, %s / %s)", got, list, why, lsmlist.ListProblem(list))
	}
	if !strings.Contains(stderr, "security-module list handed in at "+r.out) {
		t.Errorf("stderr: %s", stderr)
	}
	if fi, err := os.Stat(r.out); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("file mode %v, %v; want 0644", fi, err)
	}
	if fi, err := os.Stat(filepath.Dir(r.out)); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("directory mode %v, %v; want 0755", fi, err)
	}
	ents, _ := os.ReadDir(filepath.Dir(r.out))
	if len(ents) != 1 {
		t.Errorf("the directory holds %d entries after the write, want the list alone: %v", len(ents), ents)
	}
	calls := readFile(t, filepath.Join(r.dir, "calls"))
	if n := strings.Count(calls, "chown 0:0 -- "); n != 2 {
		t.Errorf("handed to root %d times, want the directory and the file:\n%s", n, calls)
	}
}

// TestEntrypointReadsSecurityfsWhereTheKernelsFileIsNotThere: a container's own /sys has no securityfs, so the entrypoint
// mounts it read-only on a directory of its own, reads the list, unmounts and removes the directory.
func TestEntrypointReadsSecurityfsWhereTheKernelsFileIsNotThere(t *testing.T) {
	r := newListRig(t)
	stderr, code := r.run(t, "auto", `
mount() { printf 'mount %s\n' "$*" >>"$calls"; printf 'capability,landlock,apparmor\n' >"${*: -1}/lsm"; }
umount() { printf 'umount %s\n' "$*" >>"$calls"; rm -f -- "$2/lsm"; }`)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	list, why := lsmlist.ParseHandedIn([]byte(r.wrote(t)), bootID)
	if why != "" || list != "capability,landlock,apparmor" {
		t.Fatalf("wrote %q: list %q, %s", r.wrote(t), list, why)
	}
	calls := readFile(t, filepath.Join(r.dir, "calls"))
	if !strings.Contains(calls, "mount -t securityfs -o ro,nosuid,nodev,noexec securityfs "+r.secfs) || !strings.Contains(calls, "umount -- "+r.secfs) {
		t.Errorf("calls:\n%s", calls)
	}
	if _, err := os.Stat(r.secfs); !os.IsNotExist(err) {
		t.Errorf("the securityfs mount directory is left behind: %v", err)
	}
	if !strings.Contains(stderr, "read from securityfs mounted read-only at") {
		t.Errorf("stderr: %s", stderr)
	}
}

// TestEntrypointHandsInNothingItCannotRead: with no way to read the list the entrypoint says so and why, starts anyway
// under auto, fails the container under yes, and removes a list left from an earlier start, so a stale one is not offered.
func TestEntrypointHandsInNothingItCannotRead(t *testing.T) {
	stale := staleList
	for _, tc := range []struct {
		name, mode, prelude string
		kernel              string // written as the kernel's file when not empty
		boot                string // replaces the boot id file when not "-"
		wantExit            int
		want                string
	}{
		{name: "securityfs cannot be mounted", mode: "auto", boot: "-", want: "securityfs cannot be mounted (it needs CAP_SYS_ADMIN"},
		{name: "yes fails the container", mode: "yes", boot: "-", wantExit: 1, want: "cannot be mounted"},
		{name: "mounted but no lsm file", mode: "auto", boot: "-", prelude: `mount() { return 0; }; umount() { return 0; }`, want: "mounted but its lsm file could not be read"},
		{name: "a file that is not a list", mode: "auto", boot: "-", kernel: "AppArmor\n", want: "is not a list the kernel prints"},
		{name: "a list without capability", mode: "yes", boot: "-", kernel: "landlock,yama\n", wantExit: 1, want: "is not a list the kernel prints"},
		{name: "a name with a space", mode: "auto", boot: "-", kernel: "capability, apparmor\n", want: "is not a list the kernel prints"},
		{name: "no boot id", mode: "auto", boot: "", kernel: "capability,yama\n", want: "could not be tied to this boot"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newListRig(t)
			if tc.kernel != "" {
				if err := os.WriteFile(r.kernel, []byte(tc.kernel), 0o444); err != nil {
					t.Fatal(err)
				}
			}
			if tc.boot != "-" {
				if tc.boot == "" {
					r.boot = filepath.Join(r.dir, "no-boot-id")
				} else if err := os.WriteFile(r.boot, []byte(tc.boot), 0o444); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.MkdirAll(filepath.Dir(r.out), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(r.out, []byte(stale), 0o644); err != nil {
				t.Fatal(err)
			}
			stderr, code := r.run(t, tc.mode, tc.prelude)
			if code != tc.wantExit {
				t.Errorf("exit %d, want %d\n%s", code, tc.wantExit, stderr)
			}
			if !strings.Contains(stderr, "no security-module list handed in") || !strings.Contains(stderr, tc.want) {
				t.Errorf("stderr lacks %q:\n%s", tc.want, stderr)
			}
			if !strings.Contains(stderr, "held file opens are refused until it is") && !strings.Contains(stderr, "not a list the kernel prints") && !strings.Contains(stderr, "tied to this boot") {
				t.Errorf("stderr does not say what the container loses:\n%s", stderr)
			}
			if got := r.wrote(t); got != "" {
				t.Errorf("a list was left at %s: %q", r.out, got)
			}
		})
	}
}

// staleList is a list file as an earlier start would have left it.
const staleList = "tego-lsm-list 1\nboot_id 00000000-0000-0000-0000-000000000000\nlsm capability\n"

// TestEntrypointLsmListModes: no leaves the file alone; any other word but auto and yes is refused with exit 2.
func TestEntrypointLsmListModes(t *testing.T) {
	r := newListRig(t)
	if err := os.WriteFile(r.kernel, []byte("capability\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if _, code := r.run(t, "no", ""); code != 0 || r.wrote(t) != "" {
		t.Errorf("TEGO_LSM_LIST=no: exit %d, wrote %q", code, r.wrote(t))
	}
	stderr, code := r.run(t, "sometimes", "")
	if code != 2 || !strings.Contains(stderr, "TEGO_LSM_LIST=sometimes: want auto, yes or no") {
		t.Errorf("a bad mode: exit %d: %s", code, stderr)
	}
}

// TestImageConfigNamesTheFileTheEntrypointWrites: the machine config of the image names the path the entrypoint writes by
// default, so the two cannot drift apart.
func TestImageConfigNamesTheFileTheEntrypointWrites(t *testing.T) {
	cfg := readFile(t, "config.yaml")
	ep := readFile(t, entrypoint)
	if !strings.Contains(cfg, "lsm:\n  list_file: /run/tego-lsm/lsm-list\n") {
		t.Errorf("config.yaml does not name /run/tego-lsm/lsm-list as lsm.list_file:\n%s", cfg)
	}
	if !strings.Contains(ep, `${TEGO_LSM_LIST_FILE:-/run/tego-lsm/lsm-list}`) {
		t.Errorf("the entrypoint's default path is not /run/tego-lsm/lsm-list")
	}
}

// TestListIsNotKeptInTheHostStateDirectory: /run/tego is the host state directory, which tego opens only when it is root's
// and mode 0700 (internal/runtime/hoststate), and the entrypoint makes whatever directory holds the list mode 0755. So
// neither the list, its temporary file nor the place securityfs is mounted for a moment may be in /run/tego or below it:
// a root tego in the same image would lose its rootmark, the uprobe library locks and the cgroup backend's state. The
// list has a directory of its own, /run/tego-lsm.
func TestListIsNotKeptInTheHostStateDirectory(t *testing.T) {
	for _, f := range []string{entrypoint, "config.yaml", "compose.yaml", "README.md"} {
		for i, line := range strings.Split(readFile(t, f), "\n") {
			for rest := line; ; {
				k := strings.Index(rest, "/run/tego")
				if k < 0 {
					break
				}
				rest = rest[k+len("/run/tego"):]
				if rest == "" || strings.ContainsRune("-_", rune(rest[0])) {
					continue // /run/tego-lsm, /run/tego-tomoyo: a directory of its own
				}
				t.Errorf("%s:%d names /run/tego%s: the host state directory is not a place for the list", f, i+1, rest)
			}
		}
	}
	ep := readFile(t, entrypoint)
	for _, want := range []string{"/run/tego-lsm/lsm-list", "/run/tego-lsm/.securityfs"} {
		if !strings.Contains(ep, want) {
			t.Errorf("the entrypoint does not use %s", want)
		}
	}
}
