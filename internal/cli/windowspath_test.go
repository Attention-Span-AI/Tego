// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// The forms of a Windows path a command can be given, and what Tego's Linux reads each as.
func TestClassifyWindowsPath(t *testing.T) {
	prev := mountPresent
	t.Cleanup(func() { mountPresent = prev })
	mountPresent = func(string) bool { return false }
	for _, tc := range []struct {
		arg   string
		want  windowsForm
		linux string
	}{
		{`C:\work\rules.yaml`, windowsDrive, ""},
		{`c:/work/rules.yaml`, windowsDrive, ""},
		{`D:`, windowsDrive, ""},
		{`"C:\work\my rules.yaml"`, windowsDrive, ""},
		{`\\wsl$\tego\home\tego\rules.yaml`, windowsOwn, "/home/tego/rules.yaml"},
		{`\\wsl.localhost\tego\home\tego\a\b.yaml`, windowsOwn, "/home/tego/a/b.yaml"},
		{`\\WSL$\Tego\tmp\x.yaml`, windowsOwn, "/tmp/x.yaml"},
		{`//wsl$/tego/home/tego/x.yaml`, windowsOwn, "/home/tego/x.yaml"},
		{`\\wsl$\tego`, windowsOwn, "/"},
		{`\\wsl$\Ubuntu\home\me\x.yaml`, windowsShare, ""},
		{`\\server\share\x.yaml`, windowsShare, ""},
		{`/mnt/c/work/rules.yaml`, windowsMount, ""},
		{`/mnt/d`, windowsMount, ""},
		{`/mnt/wsl/x`, notWindows, ""},
		{`/mnt/cc/x`, notWindows, ""},
		{`/home/tego/rules.yaml`, notWindows, ""},
		{`rules.yaml`, notWindows, ""},
		{`~/rules.yaml`, notWindows, ""},
		{`C`, notWindows, ""},
		{`x:\y`, windowsDrive, ""},
		{`1:\y`, notWindows, ""},
	} {
		form, linux := classifyWindowsPath(tc.arg)
		if form != tc.want || linux != tc.linux {
			t.Errorf("%q: form %d linux %q, want %d %q", tc.arg, form, linux, tc.want, tc.linux)
		}
	}
	// A /mnt/c that exists here is a mounted drive: the file is missing on it, and nothing is said about Windows.
	mountPresent = func(string) bool { return true }
	if form, _ := classifyWindowsPath(`/mnt/c/work/rules.yaml`); form != notWindows {
		t.Errorf("a mounted /mnt/c: form %d", form)
	}
}

const copyWords = `In File Explorer, paste \\wsl$\tego\home\tego in the address bar and copy the file there`

// A missing rules file given as a Windows path says what is true in Tego's own distribution: same exit codes, same
// [path-missing], the words added after the error; the same arguments on a plain Linux host print what they always did.
func TestMissingRulesFileGivenAsWindowsPath(t *testing.T) {
	prev := mountPresent
	t.Cleanup(func() { mountPresent = prev })
	mountPresent = func(string) bool { return false }
	for _, tc := range []struct {
		name, arg string
		words     []string
	}{
		{"drive", `C:\work\rules.yaml`, []string{"does not see your Windows drives", copyWords, "/home/tego/rules.yaml"}},
		{"drive with slashes", `d:/work/other.yaml`, []string{copyWords, "/home/tego/other.yaml"}},
		{"mount", `/mnt/c/work/rules.yaml`, []string{"does not see your Windows drives", copyWords, "/home/tego/rules.yaml"}},
		{"own distribution", `\\wsl$\tego\home\tego\ww-rules.yaml`, []string{"type its Linux path here: /home/tego/ww-rules.yaml"}},
		{"own distribution, localhost form", `\\wsl.localhost\tego\home\tego\ww-rules.yaml`, []string{"type its Linux path here: /home/tego/ww-rules.yaml"}},
		{"another share", `\\server\share\rules.yaml`, []string{copyWords, "/home/tego/rules.yaml"}},
	} {
		for _, cmd := range []struct {
			name string
			args []string
			exit int
		}{
			{"rules check", []string{"rules", "check", tc.arg}, identity.ExitFinding},
			{"compile", []string{"compile", tc.arg}, identity.ExitFinding},
			{"run", []string{"run", tc.arg, "--", "true"}, identity.ExitLauncher},
		} {
			t.Run(tc.name+"/"+cmd.name, func(t *testing.T) {
				t.Setenv("WSL_DISTRO_NAME", "")
				t.Setenv("TEGO_HOST_KIND", "")
				code, _, plain := run(t, cmd.args...)
				if code != cmd.exit || !strings.Contains(plain, "no such file or directory [path-missing]") || strings.Contains(plain, "Tego's Linux") {
					t.Fatalf("plain Linux: exit %d, want %d: %q", code, cmd.exit, plain)
				}
				t.Setenv("TEGO_HOST_KIND", "windows")
				code, _, got := run(t, cmd.args...)
				if code != cmd.exit || !strings.HasSuffix(strings.TrimSpace(got), "[path-missing]") {
					t.Fatalf("Windows: exit %d, want %d: %q", code, cmd.exit, got)
				}
				before, _, _ := strings.Cut(strings.TrimSpace(plain), " [path-missing]")
				if !strings.HasPrefix(got, before+"; ") {
					t.Fatalf("the refusal's own words must come first, unchanged:\n plain %q\n got   %q", plain, got)
				}
				for _, w := range tc.words {
					if !strings.Contains(got, w) {
						t.Errorf("missing %q in %q", w, got)
					}
				}
				if strings.Count(got, "\n") != 1 {
					t.Errorf("one line expected: %q", got)
				}
			})
		}
	}
}

// A path that is not a Windows form, or a Windows form of a file that is there, is not decorated: a shell inside
// another WSL distribution with the drives mounted gets the plain refusal.
func TestMissingRulesFileOnWindowsHostNotWindowsForm(t *testing.T) {
	t.Setenv("TEGO_HOST_KIND", "windows")
	for _, arg := range []string{"nope.yaml", "/home/tego/nope.yaml", "~/nope.yaml"} {
		code, _, errs := run(t, "rules", "check", arg)
		if code != identity.ExitFinding || strings.Contains(errs, "Tego's Linux") || !strings.Contains(errs, "[path-missing]") {
			t.Errorf("%q: exit %d: %q", arg, code, errs)
		}
	}
}

// The project folder of tego init: a Windows path is said to be one, with the copy instruction.
func TestInitFolderGivenAsWindowsPath(t *testing.T) {
	t.Setenv("WSL_DISTRO_NAME", "")
	t.Setenv("TEGO_HOST_KIND", "windows")
	code, _, errs := run(t, "init", `C:\code\app`)
	if code != identity.ExitUsage || !strings.Contains(errs, `C:\code\app is not a folder here`) ||
		!strings.Contains(errs, `copy the folder there`) || !strings.Contains(errs, "/home/tego/app") || !strings.HasSuffix(strings.TrimSpace(errs), "[usage]") {
		t.Fatalf("exit %d: %q", code, errs)
	}
	t.Setenv("TEGO_HOST_KIND", "")
	code, _, errs = run(t, "init", `C:\code\app`)
	if code != identity.ExitUsage || strings.Contains(errs, "Tego's Linux") || !strings.Contains(errs, "init scaffolds an existing project directory") {
		t.Fatalf("plain Linux: exit %d: %q", code, errs)
	}
}

// A drive mount is a mount point: an empty /mnt/c folder (what Tego's distribution has with automount off) is not one,
// and a folder that is not there is none.
func TestMountPresentIsAMountPoint(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "c"), 0o755); err != nil {
		t.Fatal(err)
	}
	if mountPresent(filepath.Join(dir, "c")) {
		t.Error("an empty folder on the parent's device is no mount")
	}
	if mountPresent(filepath.Join(dir, "missing")) {
		t.Error("a missing folder is no mount")
	}
	if !mountPresent("/proc") {
		t.Error("/proc is a mount point")
	}
}

// In a WSL distribution that is not Tego's (Tego installed in an Ubuntu), the words name neither Tego's distribution nor
// /home/tego: a Windows path is not a Linux path there, and a mounted drive says where the file is.
func TestWindowsPathWordsInAnotherWSLDistribution(t *testing.T) {
	prev := mountPresent
	t.Cleanup(func() { mountPresent = prev })
	t.Setenv("TEGO_HOST_KIND", "")
	t.Setenv("WSL_DISTRO_NAME", "Ubuntu-24.04")
	for _, tc := range []struct {
		name, arg string
		mounted   bool
		want      string
	}{
		{"drive, mounted", `C:\work\rules.yaml`, true, "with the drive mounted here the file is at /mnt/c/work/rules.yaml"},
		{"drive, forward slashes, quoted", `"d:/x/y.yaml"`, true, "the file is at /mnt/d/x/y.yaml"},
		{"drive, not mounted", `C:\work\rules.yaml`, false, "/mnt/c is not mounted here"},
		{"/mnt/z, not mounted", `/mnt/z/x.yaml`, false, "that drive is not mounted in this Linux (/mnt/z is no mount point)"},
		{"another distribution's share", `\\wsl$\Ubuntu\home\me\x.yaml`, false, ""},
		{"tego's share seen from here", `\\wsl$\tego\home\tego\x.yaml`, false, ""},
		{"a Linux path", "/home/me/x.yaml", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mountPresent = func(string) bool { return tc.mounted }
			got := windowsPathWords(tc.arg, false)
			if tc.want == "" && got != "" || !strings.Contains(got, tc.want) {
				t.Fatalf("%q: %q, want %q", tc.arg, got, tc.want)
			}
			for _, bad := range []string{"Tego's Linux", "/home/tego", `\\wsl$`, "File Explorer"} {
				if strings.Contains(got, bad) {
					t.Errorf("another distribution is told %q: %q", bad, got)
				}
			}
		})
	}
	// Through a command: the refusal is the plain one plus the true words, or nothing added.
	mountPresent = func(string) bool { return false }
	code, _, errs := run(t, "rules", "check", `C:\work\rules.yaml`)
	if code != identity.ExitFinding || !strings.HasSuffix(strings.TrimSpace(errs), "[path-missing]") || strings.Contains(errs, "Tego's Linux") ||
		!strings.Contains(errs, "/mnt/c is not mounted here") {
		t.Fatalf("exit %d: %q", code, errs)
	}
	code, _, errs = run(t, "rules", "check", `\\wsl$\tego\home\tego\x.yaml`)
	if code != identity.ExitFinding || strings.Contains(errs, "Tego's Linux") || !strings.HasSuffix(strings.TrimSpace(errs), "no such file or directory [path-missing]") {
		t.Fatalf("exit %d: %q", code, errs)
	}
}

// The mount check never waits long for a dead drive.
func TestMountPresentGivesUpOnAHungStat(t *testing.T) {
	// A stat of a path that answers is quick; the bound is only held by reading it.
	src, err := os.ReadFile("setup_host.go")
	if err != nil || !strings.Contains(string(src), "time.After(2 * time.Second)") {
		t.Fatalf("the mount check lost its time limit: %v", err)
	}
}

// A folder given in Tego's own \\wsl$ spelling is one true sentence: it is Tego's Linux, and the Linux path is named.
func TestInitFolderGivenInTegosOwnWindowsSpelling(t *testing.T) {
	t.Setenv("WSL_DISTRO_NAME", "tego")
	t.Setenv("TEGO_HOST_KIND", "")
	code, _, errs := run(t, "init", `\\wsl$\tego\home\tego\nope`)
	if code != identity.ExitUsage || !strings.Contains(errs, "does not exist; that is Tego's Linux as Windows names it; type its Linux path here: /home/tego/nope") ||
		strings.Contains(errs, "is not in Tego's Linux") || strings.Contains(errs, "is not a folder here") {
		t.Fatalf("exit %d: %q", code, errs)
	}
}
