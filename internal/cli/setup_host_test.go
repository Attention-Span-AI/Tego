// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func TestSetupHostCompatibility(t *testing.T) {
	t.Setenv("WSL_DISTRO_NAME", "")
	for _, tc := range []struct {
		kind, legacy string
		want         guideHost
	}{
		{"", "", hostLinux}, {"", "1", hostMac}, {"mac", "", hostMac},
		{"windows", "", hostWindows}, {"windows", "1", hostWindows}, {"future", "", hostLinux},
	} {
		t.Run(tc.kind+tc.legacy, func(t *testing.T) {
			t.Setenv("TEGO_HOST_KIND", tc.kind)
			t.Setenv("TEGO_ON_MAC", tc.legacy)
			if got := setupHost(); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSetupHostFromWSLWithoutInterop(t *testing.T) {
	t.Setenv("TEGO_HOST_KIND", "")
	t.Setenv("TEGO_ON_MAC", "")
	t.Setenv("WSL_INTEROP", "")
	for _, distro := range []string{"", "tego", "Ubuntu-24.04"} {
		t.Setenv("WSL_DISTRO_NAME", distro)
		want := hostLinux
		if distro != "" {
			want = hostWindows
		}
		if got := setupHost(); got != want {
			t.Errorf("distribution %q without interop: got %q, want %q", distro, got, want)
		}
	}
}

func TestWindowsProjectPaths(t *testing.T) {
	home := t.TempDir()
	for _, path := range []string{`C:\work\app`, `d:/work/app`, `\\server\share\app`, `//server/share`} {
		if _, err := projectPath(path, home, hostWindows); err == nil || !strings.Contains(err.Error(), "that folder is on Windows") || !strings.Contains(err.Error(), `\\wsl$\tego`) {
			t.Errorf("%q: %v", path, err)
		}
	}
	if got, err := projectPath(home+"/app", home, hostWindows); err == nil || got != "" || !strings.Contains(err.Error(), `\\wsl$\tego`) {
		t.Fatalf("missing path: %q, %v", got, err)
	}
	if err := os.Mkdir(filepath.Join(home, "app"), 0755); err != nil {
		t.Fatal(err)
	}
	if got, err := projectPath("~/app", home, hostWindows); err != nil || got != filepath.Join(home, "app") {
		t.Fatalf("Linux path: %q, %v", got, err)
	}
}

func TestWindowsPathsAlreadyInLinux(t *testing.T) {
	home := t.TempDir()
	app := filepath.Join(home, "app")
	if err := os.Mkdir(app, 0755); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{`\\wsl$\tego` + strings.ReplaceAll(app, "/", `\`), `"\\wsl.localhost\tego` + strings.ReplaceAll(app, "/", `\`) + `"`, "/" + app} {
		got, err := projectPath(value, home, hostWindows)
		if err != nil || got != app {
			t.Errorf("%q: got %q, %v", value, got, err)
		}
	}
	quoted := filepath.Join(home, `app"`)
	if err := os.Mkdir(quoted, 0755); err != nil {
		t.Fatal(err)
	}
	if got, err := projectPath(`~/app"`, home, hostWindows); err != nil || got != quoted {
		t.Fatalf("unmatched quote selected another project: %q, %v; want %q", got, err, quoted)
	}
	for _, value := range []string{"a:b/app", "x:1", "foo:bar"} {
		if windowsProjectPath(value) {
			t.Errorf("Linux relative path classified as Windows: %q", value)
		}
	}
}

func TestGuideHostReadyGoldens(t *testing.T) {
	for _, host := range []guideHost{hostLinux, hostMac, hostWindows} {
		t.Run(string(host), func(t *testing.T) {
			f := onFixture(t, "fresh")
			noLogins(t)
			t.Setenv("TEGO_HOST_KIND", string(host))
			fakeProgram(t, "python3")
			t.Chdir(f.Home)
			code, out, errs := runGuide(t, "4\npython3 bot.py\n1\n1\n")
			if code != identity.ExitOK {
				t.Fatalf("exit %d: %s\n%s", code, out, errs)
			}
			_, panel, ok := strings.Cut(out, "  Ready\n")
			if !ok {
				t.Fatal(out)
			}
			panel, _, _ = strings.Cut(panel, "\n  Next steps")
			path := filepath.Join("testdata", "guide-ready-"+string(host)+".golden")
			// Chdir above mirrors a fresh distribution, so locate the source fixture
			// relative to the package's original test directory.
			want, err := os.ReadFile(filepath.Join(guideHostTestDir, path))
			if err != nil {
				t.Fatal(err)
			}
			if panel != string(want) {
				t.Fatalf("Ready panel differs:\ngot %q\nwant %q", panel, want)
			}
		})
	}
}

var guideHostTestDir, _ = os.Getwd()

// TestDashboardHostKinds: every host starts the one dashboard unit. Linux and the Mac print its link; Windows never
// does (from Windows the 127.0.0.1 link reaches WSL's forwarding, which the peer check refuses): the Windows command
// opens it through its relay, and a shell inside Tego's Linux is told to run tego dashboard in Windows.
func TestDashboardHostKinds(t *testing.T) {
	for _, c := range []struct {
		host   guideHost
		native string
	}{{hostLinux, ""}, {hostMac, ""}, {hostWindows, ""}, {hostWindows, "1"}} {
		t.Run(string(c.host)+c.native, func(t *testing.T) {
			onFixture(t, "fresh")
			t.Setenv("TEGO_HOST_KIND", string(c.host))
			t.Setenv("TEGO_WINDOWS_NATIVE", c.native)
			old := guideDashboard
			t.Cleanup(func() { guideDashboard = old })
			const link = "http://127.0.0.1:12345/?t=fixture"
			started := false
			guideDashboard = func(context.Context, string) string {
				started = true
				return link
			}
			code, out, errs := run(t, "dashboard")
			if code != identity.ExitOK || !started {
				t.Fatalf("exit %d, unit started %v: %s%s", code, started, out, errs)
			}
			if strings.Contains(out, link) == (c.host == hostWindows) || strings.Contains(out, "127.0.0.1") == (c.host == hostWindows) {
				t.Fatal(out)
			}
			if strings.Contains(out, "Open the link above") != (c.host == hostLinux) {
				t.Fatal(out)
			}
			if strings.Contains(out, "type exit, then run: tego dashboard") != (c.host == hostWindows && c.native == "") {
				t.Fatal(out)
			}
		})
	}
}
