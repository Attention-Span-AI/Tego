// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// The state of the stock Debian 12 and 13 cloud images: systemd runs a user manager, no bus socket exists.
func stockDebian() userBusFacts {
	return userBusFacts{Systemd: true, UID: 1000, RuntimeDir: true, Bus: false, Debian: true, Distro: "debian"}
}

func fakeUserBus(t *testing.T, f userBusFacts) {
	t.Helper()
	prev := userBusProbe
	t.Cleanup(func() { userBusProbe = prev })
	userBusProbe = func() userBusFacts { return f }
}

func TestClassifyUserBus(t *testing.T) {
	prevLinger := lingerCommand
	t.Cleanup(func() { lingerCommand = prevLinger })
	lingerCommand = func(uid int) string { return "sudo loginctl enable-linger dana" }
	fedora := userBusFacts{Systemd: true, UID: 1000, RuntimeDir: true, Distro: "fedora"}
	for _, c := range []struct {
		name  string
		f     userBusFacts
		found bool
		want  []string
	}{
		{"stock Debian: no bus", stockDebian(), true, []string{"no message bus", "sudo apt install dbus-user-session", "log in again", "tego serve"}},
		{"Debian with the package", userBusFacts{Systemd: true, UID: 1000, RuntimeDir: true, Bus: true, Debian: true}, false, nil},
		{"no user manager at all", userBusFacts{Systemd: true, UID: 1000, Debian: true}, true, []string{"no user service manager", "/run/user/1000", "sudo loginctl enable-linger dana", "tego serve"}},
		{"another family: the package is named by what it does", fedora, true, []string{"no message bus", "fedora", "dbus-user-session", "tego serve"}},
		{"systemd is not the init", userBusFacts{UID: 1000, Debian: true}, false, nil},
		{"root has no user manager of its own", userBusFacts{Systemd: true, Root: true, Debian: true}, false, nil},
	} {
		p := classifyUserBus(c.f)
		if p.found() != c.found {
			t.Errorf("%s: found = %v", c.name, p.found())
			continue
		}
		all := p.Why + "\n" + strings.Join(p.Fix, "\n") + "\n" + p.Alt
		for _, w := range c.want {
			if !strings.Contains(all, w) {
				t.Errorf("%s: lacks %q:\n%s", c.name, w, all)
			}
		}
	}
	// the Fedora-family answer does not offer the Debian command as one to type
	if p := classifyUserBus(fedora); len(p.Fix) != 0 {
		t.Errorf("a command was given for a distribution whose package is unproven: %v", p.Fix)
	}
}

func TestParseOSReleaseFamily(t *testing.T) {
	for _, c := range []struct {
		text   string
		debian bool
		id     string
	}{
		{"PRETTY_NAME=\"Debian GNU/Linux 12\"\nID=debian\n", true, "debian"},
		{"ID=ubuntu\nID_LIKE=debian\n", true, "ubuntu"},
		{"ID=\"linuxmint\"\nID_LIKE=\"ubuntu debian\"\n", true, "linuxmint"},
		{"ID=fedora\n", false, "fedora"},
		{"ID=\"rhel\"\nID_LIKE=\"fedora\"\n", false, "rhel"},
		{"", false, ""},
	} {
		if d, id := parseOSReleaseFamily(c.text); d != c.debian || id != c.id {
			t.Errorf("%q: %v %q, want %v %q", c.text, d, id, c.debian, c.id)
		}
	}
}

// busSocketExists looks at paths of a temporary folder only.
func TestBusSocketExists(t *testing.T) {
	dir, err := os.MkdirTemp("", "bus")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if busSocketExists("", dir) {
		t.Error("an empty runtime folder has a bus")
	}
	if err := os.WriteFile(filepath.Join(dir, "bus"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if busSocketExists("", dir) {
		t.Error("a regular file named bus is not a socket")
	}
	os.Remove(filepath.Join(dir, "bus"))
	l, err := net.Listen("unix", filepath.Join(dir, "bus"))
	if err != nil {
		t.Skip("no unix socket here: " + err.Error())
	}
	defer l.Close()
	if !busSocketExists("", dir) {
		t.Error("the socket is not seen")
	}
	if !busSocketExists("unix:path="+filepath.Join(dir, "bus")+",guid=x", "/nonexistent") {
		t.Error("the address's socket is not seen")
	}
	if busSocketExists("unix:path="+filepath.Join(dir, "none"), dir) {
		t.Error("an address naming a missing socket has a bus")
	}
	if !busSocketExists("unix:abstract=/tmp/dbus-x", "/nonexistent") || !busSocketExists("tcp:host=127.0.0.1,port=1", "/nonexistent") {
		t.Error("an address that is not a file path must not be called missing")
	}
}

// tego dashboard on the stock image: it names the package and the one command, offers the foreground way, starts
// nothing, and exits with Tego's own error code.
func TestDashboardNamesTheMissingUserBusAndStartsNothing(t *testing.T) {
	onFixture(t, "fresh")
	fakeUserBus(t, stockDebian())
	prev := guideDashboard
	t.Cleanup(func() { guideDashboard = prev })
	guideDashboard = func(context.Context, string) string { t.Error("a dashboard was started with no bus"); return "" }
	code, out, errs := run(t, "dashboard")
	if code != identity.ExitError {
		t.Errorf("exit %d", code)
	}
	for _, w := range []string{"The dashboard cannot start", "sudo apt install dbus-user-session", "log out and log in again", "tego serve"} {
		if !strings.Contains(out, w) {
			t.Errorf("tego dashboard lacks %q:\n%s%s", w, out, errs)
		}
	}
	if strings.Contains(out, "didn't start") {
		t.Errorf("the generic failure line is printed beside the cause:\n%s", out)
	}
}

// The other state, a manager and a bus, goes on to start the dashboard as before.
func TestDashboardStartsWhenTheUserBusIsThere(t *testing.T) {
	onFixture(t, "fresh")
	f := stockDebian()
	f.Bus = true
	fakeUserBus(t, f)
	starts := 0
	prev := guideDashboard
	t.Cleanup(func() { guideDashboard = prev })
	guideDashboard = func(context.Context, string) string { starts++; return "http://127.0.0.1:1/?t=started" }
	if code, out, errs := run(t, "dashboard"); code != identity.ExitOK || starts != 1 {
		t.Fatalf("exit %d, %d starts\n%s%s", code, starts, out, errs)
	}
}

func TestDoctorSaysWhenTheUserBusIsMissing(t *testing.T) {
	var b strings.Builder
	c := checkUserBusWith(stockDebian())
	if c == nil {
		t.Fatal("no check for the stock Debian image")
	}
	if err := writeUserBusCheck(&b, *c); err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"warn dashboard service:", "sudo apt install dbus-user-session", "tego serve"} {
		if !strings.Contains(b.String(), w) {
			t.Errorf("doctor's line lacks %q: %s", w, b.String())
		}
	}
	ok := stockDebian()
	ok.Bus = true
	if checkUserBusWith(ok) != nil {
		t.Error("doctor warns on a machine with a bus")
	}
}

// tego start: with no bus the guide starts nothing, says why before the Ready panel, and the panel does not say
// "tego dashboard opens it" as if it would.
func TestStartDoesNotTryTheDashboardWithoutAUserBus(t *testing.T) {
	prev := guideDashboard
	t.Cleanup(func() { guideDashboard = prev })
	started := 0
	guideDashboard = func(context.Context, string) string { started++; return "http://127.0.0.1:1/?t=x" }

	fakeUserBus(t, stockDebian())
	g := &walk{tty: true}
	url, p := g.dashboardStep(context.Background(), t.TempDir())
	if url != "" || !p.found() || started != 0 {
		t.Fatalf("url %q, problem %v, %d starts", url, p.found(), started)
	}
	rows := dashboardRows(hostLinux, url, p, false, "", "")
	if len(rows) != 1 || !strings.Contains(rows[0], "not started (see above)") || strings.Contains(rows[0], "tego dashboard opens it") {
		t.Errorf("Ready panel rows: %q", rows)
	}
	var out strings.Builder
	g.out = &out
	writeUserBusProblem(g, p)
	for _, w := range []string{"sudo apt install dbus-user-session", "tego serve"} {
		if !strings.Contains(out.String(), w) {
			t.Errorf("the guide's text lacks %q:\n%s", w, out.String())
		}
	}

	// a bus, or no terminal: as before
	f := stockDebian()
	f.Bus = true
	fakeUserBus(t, f)
	if url, p := g.dashboardStep(context.Background(), t.TempDir()); url == "" || p.found() || started != 1 {
		t.Errorf("with a bus: url %q, problem %v, %d starts", url, p.found(), started)
	}
	fakeUserBus(t, stockDebian())
	if url, p := (&walk{}).dashboardStep(context.Background(), t.TempDir()); url != "" || p.found() || started != 1 {
		t.Errorf("no terminal: url %q, problem %v, %d starts", url, p.found(), started)
	}
}

// tego doctor carries the same finding in its report and its JSON, and is silent where nothing is missing.
func TestDoctorReportCarriesTheUserBusFinding(t *testing.T) {
	fakeUserBus(t, stockDebian())
	_, out, _ := run(t, "doctor", "--no-scope")
	if !strings.Contains(out, "\nwarn dashboard service: ") || !strings.Contains(out, "sudo apt install dbus-user-session") {
		t.Errorf("doctor's report lacks the finding:\n%s", out)
	}
	_, out, _ = run(t, "doctor", "--no-scope", "--json")
	var rep struct {
		UserBus *userBusCheck `json:"user_bus"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil || rep.UserBus == nil || !strings.Contains(rep.UserBus.Fix, "sudo apt install dbus-user-session") {
		t.Errorf("doctor --json user_bus %+v (%v)", rep.UserBus, err)
	}
	ok := stockDebian()
	ok.Bus = true
	fakeUserBus(t, ok)
	if _, out, _ := run(t, "doctor", "--no-scope"); strings.Contains(out, "dashboard service") {
		t.Errorf("doctor warns on a machine with a bus:\n%s", out)
	}
}
