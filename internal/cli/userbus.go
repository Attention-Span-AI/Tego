// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The dashboard runs as a unit of the person's own service manager (guideDashboard: systemd-run --user --pipe), and
// that call reaches the manager through the user's message bus (D-Bus). A stock Debian 12 or 13 cloud image has the
// manager but not the package that gives it a bus (dbus-user-session), so /run/user/<uid>/bus does not exist and the
// call answers "Failed to connect to user scope bus" while the dashboard's log holds only that line. tego dashboard,
// tego start and tego doctor look for the state themselves and say what to do.

// userBusFacts is what the check reads of the machine: gathered by realUserBusFacts, handed in by a test.
type userBusFacts struct {
	Systemd    bool   // systemd is the init (sd_booted: /run/systemd/system is a directory)
	Root       bool   // the process runs as root: it has no user manager of its own to ask
	UID        int    // the user whose manager it is
	RuntimeDir bool   // the user's runtime directory (/run/user/<uid>, or $XDG_RUNTIME_DIR) exists: a manager runs
	Bus        bool   // the user's bus is there: its socket exists, or $DBUS_SESSION_BUS_ADDRESS names another transport
	Debian     bool   // the distribution is Debian or built on it (ID or ID_LIKE says debian or ubuntu)
	Distro     string // the os-release ID, for a sentence that names it
}

// userBusProbe gathers the facts; a variable so a test gives it a machine of its own and never reads this one.
var userBusProbe = realUserBusFacts

// userBusProblem says what is missing, in the words of the product: Why is one sentence, Fix the lines to type, in
// order, and Alt a way to see the dashboard now. The zero value means nothing is missing (or the machine is not one
// this check speaks for: systemd is not the init, or the process is root).
type userBusProblem struct {
	Why string
	Fix []string
	Alt string
}

// found reports whether a problem was found.
func (p userBusProblem) found() bool { return p.Why != "" }

// foregroundDashboard is the way to see the dashboard without the user manager: tego serve runs it in the terminal.
const foregroundDashboard = "To see the dashboard now, run tego serve: it runs in this terminal until you press Ctrl-C."

// classifyUserBus reads the facts: no user manager (no runtime directory) and a manager without a bus are two
// different states with two different remedies.
func classifyUserBus(f userBusFacts) userBusProblem {
	if !f.Systemd || f.Root {
		return userBusProblem{}
	}
	switch {
	case !f.RuntimeDir:
		return userBusProblem{
			Why: "this login has no user service manager (there is no /run/user/" + strconv.Itoa(f.UID) + "), and Tego's dashboard runs in it",
			Fix: []string{"log in again as this user through ssh or a console (not su or sudo -u), or ask an administrator to run: " + lingerCommand(f.UID)},
			Alt: foregroundDashboard,
		}
	case !f.Bus && f.Debian:
		return userBusProblem{
			Why: "your user service manager has no message bus (D-Bus), and Tego's dashboard runs in it; Debian and Ubuntu cloud images leave out the package that gives it one",
			Fix: []string{"sudo apt install dbus-user-session", "then log out and log in again"},
			Alt: foregroundDashboard,
		}
	case !f.Bus:
		d := f.Distro
		if d == "" {
			d = "this distribution"
		}
		return userBusProblem{
			Why: "your user service manager has no message bus (D-Bus), and Tego's dashboard runs in it; install the package of " + d + " that starts a bus for each user (on Debian and Ubuntu it is dbus-user-session), then log out and log in again",
			Alt: foregroundDashboard,
		}
	}
	return userBusProblem{}
}

// realUserBusFacts reads this machine. Nothing is started; it stats two paths and reads the os-release file.
func realUserBusFacts() userBusFacts {
	f := userBusFacts{UID: os.Geteuid()}
	f.Root = f.UID == 0
	if st, err := os.Stat("/run/systemd/system"); err == nil && st.IsDir() {
		f.Systemd = true
	}
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if !filepath.IsAbs(dir) {
		dir = filepath.Join("/run/user", strconv.Itoa(f.UID))
	}
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		f.RuntimeDir = true
	}
	f.Bus = busSocketExists(os.Getenv("DBUS_SESSION_BUS_ADDRESS"), dir)
	f.Debian, f.Distro = osReleaseFamily()
	return f
}

// busSocketExists reports whether the user's bus is there: the unix socket named by address, or by default
// <runtimeDir>/bus. An address of another kind (an abstract socket, tcp:) cannot be checked by a file, so it counts as
// there: the check never says a bus is missing when it cannot tell.
func busSocketExists(address, runtimeDir string) bool {
	path := filepath.Join(runtimeDir, "bus")
	if address != "" {
		rest, ok := strings.CutPrefix(address, "unix:path=")
		if !ok {
			return true
		}
		path, _, _ = strings.Cut(rest, ",")
	}
	st, err := os.Stat(path)
	return err == nil && st.Mode()&os.ModeSocket != 0
}

// osReleaseFamily reads /etc/os-release for its ID and ID_LIKE.
func osReleaseFamily() (debian bool, id string) {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return false, ""
	}
	return parseOSReleaseFamily(string(b))
}

// parseOSReleaseFamily is osReleaseFamily on the file's text.
func parseOSReleaseFamily(text string) (debian bool, id string) {
	words := map[string]bool{}
	for _, l := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			id = v
			words[v] = true
		case "ID_LIKE":
			for _, w := range strings.Fields(v) {
				words[w] = true
			}
		}
	}
	return words["debian"] || words["ubuntu"], id
}

// writeUserBusProblem prints the problem as the guide does: what is wrong, the lines to type, and the foreground way.
func writeUserBusProblem(g *walk, p userBusProblem) {
	g.bad("The dashboard cannot start: " + p.Why + ".")
	for _, c := range p.Fix {
		if strings.HasPrefix(c, "sudo ") {
			g.cmd(c)
		} else {
			g.detail(c)
		}
	}
	if p.Alt != "" {
		g.detail(p.Alt)
	}
}

// userBusCheck is doctor's line for the same state: a warning, never the exit (it is a dashboard dependency, not a
// tier's), as doctordashboard.go's.
type userBusCheck struct {
	// Detail is what doctor prints after "dashboard service: ".
	Detail string `json:"detail"`
	// Fix is the lines that make it work, in order, "" joined by ", ".
	Fix string `json:"fix,omitempty"`
	// Foreground is how to see the dashboard meanwhile.
	Foreground string `json:"foreground,omitempty"`
}

// checkUserBus asks the machine and returns nil when nothing is missing.
func checkUserBus() *userBusCheck { return checkUserBusWith(userBusProbe()) }

// checkUserBusWith is checkUserBus on facts already gathered.
func checkUserBusWith(f userBusFacts) *userBusCheck {
	p := classifyUserBus(f)
	if !p.found() {
		return nil
	}
	return &userBusCheck{Detail: p.Why, Fix: strings.Join(p.Fix, ", "), Foreground: p.Alt}
}

// writeUserBusCheck writes the check as one line in the shape of writeDashboardCheck's.
func writeUserBusCheck(w io.Writer, c userBusCheck) error {
	line := "\nwarn dashboard service: " + c.Detail
	if c.Fix != "" {
		line += "; fix: " + c.Fix
	}
	if c.Foreground != "" {
		line += "; " + strings.ToLower(c.Foreground[:1]) + c.Foreground[1:]
	}
	if _, err := fmt.Fprintln(w, line); err != nil {
		return fmt.Errorf("doctor: write dashboard service: %w", err)
	}
	return nil
}
