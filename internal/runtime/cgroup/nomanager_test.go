// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestNoUserManagerIsItsOwnCause: a user whose user manager is not running (an account with a nologin or false shell
// reached through sudo -u or su -s, which never logged in) has no user@<uid>.service
// cgroup at all. Detect refused it with the delegation fix ("enable systemd user delegation"), which changes nothing:
// delegation was on. It is now ErrNoUserManager, whose fix starts that user's manager without a login (sudo loginctl
// enable-linger <name>, the name from the passwd entry, as on Fedora 44), and still ErrNotDelegated. A
// candidate that exists but is not writable keeps the delegation fix, and so does a mount with no user.slice (no
// systemd layout to start a manager in).
func TestNoUserManagerIsItsOwnCause(t *testing.T) {
	mount := t.TempDir()
	if err := os.MkdirAll(filepath.Join(mount, "user.slice", "user-1000.slice"), 0o755); err != nil {
		t.Fatal(err)
	}
	prev := lookupName
	lookupName = func(uid int) (string, bool) {
		name, ok := map[int]string{1001: "svc", 1002: "a b", 1004: "-x", 1005: "1234"}[uid]
		return name, ok
	}
	t.Cleanup(func() { lookupName = prev })

	canonical := canonicalSubtreeIn(mount, 1001)
	_, err := firstWritableIn(mount, 1001, []string{canonical})
	var de *DetectError
	if !errors.Is(err, ErrNoUserManager) || !errors.Is(err, ErrNotDelegated) || !errors.As(err, &de) {
		t.Fatalf("no user@1001.service: %v, want ErrNoUserManager and ErrNotDelegated", err)
	}
	if !strings.HasPrefix(de.Diagnosis, ErrNotDelegated.Error()) || !strings.Contains(de.Diagnosis, "no user manager runs for uid 1001") {
		t.Errorf("diagnosis %q", de.Diagnosis)
	}
	if strings.Contains(de.Remedy, "Delegate=") || !strings.Contains(de.Remedy, "sudo loginctl enable-linger svc") ||
		!strings.Contains(de.Remedy, "XDG_RUNTIME_DIR=/run/user/1001 systemd-run --user --scope bash") {
		t.Errorf("remedy %q", de.Remedy)
	}
	if got := LingerCommand(1002); got != "sudo loginctl enable-linger 'a b'" {
		t.Errorf("a name that is not one plain word: %q", got)
	}
	if got := LingerCommand(1003); got != "sudo loginctl enable-linger 1003" {
		t.Errorf("a uid with no passwd entry: %q", got)
	}
	// A name loginctl would read as an option (a leading '-') or as a uid (all digits), quoted or not: the uid.
	for uid, want := range map[int]string{1004: "sudo loginctl enable-linger 1004", 1005: "sudo loginctl enable-linger 1005"} {
		if got := LingerCommand(uid); got != want {
			t.Errorf("uid %d: %q, want %q", uid, got, want)
		}
	}

	// A candidate that exists and is not writable: the delegation fix, as before.
	if err := os.MkdirAll(canonical, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := firstWritableIn(mount, 1001, []string{canonical}); errors.Is(err, ErrNoUserManager) || !errors.Is(err, ErrNotDelegated) ||
		!strings.Contains(err.Error(), "Delegate=cpu memory pids") {
		t.Errorf("an existing candidate: %v", err)
	}
	// No user.slice: no systemd layout, the delegation fix.
	bare := t.TempDir()
	if _, err := firstWritableIn(bare, 1001, []string{canonicalSubtreeIn(bare, 1001)}); errors.Is(err, ErrNoUserManager) || !errors.Is(err, ErrNotDelegated) {
		t.Errorf("no user.slice: %v", err)
	}
}

// TestTheNoManagerFixOpensTheShellAsThatUser: after linger, the shell in the user's manager is opened as that user. The
// fix said "opened with XDG_RUNTIME_DIR=/run/user/1001 systemd-run --user --scope bash", which the administrator who
// reads it typed in their own shell: on Ubuntu 24.04 and AlmaLinux 9.8 that opened the administrator's own scope, and on
// Fedora 44 it failed. The fix now names sudo -u and the user's name from the passwd entry,
// or '#<uid>' when sudo would not read the name as itself, and says whose shell it opens.
func TestTheNoManagerFixOpensTheShellAsThatUser(t *testing.T) {
	prev := lookupName
	lookupName = func(uid int) (string, bool) {
		name, ok := map[int]string{1001: "svc", 1002: "a b", 1004: "-x"}[uid]
		return name, ok
	}
	t.Cleanup(func() { lookupName = prev })
	for uid, want := range map[int]string{
		1001: "sudo -u svc XDG_RUNTIME_DIR=/run/user/1001 systemd-run --user --scope bash",
		1002: "sudo -u 'a b' XDG_RUNTIME_DIR=/run/user/1002 systemd-run --user --scope bash",
		1003: "sudo -u '#1003' XDG_RUNTIME_DIR=/run/user/1003 systemd-run --user --scope bash",
		1004: "sudo -u '#1004' XDG_RUNTIME_DIR=/run/user/1004 systemd-run --user --scope bash",
	} {
		fix := NoManagerFix(uid)
		if !strings.Contains(fix, want) || !strings.Contains(fix, "as this user") {
			t.Errorf("uid %d: %q, want %q, opened as this user", uid, fix, want)
		}
		if strings.Contains(fix, "opened with XDG_RUNTIME_DIR") {
			t.Errorf("uid %d: the fix names a command that opens the reader's own scope: %q", uid, fix)
		}
		// Typed inside a shell sudo su opened, sudo -u fails ("is not in the sudoers file", acceptance 4): the words
		// say how to come back.
		if !strings.Contains(fix, "not one sudo or su opened; if you are in one, type exit first") {
			t.Errorf("uid %d: the fix does not say to type exit in a shell sudo or su opened: %q", uid, fix)
		}
	}
}

// TestANameSystemdRefusesHasNoLingerFix: for an account whose name systemd refuses (digits only: the user 4242 on
// Ubuntu 24.04), loginctl enable-linger exits 0 and no user manager starts, so tego setup
// named the same command again. ManagerRefused says so from the passwd entry, and the fix names no linger command
// and no scope: it says what an administrator can do instead.
func TestANameSystemdRefusesHasNoLingerFix(t *testing.T) {
	prev := lookupName
	lookupName = func(uid int) (string, bool) {
		name, ok := map[int]string{1001: "svc", 1004: "4242", 1005: "-1"}[uid]
		return name, ok
	}
	t.Cleanup(func() { lookupName = prev })
	if why := ManagerRefused(1001); why != "" {
		t.Errorf("svc: %q", why)
	}
	if why := ManagerRefused(1003); why != "" {
		t.Errorf("no passwd entry: %q", why)
	}
	for _, uid := range []int{1004, 1005} {
		why := ManagerRefused(uid)
		if why == "" || !strings.Contains(why, "systemd starts no user manager") {
			t.Errorf("uid %d: %q", uid, why)
		}
		fix := NoManagerFix(uid)
		if strings.Contains(fix, "sudo loginctl") || strings.Contains(fix, "systemd-run") || !strings.Contains(fix, why) ||
			!strings.Contains(fix, "an account whose name starts with a letter") {
			t.Errorf("uid %d: fix %q", uid, fix)
		}
	}
	if why := ManagerRefused(1004); !strings.Contains(why, "4242") || !strings.Contains(why, "digits only") {
		t.Errorf("4242: %q", why)
	}
}

// TestThePlacementFixOpensTheShellAsThatUserForAnotherReader: after linger, sudo -u svc tego doctor printed on stdout,
// and tego run, watch and test in their error line, the fix "open one with systemd-run --user --scope bash", which the
// administrator who reads it typed in their own shell, where it opens the administrator's own scope
// (Ubuntu 24.04), beside a next: line that named sudo -u. CanPlace's refusal now
// names the sudo -u command when the reader is another user (config.ReadByAnother), and the bare command, as before,
// when the reader is the user.
func TestThePlacementFixOpensTheShellAsThatUserForAnotherReader(t *testing.T) {
	mount := t.TempDir()
	const user = "/user.slice/user-1002.slice"
	root := filepath.Join(mount, user, "user@1002.service")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	session := []byte("0::/user.slice/user-1000.slice/session-3.scope\n")
	prevName, prevReader, prevReach := lookupName, readByAnother, managerReachable
	lookupName = func(uid int) (string, bool) {
		name, ok := map[int]string{os.Getuid(): "svc", 1002: "svc", 1003: "#0", 1004: "+x"}[uid]
		return name, ok
	}
	managerReachable = func(int) bool { return true }
	t.Cleanup(func() { lookupName, readByAnother, managerReachable = prevName, prevReader, prevReach })

	const bare = "open one with systemd-run --user --scope bash"
	asSvc := "sudo -u svc XDG_RUNTIME_DIR=/run/user/" + strconv.Itoa(os.Getuid()) + " systemd-run --user --scope bash"
	for _, other := range []bool{true, false} {
		readByAnother = func() bool { return other }
		err := canPlace(mount, session, root, placementRemedy)
		var de *DetectError
		if !errors.As(err, &de) || !errors.Is(err, ErrBesideSubtree) {
			t.Fatalf("other=%v: canPlace = %v, want the placement refusal", other, err)
		}
		// doctor prints Remedy after "fix: " (detectFailure); run, watch and test print Error().
		for _, said := range []string{de.Remedy, err.Error()} {
			if other && (strings.Contains(said, bare) || !strings.Contains(said, asSvc) ||
				!strings.Contains(said, "from your own login shell, not one sudo or su opened (if you are in one, type exit first)")) {
				t.Errorf("read by another user: %q, want %q from your own login shell and not %q", said, asSvc, bare)
			}
			if !other && (!strings.Contains(said, bare) || strings.Contains(said, "sudo -u")) {
				t.Errorf("read by the user: %q, want %q", said, bare)
			}
		}
	}
	// A name sudo would read as a uid ('#0' is uid 0) or that NSS marks ('+'): the uid, never the name.
	for uid, want := range map[int]string{1002: "sudo -u svc ", 1003: "sudo -u '#1003' ", 1004: "sudo -u '#1004' "} {
		if got := PlacementFix(uid, true); !strings.Contains(got, want) {
			t.Errorf("uid %d: %q, want %q", uid, got, want)
		}
	}
}

// TestThePlacementFixNamesNoCommandWhenTheManagerKeepsNoSocket: the user manager runs (Detect found
// user@<uid>.service) but the user's logind folder holds no socket of it, so the sudo -u command the fix: line named
// fails from the administrator's shell (systemd-run --user connects through that folder). The next: line of tego setup,
// run, watch and test named no command there, and this fix: line still named one (integration pass 5, 2026-11-11, read
// not run). The remedy now says why and names none; with a socket it names the command as before, and for the user's
// own shell it is unchanged.
func TestThePlacementFixNamesNoCommandWhenTheManagerKeepsNoSocket(t *testing.T) {
	mount := t.TempDir()
	root := filepath.Join(mount, "user.slice/user-1002.slice/user@1002.service")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	session := []byte("0::/user.slice/user-1000.slice/session-3.scope\n")
	prevName, prevReader, prevReach := lookupName, readByAnother, managerReachable
	lookupName = func(int) (string, bool) { return "svc", true }
	t.Cleanup(func() { lookupName, readByAnother, managerReachable = prevName, prevReader, prevReach })
	uid := os.Getuid()
	remedy := func(other, reachable bool) string {
		readByAnother, managerReachable = func() bool { return other }, func(int) bool { return reachable }
		var de *DetectError
		if err := canPlace(mount, session, root, placementRemedy); !errors.As(err, &de) || !errors.Is(err, ErrBesideSubtree) {
			t.Fatalf("canPlace = %v, want the placement refusal", err)
		}
		return de.Remedy
	}
	got := remedy(true, false)
	if strings.Contains(got, "systemd-run --user --scope") || strings.Contains(got, "sudo -u") ||
		!strings.Contains(got, "keeps no socket under /run/user/"+strconv.Itoa(uid)) || !strings.Contains(got, "no command opens a shell in it") {
		t.Errorf("no socket, read by another user: %q", got)
	}
	if got := remedy(true, true); !strings.Contains(got, "sudo -u svc XDG_RUNTIME_DIR=/run/user/"+strconv.Itoa(uid)+" systemd-run --user --scope bash") {
		t.Errorf("a socket, read by another user: %q", got)
	}
	// The user's own shell names the bare command whatever the folder holds: its XDG_RUNTIME_DIR is its own.
	if got := remedy(false, false); !strings.Contains(got, "open one with systemd-run --user --scope bash") || strings.Contains(got, "sudo -u") {
		t.Errorf("no socket, read by the user: %q", got)
	}
}
