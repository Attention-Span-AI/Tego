// SPDX-License-Identifier: Apache-2.0

package guide

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

var sample = Check{Where: WhereShell, Build: "tego=v1 commit=c exe=1:2:3:4.000000000", BootID: "b-1", Tier: "landlock",
	Time: time.Date(2026, 11, 11, 9, 30, 0, 0, time.UTC)}

const good = `{"schema":"tego.check/1","checks":[{"where":"shell","build":"b","boot_id":"x","tier":"landlock","first_fix":"","time":"2026-11-11T09:30:00Z"}]}`

// TestDecodeChecksIsStrict: a file this package did not write is refused whole, never read as a default: an unknown
// key, a missing key, a value of another type, a truncated file, data after the object, another schema, an unknown
// place or tier, two checks from one place, a fix beside a tier, a character that does not print, and a file too large.
func TestDecodeChecksIsStrict(t *testing.T) {
	if _, err := DecodeChecks([]byte(good)); err != nil {
		t.Fatalf("the good file: %v", err)
	}
	for name, text := range map[string]string{
		"unknown key":      strings.Replace(good, `"tier"`, `"extra":1,"tier"`, 1),
		"unknown top key":  strings.Replace(good, `"schema"`, `"x":true,"schema"`, 1),
		"missing key":      strings.Replace(good, `"first_fix":"",`, ``, 1),
		"missing checks":   `{"schema":"tego.check/1"}`,
		"null checks":      `{"schema":"tego.check/1","checks":null}`,
		"wrong type":       strings.Replace(good, `"tier":"landlock"`, `"tier":1`, 1),
		"null field":       strings.Replace(good, `"tier":"landlock"`, `"tier":null`, 1),
		"truncated":        good[:len(good)-3],
		"trailing data":    good + `{}`,
		"another schema":   strings.Replace(good, "tego.check/1", "tego.check/2", 1),
		"unknown place":    strings.Replace(good, `"shell"`, `"desktop"`, 1),
		"observe tier":     strings.Replace(good, `"landlock"`, `"observe"`, 1),
		"bad time":         strings.Replace(good, `2026-11-11T09:30:00Z`, `yesterday`, 1),
		"empty build":      strings.Replace(good, `"build":"b"`, `"build":""`, 1),
		"fix with a tier":  strings.Replace(good, `"first_fix":""`, `"first_fix":"do x"`, 1),
		"control char":     strings.Replace(good, `"first_fix":""`, `"first_fix":"a\u001b[2Jb"`, 1),
		"bidi override":    strings.Replace(good, `"build":"b"`, `"build":"b\u202e"`, 1),
		"two from a place": strings.Replace(good, `]}`, `,`+good[strings.Index(good, `{"where"`):len(good)-2]+`]}`, 1),
		"too large":        good + strings.Repeat(" ", MaxCheckBytes),
		"an array":         `[]`,
		"empty":            ``,
		"unknown cause":    strings.Replace(good, `"tier":"landlock"`, `"tier":"","cause":"elsewhere"`, 1),
		"cause with tier":  strings.Replace(good, `"tier":"landlock"`, `"tier":"landlock","cause":"outside-user-manager"`, 1),
		"cause for root":   strings.Replace(strings.Replace(good, `"shell"`, `"root"`, 1), `"tier":"landlock"`, `"tier":"","cause":"outside-user-manager"`, 1),
		"null cause":       strings.Replace(good, `"tier":"landlock"`, `"tier":"","cause":null`, 1),
	} {
		if cs, err := DecodeChecks([]byte(text)); !errors.Is(err, ErrBadCheck) {
			t.Errorf("%s: %v, %+v; want ErrBadCheck", name, err, cs)
		}
	}
}

// TestCheckCauseRoundTrips: a shell entry that starts no run only because it is outside the user manager's cgroup
// keeps that cause through the file, and a file an older build wrote, with no cause key, still decodes (acceptance B,
// 2026-11-11: the cause decides the next step, on the dashboard too).
func TestCheckCauseRoundTrips(t *testing.T) {
	c := sample
	c.Tier, c.FirstFix, c.Cause = "", "start tego from a shell in your user manager's cgroup", CauseOutsideUserManager
	b, err := EncodeChecks([]Check{c})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeChecks(b)
	if err != nil || len(got) != 1 || got[0] != c {
		t.Fatalf("round trip %+v: %+v %v", c, got, err)
	}
	b, err = EncodeChecks([]Check{sample})
	if err != nil || strings.Contains(string(b), "cause") {
		t.Errorf("a check with no cause writes the key: %s %v", b, err)
	}
	if _, err := DecodeChecks([]byte(good)); err != nil {
		t.Errorf("a file with no cause key: %v", err)
	}
}

// TestStoreCheckWritesOneEntryPerPlace: a check replaces the check of its place, keeps the other places' checks of
// its boot and build and drops the others; the file is 0600 in a 0700 folder and reads back equal.
func TestStoreCheckWritesOneEntryPerPlace(t *testing.T) {
	home := t.TempDir()
	root := sample
	root.Where, root.Tier = WhereRoot, "landlock"
	old := sample
	old.Where, old.BootID = WhereUserManager, "an older boot"
	for _, c := range []Check{old, root, sample} {
		if err := StoreCheck(home, c); err != nil {
			t.Fatal(err)
		}
	}
	shell := sample
	shell.Tier, shell.FirstFix = "", "do the fix"
	if err := StoreCheck(home, shell); err != nil {
		t.Fatal(err)
	}
	got, err := ReadChecks(home)
	if err != nil {
		t.Fatal(err)
	}
	if want := []Check{shell, root}; !reflect.DeepEqual(got, want) {
		t.Errorf("stored %+v, want %+v", got, want)
	}
	for path, mode := range map[string]os.FileMode{CheckPath(home): 0o600, filepath.Dir(CheckPath(home)): 0o700 | os.ModeDir} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode() != mode {
			t.Errorf("%s: mode %v, want %v", path, fi.Mode(), mode)
		}
	}
	left, err := filepath.Glob(filepath.Join(filepath.Dir(CheckPath(home)), ".check.json.*"))
	if err != nil || len(left) != 0 {
		t.Errorf("temporary files left: %v %v", left, err)
	}
}

// TestCheckFileThatIsNotAFileIsRefused: a link at ~/.tego/state or at check.json, a FIFO, a directory and a file larger
// than MaxCheckBytes at check.json are each an error on read (never a hang, never a default), and StoreCheck refuses to
// write through a link at state. A missing file is os.ErrNotExist.
func TestCheckFileThatIsNotAFileIsRefused(t *testing.T) {
	setup := func(t *testing.T) (home, state string) {
		home = t.TempDir()
		state = filepath.Join(home, ".tego", StateDir)
		if err := os.MkdirAll(state, 0o700); err != nil {
			t.Fatal(err)
		}
		return home, state
	}
	t.Run("missing", func(t *testing.T) {
		home, _ := setup(t)
		if _, err := ReadChecks(home); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a missing check.json: %v", err)
		}
		if _, err := ReadChecks(t.TempDir()); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a missing ~/.tego: %v", err)
		}
	})
	t.Run("fifo", func(t *testing.T) {
		home, state := setup(t)
		if err := syscall.Mkfifo(filepath.Join(state, CheckFile), 0o600); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := ReadChecks(home); done <- err }()
		select {
		case err := <-done:
			if err == nil || errors.Is(err, fs.ErrNotExist) {
				t.Errorf("a FIFO: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("reading a FIFO at check.json hung")
		}
		// StoreCheck replaces the FIFO by its rename, without hanging on it.
		go func() { done <- StoreCheck(home, sample) }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("StoreCheck over a FIFO: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("storing over a FIFO at check.json hung")
		}
		if cs, err := ReadChecks(home); err != nil || len(cs) != 1 {
			t.Errorf("after StoreCheck over a FIFO: %+v, %v", cs, err)
		}
	})
	t.Run("directory", func(t *testing.T) {
		home, state := setup(t)
		if err := os.Mkdir(filepath.Join(state, CheckFile), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadChecks(home); err == nil || errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a directory: %v", err)
		}
		// A folder is left as it is: the rename fails, the check is not stored, and no temporary file is left.
		if err := StoreCheck(home, sample); err == nil {
			t.Error("StoreCheck replaced a directory")
		}
		if fi, err := os.Lstat(filepath.Join(state, CheckFile)); err != nil || !fi.IsDir() {
			t.Errorf("the folder at check.json after StoreCheck: %v, %v", fi, err)
		}
		if ents, _ := os.ReadDir(state); len(ents) != 1 {
			t.Errorf("StoreCheck left files beside the folder: %v", ents)
		}
	})
	t.Run("large", func(t *testing.T) {
		home, state := setup(t)
		if err := os.WriteFile(filepath.Join(state, CheckFile), make([]byte, MaxCheckBytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadChecks(home); !errors.Is(err, ErrBadCheck) {
			t.Errorf("a large file: %v", err)
		}
	})
	t.Run("link at check.json", func(t *testing.T) {
		home, state := setup(t)
		target := filepath.Join(t.TempDir(), "real.json")
		if err := os.WriteFile(target, []byte(good), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(state, CheckFile)); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadChecks(home); err == nil {
			t.Error("a link at check.json was followed")
		}
		// Storing replaces the link itself (rename), never writes through it.
		if err := StoreCheck(home, sample); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(target); string(b) != good {
			t.Errorf("the link's target was written: %s", b)
		}
	})
	t.Run("link at state", func(t *testing.T) {
		home := t.TempDir()
		elsewhere := t.TempDir()
		if err := os.Mkdir(filepath.Join(home, ".tego"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, filepath.Join(home, ".tego", StateDir)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(elsewhere, CheckFile), []byte(good), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadChecks(home); err == nil || errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a link at state was followed: %v", err)
		}
		if err := StoreCheck(home, sample); err == nil {
			t.Error("StoreCheck wrote through a link at state")
		}
		if ents, _ := os.ReadDir(elsewhere); len(ents) != 1 {
			t.Errorf("the link's target folder holds %d entries", len(ents))
		}
	})
	t.Run("state another may write", func(t *testing.T) {
		home, state := setup(t)
		if err := os.Chmod(state, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := StoreCheck(home, sample); err == nil {
			t.Error("StoreCheck wrote into a folder others may write")
		}
	})
}

// TestStoreCheckRefusesWhatItWouldNotRead: a check with an unknown place, a control character or no build is refused
// before anything is written.
func TestStoreCheckRefusesWhatItWouldNotRead(t *testing.T) {
	home := t.TempDir()
	for _, c := range []Check{
		{Where: "desktop", Build: "b", BootID: "x", Time: sample.Time},
		{Where: WhereShell, Build: "b\n", BootID: "x", Time: sample.Time},
		{Where: WhereShell, BootID: "x", Time: sample.Time},
	} {
		if err := StoreCheck(home, c); err == nil {
			t.Errorf("stored %+v", c)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".tego")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a refused check made ~/.tego: %v", err)
	}
}

// FuzzDecodeChecks: any bytes either decode to checks that EncodeChecks writes and DecodeChecks reads back equal, or
// are ErrBadCheck; nothing panics.
func FuzzDecodeChecks(f *testing.F) {
	f.Add([]byte(good))
	f.Add([]byte(`{"schema":"tego.check/1","checks":[]}`))
	f.Add([]byte(strings.Replace(good, `"tier":"landlock","first_fix":""`, `"tier":"","first_fix":"run x"`, 1)))
	f.Add([]byte(good[:40]))
	f.Fuzz(func(t *testing.T, b []byte) {
		cs, err := DecodeChecks(b)
		if err != nil {
			if !errors.Is(err, ErrBadCheck) {
				t.Fatalf("an error that is not ErrBadCheck: %v", err)
			}
			return
		}
		out, err := EncodeChecks(cs)
		if err != nil {
			t.Fatalf("decoded %+v does not encode: %v", cs, err)
		}
		again, err := DecodeChecks(out)
		if err != nil {
			t.Fatalf("encoded %s does not decode: %v", out, err)
		}
		if len(again) != len(cs) {
			t.Fatalf("round trip: %+v -> %+v", cs, again)
		}
	})
}

// TestPlaceAndUserManager: the place a check is stored under follows root and the user manager's cgroup, and only a
// cgroup at or beneath user@<uid>.service is the user manager's.
func TestPlaceAndUserManager(t *testing.T) {
	for cg, want := range map[string]bool{
		"0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope\n": true,
		"0::/user.slice/user-1000.slice/user@1000.service\n":                   true,
		"0::/user.slice/user-1000.slice/session-3.scope\n":                     false,
		"0::/user.slice/user-1000.slice/user@10000.service/app.slice\n":        false,
		"0::/\n":                                false,
		"1:name=systemd:/user@1000.service/x\n": false,
		"":                                      false,
	} {
		if got := inUserManager([]byte(cg), 1000); got != want {
			t.Errorf("%q: %v, want %v", cg, got, want)
		}
	}
	if place(true, true) != WhereRoot || place(false, true) != WhereUserManager || place(false, false) != WhereShell {
		t.Error("place")
	}
}

// TestOpenScopeNamesOnlyACommandThatCanWork: the command that opens a shell in the user manager's cgroup is named only
// when systemd-run is on PATH and a socket of the user's own manager is under XDG_RUNTIME_DIR, which systemd-run --user
// connects through; it uses $SHELL's name when that shell is one of a fixed list and on PATH, else bash; otherwise it is "" with the reason
// (acceptance B, 2026-11-11: never a command that fails).
func TestOpenScopeNamesOnlyACommandThatCanWork(t *testing.T) {
	bin, rt := t.TempDir(), t.TempDir()
	for _, p := range []string{"systemd-run", "bash", "zsh", "nologin", "false", "python3", "evil-tool"} {
		if err := os.WriteFile(filepath.Join(bin, p), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(rt, "systemd"), 0o700); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Close(fd) }()
	// Bound by a name relative to rt: a test's temporary path can be longer than sun_path holds, and the test skipped.
	t.Chdir(rt)
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: filepath.Join("systemd", "private")}); err != nil {
		t.Skipf("cannot bind a socket under %s: %v", rt, err)
	}
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	uid := os.Getuid()
	// The logind roots: none holds a folder of the uid; lr holds lr/<uid>/systemd/private, the uid's manager's socket,
	// where a user manager started by linger keeps it (/run/user/<uid>), reached after su or sudo -u only by naming it.
	none, lr := t.TempDir(), t.TempDir()
	own := filepath.Join(lr, strconv.Itoa(uid))
	if err := os.MkdirAll(filepath.Join(own, "systemd"), 0o700); err != nil {
		t.Fatal(err)
	}
	lfd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Close(lfd) }()
	t.Chdir(own)
	if err := syscall.Bind(lfd, &syscall.SockaddrUnix{Name: filepath.Join("systemd", "private")}); err != nil {
		t.Skipf("cannot bind a socket under %s: %v", own, err)
	}
	empty := t.TempDir()
	viaLogind := "XDG_RUNTIME_DIR=" + own + " systemd-run --user --scope bash"
	for _, tc := range []struct {
		name    string
		vars    map[string]string
		uid     int
		logind  string
		command string
		missing string
	}{
		{"bash", map[string]string{"PATH": bin, "XDG_RUNTIME_DIR": rt, "SHELL": "/bin/bash"}, uid, none, "systemd-run --user --scope bash", ""},
		{"the login shell", map[string]string{"PATH": bin, "XDG_RUNTIME_DIR": rt, "SHELL": "/usr/bin/zsh"}, uid, none, "systemd-run --user --scope zsh", ""},
		{"a shell not on PATH", map[string]string{"PATH": bin, "XDG_RUNTIME_DIR": rt, "SHELL": "/opt/fish"}, uid, none, "systemd-run --user --scope bash", ""},
		// $SHELL names a program that is no shell of the list, even one on PATH: bash (the review's S1).
		{"nologin", map[string]string{"PATH": bin, "XDG_RUNTIME_DIR": rt, "SHELL": "/usr/sbin/nologin"}, uid, none, "systemd-run --user --scope bash", ""},
		{"false", map[string]string{"PATH": bin, "XDG_RUNTIME_DIR": rt, "SHELL": "/bin/false"}, uid, none, "systemd-run --user --scope bash", ""},
		{"python3", map[string]string{"PATH": bin, "XDG_RUNTIME_DIR": rt, "SHELL": "/usr/bin/python3"}, uid, none, "systemd-run --user --scope bash", ""},
		{"a program on PATH", map[string]string{"PATH": bin, "XDG_RUNTIME_DIR": rt, "SHELL": "/opt/evil-tool"}, uid, none, "systemd-run --user --scope bash", ""},
		{"no systemd-run", map[string]string{"PATH": rt, "XDG_RUNTIME_DIR": rt}, uid, none, "", "systemd-run is not on your PATH"},
		{"no runtime dir", map[string]string{"PATH": bin}, uid, none, "", "XDG_RUNTIME_DIR is not set"},
		{"another user's manager", map[string]string{"PATH": bin, "XDG_RUNTIME_DIR": rt}, uid + 1, none, "", "socket is not under"},
		// After su or sudo -u (XDG_RUNTIME_DIR unset, or another user's), the uid's own logind folder holding its
		// manager's socket: the command names that folder, a number and fixed words (the review's S5).
		{"no runtime dir, a manager in the logind folder", map[string]string{"PATH": bin, "SHELL": "/usr/sbin/nologin"}, uid, lr, viaLogind, ""},
		{"a runtime dir with no socket, a manager in the logind folder", map[string]string{"PATH": bin, "XDG_RUNTIME_DIR": empty}, uid, lr, viaLogind, ""},
		{"no runtime dir, another uid's logind folder", map[string]string{"PATH": bin}, uid + 1, lr, "", "XDG_RUNTIME_DIR is not set"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := openScope(env(tc.vars), tc.uid, tc.logind, reader{})
			command, missing := o.Command, o.Missing
			if command != tc.command || (tc.missing == "") != (missing == "") || !strings.Contains(missing, tc.missing) ||
				o.As != "" {
				t.Errorf("openScope = %+v; want %q and a reason with %q", o, tc.command, tc.missing)
			}
		})
	}

	// Started from another user's shell through sudo or su (acceptance 3, 2026-11-11): the person types the command in
	// their own shell, so it opens the shell as this user, with sudo -u and the name from the passwd entry, and always
	// through the user's logind folder, whatever this process's XDG_RUNTIME_DIR holds. Typed without sudo -u it opened
	// the reader's own scope on Ubuntu 24.04 and AlmaLinux 9.8, and failed on Fedora 44.
	asSvc := "sudo -u svc XDG_RUNTIME_DIR=" + own + " systemd-run --user --scope bash"
	asUID := "sudo -u '#" + strconv.Itoa(uid) + "' XDG_RUNTIME_DIR=" + own + " systemd-run --user --scope bash"
	svc := reader{other: true, name: "svc", named: true}
	for _, tc := range []struct {
		name    string
		vars    map[string]string
		r       reader
		logind  string
		command string
		as      string
		missing string
	}{
		{"sudo -u, no runtime dir", map[string]string{"PATH": bin, "SHELL": "/usr/sbin/nologin"}, svc, lr, asSvc, "svc", ""},
		{"sudo -u, the user's own runtime dir given", map[string]string{"PATH": bin, "XDG_RUNTIME_DIR": rt}, svc, lr, asSvc, "svc", ""},
		// $SHELL is this process's, not the reader's, and cgroup.PlacementFix, the fix: line beside this next: line,
		// names bash: so does this command, never a second one for the same shell (integration pass 5).
		{"sudo -u, a zsh $SHELL", map[string]string{"PATH": bin, "SHELL": "/usr/bin/zsh"}, svc, lr, asSvc, "svc", ""},
		{"a name with a space", map[string]string{"PATH": bin}, reader{other: true, name: "a b", named: true}, lr,
			strings.Replace(asSvc, "-u svc", "-u 'a b'", 1), "'a b'", ""},
		{"a name sudo reads as an option", map[string]string{"PATH": bin}, reader{other: true, name: "-x", named: true}, lr, asUID, "'#" + strconv.Itoa(uid) + "'", ""},
		{"a name sudo reads as a uid", map[string]string{"PATH": bin}, reader{other: true, name: "#0", named: true}, lr, asUID, "'#" + strconv.Itoa(uid) + "'", ""},
		{"no passwd entry", map[string]string{"PATH": bin}, reader{other: true}, lr, asUID, "'#" + strconv.Itoa(uid) + "'", ""},
		{"no manager in the logind folder", map[string]string{"PATH": bin, "XDG_RUNTIME_DIR": rt}, svc, none, "", "", "keeps no socket under"},
		{"no systemd-run", map[string]string{"PATH": rt}, svc, lr, "", "", "systemd-run is not on your PATH"},
	} {
		t.Run("another user's shell/"+tc.name, func(t *testing.T) {
			o := openScope(env(tc.vars), uid, tc.logind, tc.r)
			if o.Command != tc.command || o.As != tc.as || (tc.missing == "") != (o.Missing == "") || !strings.Contains(o.Missing, tc.missing) {
				t.Errorf("openScope = %+v; want %q as %q and a reason with %q", o, tc.command, tc.as, tc.missing)
			}
		})
	}
}
