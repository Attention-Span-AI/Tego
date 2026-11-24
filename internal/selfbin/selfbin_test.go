// SPDX-License-Identifier: Apache-2.0

package selfbin

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/internal/shellword"
)

// TestSafe holds the one rule for a path that goes into a pasteable line: printable, valid UTF-8, no control, no bidi
// control. A newline, a carriage return or an escape in a directory name on the binary's path let whoever owns the
// directory forge a second apparent command on the administrator's screen.
func TestSafe(t *testing.T) {
	for _, tc := range []struct {
		name, s string
		ok      bool
	}{
		{"plain", "/home/svc/.local/bin/tego", true},
		{"spaces and quotes", "/home/a b/it's/tego", true},
		{"printable unicode", "/home/josé/日本/tego", true},
		{"newline", "/x\n  sudo -i\ntego", false},
		{"carriage return", "/x\rsudo -i", false},
		{"escape", "/x\x1b[2Jtego", false},
		{"nul", "/x\x00y", false},
		{"del", "/x\x7fy", false},
		{"c1 control", "/x\u0085y", false},
		{"bidi override", "/x\u202ey/tego", false},
		{"zero width", "/x\u200by", false},
		{"line separator", "/x y", false},
		{"invalid utf-8", "/x\xffy", false},
		{"truncated utf-8", "/x\xe2\x82", false},
	} {
		if got := Safe(tc.s); got != tc.ok {
			t.Errorf("%s: Safe(%q) = %v, want %v", tc.name, tc.s, got, tc.ok)
		}
	}
}

// script writes an executable file at path (making its folders).
func script(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestNamed: a usable path is named, absolute, links followed and quoted; every other answer is no word and a reason.
func TestNamed(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	exe := func(p string) func() (string, error) { return func() (string, error) { return p, nil } }
	bin := filepath.Join(dir, "bin dir", "te'go")
	script(t, bin)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(bin, link); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{bin: "'" + dir + "/bin dir/te'\\''go'", link: "'" + dir + "/bin dir/te'\\''go'"} {
		if w, why := named(exe(name), bin); w != want || why != "" {
			t.Errorf("%s: %q, %q, want %q", name, w, why, want)
		}
	}
	for _, tc := range []struct {
		name string
		exe  func() (string, error)
		why  string
	}{
		{"no executable", func() (string, error) { return "", os.ErrNotExist }, NoPath},
		{"empty", exe(""), NoPath},
		{"relative", exe("tego"), NoPath},
		{"missing", exe(filepath.Join(dir, "none")), NoPath},
		{"a directory", exe(dir), NoPath},
	} {
		if w, why := named(tc.exe, bin); w != "" || why != tc.why {
			t.Errorf("%s: %q, %q, want no word and %q", tc.name, w, why, tc.why)
		}
	}
	// Not executable by this process.
	if os.Geteuid() != 0 {
		plain := filepath.Join(dir, "plain")
		if err := os.WriteFile(plain, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if w, why := named(exe(plain), plain); w != "" || why != NoExec {
			t.Errorf("not executable: %q, %q, want %q", w, why, NoExec)
		}
	}
	// A path with a newline is declined, not shown: the file exists and is the running one.
	evil := filepath.Join(dir, "x\n  sudo -i\ntego")
	script(t, evil)
	if w, why := named(exe(evil), evil); w != "" || why != Unsafe {
		t.Errorf("newline in the path: %q, %q, want no word and %q", w, why, Unsafe)
	}
	evil2 := filepath.Join(dir, "\u202etego")
	script(t, evil2)
	if w, why := named(exe(evil2), evil2); w != "" || why != Unsafe {
		t.Errorf("bidi override in the path: %q, %q", w, why)
	}
}

// TestNamedRefusesAReplacedExecutable: the running file is unlinked and a searchable directory (or another file) is made
// at its path. The path still resolves and passes access(X_OK), but it no longer identifies the running file; the
// comparison with the file this process holds open does. Real files, no injected
// answer: self is a descriptor of the original file.
func TestNamedRefusesAReplacedExecutable(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tego")
	script(t, path)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	self := "/proc/self/fd/" + strconv.Itoa(int(f.Fd()))
	exe := func() (string, error) { return path, nil }
	if w, why := named(exe, self); why != "" || w != path {
		t.Fatalf("the original: %q, %q", w, why)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if w, why := named(exe, self); w != "" || why != NoPath {
		t.Errorf("unlinked: %q, %q, want %q", w, why, NoPath)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if w, why := named(exe, self); w != "" || why != NoPath {
		t.Errorf("replaced by a directory: %q, %q, want %q", w, why, NoPath)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	script(t, path)
	if w, why := named(exe, self); w != "" || why != NoPath {
		t.Errorf("replaced by another file: %q, %q, want %q", w, why, NoPath)
	}
	// The real thing: this test binary names itself.
	if w, why := Named(os.Executable); why == "" {
		if !strings.HasPrefix(w, "/") && !strings.HasPrefix(w, "'/") {
			t.Errorf("nonabsolute executable word: %q", w)
		}
	} else if why != Untrusted || w != "" {
		t.Errorf("Named(os.Executable) = %q, %q", w, why)
	}
}

// Path returns the same checked executable that Named quotes, with no shell quoting in a process argument.
func TestPathReturnsTheCheckedExecutable(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	if got, why := Path(os.Executable); got != want || why != "" {
		t.Fatalf("Path = %q, %q; want %q", got, why, want)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin dir", "te'go")
	script(t, bin)
	if got, why := checkedPath(func() (string, error) { return bin, nil }, bin); got != bin || why != "" {
		t.Fatalf("raw path = %q, %q; want %q", got, why, bin)
	}
}

// named checks path identity and quoting independently of the ancestor-permission tests below.
func named(executable func() (string, error), self string) (word, why string) {
	path, why := checkedPath(executable, self)
	if why != "" {
		return "", why
	}
	return shellword.Quote(path), ""
}

func TestSudo(t *testing.T) {
	for _, tc := range []struct{ name, word, reason, args, want string }{
		{"quoted", "'/home/svc/my tools/tego'", "", "doctor", "sudo '/home/svc/my tools/tego' doctor"},
		{"missing", "", NoPath, "doctor", ""},
		{"unsafe", "", Unsafe, "doctor", ""},
		{"unexecutable", "", NoExec, "doctor", ""},
		{"unsafe arguments", "/usr/bin/tego", "", "run a\nsudo -i", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, why := Sudo(tc.args, func() (string, string) { return tc.word, tc.reason })
			if got != tc.want || (why == "") != (tc.want != "") {
				t.Fatalf("Sudo = %q, %q; want %q", got, why, tc.want)
			}
		})
	}
}

// fixtureInfo changes metadata without requiring root or a second host user.
type fixtureInfo struct {
	os.FileInfo
	owner *syscall.Stat_t
}

func (i fixtureInfo) Sys() any { return i.owner }

// TestNamedRejectsReplaceableChain uses real temp files and modes. Only ancestors
// above the fixture root get synthetic root-owned 0755 metadata: the checkout's
// shared build/scratch ancestors may themselves be unsafe, independently of the
// tree under test. Ownership cases use copied stat metadata, without chown.
func TestNamedRejectsReplaceableChain(t *testing.T) {
	for _, tc := range []struct {
		name, node                string
		mode                      os.FileMode
		foreign, missing, allowed bool
	}{
		{name: "safe chain", allowed: true},
		{name: "world writable ancestor", node: "shared", mode: 0o777},
		{name: "private group writable ancestor", node: "shared", mode: 0o775, allowed: true},
		{name: "sticky world writable ancestor", node: "shared", mode: 0o777 | os.ModeSticky, allowed: true},
		{name: "foreign sticky directory owner", node: "shared", mode: 0o777 | os.ModeSticky, foreign: true},
		{name: "foreign child in sticky ancestor", node: "shared/own", foreign: true},
		{name: "foreign read only ancestor", node: "shared/own", mode: 0o555, foreign: true},
		{name: "foreign executable owner", node: "shared/own/tego", foreign: true},
		{name: "writable executable", node: "shared/own/tego", mode: 0o777},
		{name: "unreadable ancestor metadata", node: "shared", missing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			bin := filepath.Join(root, "shared", "own", "tego")
			script(t, bin)
			target := filepath.Join(root, tc.node)
			t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "shared", "own"), 0o755) })
			if tc.mode != 0 {
				if err := os.Chmod(target, tc.mode); err != nil {
					t.Fatal(err)
				}
			}
			if tc.name == "foreign child in sticky ancestor" {
				if err := os.Chmod(filepath.Join(root, "shared"), 0o777|os.ModeSticky); err != nil {
					t.Fatal(err)
				}
			}
			top, err := os.Stat("/")
			if err != nil {
				t.Fatal(err)
			}
			stat := func(path string) (os.FileInfo, error) {
				if path != root && !strings.HasPrefix(path, root+string(os.PathSeparator)) {
					return top, nil
				}
				if tc.missing && path == target {
					return nil, os.ErrPermission
				}
				info, err := os.Lstat(path)
				if err != nil {
					return nil, err
				}
				if tc.foreign && path == target {
					owner := *info.Sys().(*syscall.Stat_t)
					owner.Uid = uint32(os.Geteuid()) + 10001
					return fixtureInfo{info, &owner}, nil
				}
				return info, nil
			}
			word, why := namedPathWithTrust(func() (string, error) { return bin, nil }, bin, stat,
				func(path string, uid int, stat func(string) (os.FileInfo, error)) bool {
					return trustedChainWithGroups(path, uid, stat, groupTrust{primary: uint32(os.Getegid()), primaryOK: true, complete: true, groups: map[uint32]groupUse{uint32(os.Getegid()): {used: true}}}, noAccessACL)
				})
			command, reason := Sudo("doctor", func() (string, string) { return word, why })
			if tc.allowed {
				if why != "" || command != "sudo "+shellword.Quote(bin)+" doctor" {
					t.Fatalf("safe chain: %q, %q", command, reason)
				}
			} else if word != "" || command != "" || reason != Untrusted {
				t.Fatalf("replaceable chain: word %q command %q reason %q", word, command, reason)
			}
		})
	}
}

// Boolean adapters let the existing fixture tables check the production refusal walk.
// A printed command will run later. Checking inode identity now is insufficient
// if an unrelated account can rewrite the file or rename any part of its path.
func trustedChain(path string, uid int, stat func(string) (os.FileInfo, error)) bool {
	return trustedChainWithGroups(path, uid, stat, systemGroupTrust(uid), noAccessACL)
}

func trustedChainWithGroups(path string, uid int, stat func(string) (os.FileInfo, error), groups groupTrust, aclSafe func(string) bool) bool {
	return chainRefusal(path, uid, stat, func() groupTrust { return groups }, aclSafe) == ""
}
