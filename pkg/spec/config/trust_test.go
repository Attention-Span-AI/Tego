// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// trustedDir returns a fresh 0700 directory owned by the test uid: t.TempDir's own subdirectories
// follow the umask (0775 here) and would fail R20's directory check themselves.
func trustedDir(t testing.TB) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "trusted")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// writeFile creates a layer file with the given mode inside dir.
func writeFile(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // WriteFile honours umask; the test wants the exact bits
		t.Fatal(err)
	}
	return path
}

// mkdirMode creates a directory with exactly mode. Mkdir honours the umask as WriteFile does, and a
// umask of 022 (a systemd service's default, and so a CI runner's) turns 0770 into 0750 and 0777 into
// 0755: a directory no other user can write, which the untrusted-directory cases would then read as
// trusted.
func mkdirMode(t *testing.T, dir, name string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.Mkdir(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// The trust rule over fixtures (R20, E10, E13, E26).
// identity-config.md R20, E10 (a symlink is judged by its target and directory), E13 (a directory is untrusted, not skipped), E26 (a FIFO with no writer neither hangs nor loads). E27: the MaxLayerSize case (the doc still calls the size cap undefined, Q4).
func TestReadTrusted(t *testing.T) {
	uid := os.Getuid()
	cases := []struct {
		name   string
		setup  func(t *testing.T, dir string) string
		uid    int
		absent bool
		reason string // substring of UntrustedError.Reason; "" = trusted
		errIs  error  // non-untrusted error expected
	}{
		{name: "trusted 0644", setup: func(t *testing.T, dir string) string {
			return writeFile(t, dir, "c.yaml", "version: 0\n", 0o644)
		}, uid: uid},
		{name: "trusted 0600", setup: func(t *testing.T, dir string) string {
			return writeFile(t, dir, "c.yaml", "", 0o600)
		}, uid: uid},
		{name: "absent", setup: func(t *testing.T, dir string) string {
			return filepath.Join(dir, "missing.yaml")
		}, uid: uid, absent: true},
		{name: "group writable", setup: func(t *testing.T, dir string) string {
			return writeFile(t, dir, "c.yaml", "", 0o664)
		}, uid: uid, reason: "group or other writable"},
		{name: "other writable", setup: func(t *testing.T, dir string) string {
			return writeFile(t, dir, "c.yaml", "", 0o646)
		}, uid: uid, reason: "group or other writable"},
		{name: "owned by another uid", setup: func(t *testing.T, dir string) string {
			return writeFile(t, dir, "c.yaml", "", 0o644)
		}, uid: uid + 1, reason: "owned by uid"},
		{name: "root-owned file in root-owned directory is trusted for any uid", setup: func(t *testing.T, dir string) string {
			return "/etc/hostname"
		}, uid: uid + 1},
		{name: "directory group writable", setup: func(t *testing.T, dir string) string {
			sub := mkdirMode(t, dir, "lax", 0o770)
			return writeFile(t, sub, "c.yaml", "", 0o644)
		}, uid: uid, reason: "directory group or other writable"},
		{name: "E10 symlink into a world-writable directory", setup: func(t *testing.T, dir string) string {
			lax := mkdirMode(t, dir, "world", 0o777)
			target := writeFile(t, lax, "real.yaml", "", 0o644)
			link := filepath.Join(dir, "c.yaml")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			return link
		}, uid: uid, reason: "directory group or other writable"},
		{name: "E10 symlink into a trusted directory", setup: func(t *testing.T, dir string) string {
			target := filepath.Join(dir, "elsewhere")
			if err := os.Mkdir(target, 0o700); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(dir, "c.yaml") // the layer path, under a different name than its target
			if err := os.Symlink(writeFile(t, target, "real.yaml", "version: 0\n", 0o600), link); err != nil {
				t.Fatal(err)
			}
			return link
		}, uid: uid},
		{name: "E13 a directory", setup: func(t *testing.T, dir string) string {
			return dir
		}, uid: uid, reason: "not a regular file"},
		{name: "E26 FIFO with no writer", setup: func(t *testing.T, dir string) string {
			path := filepath.Join(dir, "fifo")
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}, uid: uid, reason: "not a regular file"},
		{name: "over MaxLayerSize", setup: func(t *testing.T, dir string) string {
			path := writeFile(t, dir, "big.yaml", "", 0o600)
			if err := os.Truncate(path, MaxLayerSize+1); err != nil {
				t.Fatal(err)
			}
			return path
		}, uid: uid, errIs: errTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.setup(t, trustedDir(t))
			if _, err := os.Lstat(path); tc.name == "root-owned file in root-owned directory is trusted for any uid" && err != nil {
				t.Skip("/etc/hostname absent")
			}
			type result struct {
				absent bool
				err    error
			}
			done := make(chan result, 1)
			go func() {
				_, absent, err := readTrusted(path, tc.uid)
				done <- result{absent, err}
			}()
			var r result
			select {
			case r = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("readTrusted hung (E26 deadline)")
			}
			if r.absent != tc.absent {
				t.Errorf("absent = %v, want %v", r.absent, tc.absent)
			}
			if tc.errIs != nil {
				if !errors.Is(r.err, tc.errIs) {
					t.Fatalf("err = %v, want %v", r.err, tc.errIs)
				}
				return
			}
			var ue *UntrustedError
			if tc.reason == "" {
				if r.err != nil {
					t.Fatalf("unexpected error: %v", r.err)
				}
				return
			}
			if !errors.As(r.err, &ue) || !errors.Is(r.err, ErrUntrusted) {
				t.Fatalf("err = %v, want *UntrustedError", r.err)
			}
			if !strings.Contains(ue.Reason, tc.reason) {
				t.Errorf("reason %q does not contain %q", ue.Reason, tc.reason)
			}
			if !strings.HasPrefix(ue.Error(), "machine config untrusted: ") || ue.Fix() == "" {
				t.Errorf("message %q", ue.Error())
			}
		})
	}
}

// T-config-trust-2 / I11: both trust modes run through the one helper; abort stops before the
// next layer, warn skips the layer whole.
// identity-config.md I11: abort and warn-and-skip both go through the one trust helper.
func TestLoadSourcesTrustModes(t *testing.T) {
	dir := trustedDir(t)
	etc := writeFile(t, dir, "etc.yaml", "stop_grace: 3s\nlimits:\n  pids: 10\n", 0o664) // untrusted
	env := writeFile(t, dir, "env.yaml", "this: [is: not\n", 0o600)                      // malformed, must not be read in abort mode
	src := Sources{Etc: etc, EnvFile: env}

	m, diags, err := LoadSources(src, "", os.Getuid(), TrustAbort)
	if m != nil || !errors.Is(err, ErrUntrusted) {
		t.Fatalf("abort: m=%v err=%v", m, err)
	}
	for _, d := range diags {
		if strings.Contains(d.File, "env.yaml") {
			t.Errorf("later layer was read after an untrusted one: %v", d)
		}
	}

	m, diags, err = LoadSources(src, "", os.Getuid(), TrustWarn)
	if err != nil || m == nil {
		t.Fatalf("warn: err=%v", err)
	}
	if m.StopGrace.Value != DefaultStopGrace || m.Limits.Pids.Bounded {
		t.Error("untrusted layer partially applied")
	}
	codes := map[string]int{}
	for _, d := range diags {
		codes[d.Code]++
		if d.Severity != SeverityWarning {
			t.Errorf("warn mode produced a non-warning: %v", d)
		}
	}
	if codes[CodeUntrusted] != 1 || codes[CodeInvalid] < 1 {
		t.Errorf("diagnostics = %v", diags)
	}
}

// TestReadTrustedFDPinnedAcrossSwap is the TOCTOU boundary the file half of the trust check CAN
// defend ("what happens when the file changes between the stat and the read").
// readTrusted opens the file once, fstats that fd (the trust decision) and reads from the same fd
// (never re-opening the path), so a rename that swaps a different file into the path afterward
// cannot change what gets parsed. A real race between readTrusted's own internal stat and its own
// internal read cannot be triggered from outside a single call — there is no hook to pause it
// mid-function, and the repository's own rule against sleep/retry-based tests (a prior test that
// wrote a control file non-atomically) rules out trying to win that timing anyway — so this drives
// the exact same primitives (open with O_NONBLOCK, fstat via the package's fstat, then read) in the
// same order readTrusted uses, with the swap placed deterministically between the two.
func TestReadTrustedFDPinnedAcrossSwap(t *testing.T) {
	dir := trustedDir(t)
	path := writeFile(t, dir, "c.yaml", "trusted\n", 0o600)

	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := fstat(f); err != nil { // the trust decision readTrusted makes on this fd
		t.Fatal(err)
	}

	// TOCTOU window: after the trust decision, the path is repointed at a different, equally
	// legitimate-looking file (the classic swap attack; an unlink+recreate is equivalent).
	evil := writeFile(t, dir, "evil.yaml", "evil\n", 0o600)
	if err := os.Rename(evil, path); err != nil {
		t.Fatal(err)
	}

	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "trusted\n" {
		t.Fatalf("read %q after the swap; the fd was already open, so the swap must not be visible", got)
	}
}

// TestReadTrustedInPlaceMutationVisible is the boundary the file check does NOT defend, named so it
// is never mistaken for one it does. R20's fstat pins identity (owner, mode, inode), not
// content. A write to the SAME inode after the stat — as opposed to a swap to a different inode — is
// visible on the next read, because it is still the one fd, the one file, whose bytes changed. This
// is not a hole: a 0600 (or non-group/other-writable) file that already passed the owner check can
// only be rewritten in place by its own owner or root, so nothing untrusted gets a vote either way.
func TestReadTrustedInPlaceMutationVisible(t *testing.T) {
	dir := trustedDir(t)
	path := writeFile(t, dir, "c.yaml", "before\n", 0o600)

	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := fstat(f); err != nil {
		t.Fatal(err)
	}

	// In-place rewrite of the same inode (O_TRUNC on the existing path, not a rename): the already
	// open fd keeps referring to this same file, so its new bytes are what the next read sees.
	if err := os.WriteFile(path, []byte("after\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "after\n" {
		t.Fatalf("read %q; an in-place rewrite of the open file's own inode should be visible", got)
	}
}

// TestCheckDirectoryAcrossRename pins which directory R20 judges: the one the open file is in
// right now, named from the descriptor itself, not whatever the caller's path string resolves to on a
// second walk. Rename the parent away and leave a trusted-looking impostor at the vacated name, and the
// check must still report the real (renamed, now world-writable) parent. The companion case — a directory
// that passes the rule but is not the one holding the file at all — is TestCheckDirectoryRejectsReplacedFile.
// identity-config.md E33 (the rename half): the directory judged is the one holding the descriptor.
func TestCheckDirectoryAcrossRename(t *testing.T) {
	uid := os.Getuid()
	real := trustedDir(t)
	path := writeFile(t, real, "c.yaml", "trusted\n", 0o600)

	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	moved := real + ".moved"
	if err := os.Rename(real, moved); err != nil { // f's true parent, now living under a new name
		t.Fatal(err)
	}
	if err := os.Chmod(moved, 0o777); err != nil { // make the TRUE parent untrusted
		t.Fatal(err)
	}
	if err := os.Mkdir(real, 0o700); err != nil { // a trusted-looking impostor at the vacated name
		t.Fatal(err)
	}

	err = checkDirectory(f, path, uid)
	var ue *UntrustedError
	if !errors.As(err, &ue) {
		t.Fatalf("checkDirectory(%q) = %v, want an UntrustedError for the real (renamed) parent", path, err)
	}
	if !strings.Contains(ue.Reason, "directory") {
		t.Errorf("reason %q does not name the directory", ue.Reason)
	}
	if ue.Path != moved {
		t.Errorf("UntrustedError names %q, want the true parent %q (not the impostor left at the old name)", ue.Path, moved)
	}
}

// TestCheckDirectoryRejectsReplacedFile pins the bind between the two halves of R20: the directory the
// rule passes must be the directory the checked file actually lives in. checkDirectory names the
// directory from the open descriptor and then has to open that name, so an ancestor renamed away in
// between leaves it judging a directory the file is not in; the degenerate, deterministic form of that
// swap is the one below (the path is repointed at another file, so the inode behind f no longer has a
// containing directory at all). Before the bind check, the trusted 0700 directory still passed and the
// layer was honoured; now the mismatch is caught and the layer refused, fail-closed.
// identity-config.md E33: a directory that does not hold the open inode is refused, fail-closed.
func TestCheckDirectoryRejectsReplacedFile(t *testing.T) {
	dir := trustedDir(t)
	path := writeFile(t, dir, "c.yaml", "trusted\n", 0o600)

	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	evil := writeFile(t, dir, "evil.yaml", "evil\n", 0o600)
	if err := os.Rename(evil, path); err != nil { // the classic swap: same name, different inode
		t.Fatal(err)
	}

	err = checkDirectory(f, path, os.Getuid())
	var ue *UntrustedError
	if !errors.As(err, &ue) || !errors.Is(err, ErrUntrusted) {
		t.Fatalf("checkDirectory after a swap = %v, want an *UntrustedError: the directory checked no longer contains the file the bytes come from", err)
	}
}

// TestProcFDDotDotOnFileIsENOTDIR pins the kernel behaviour that rules out the one construction that
// would let checkDirectory reach the parent with no second path resolution at all. "/proc/self/fd/<n>/.."
// works only when fd n is itself a directory; R20 has already established that a layer fd is S_ISREG, and
// Linux refuses to walk ".." under a non-directory. An earlier revision used it anyway with the path walk
// as the "procfs unavailable" fallback, so the fallback ran on every call while the comment claimed the
// race was gone. If this assertion ever fails the construction became viable and checkDirectory could use
// it; while it holds, only checkContains' inode bind closes that window.
func TestProcFDDotDotOnFileIsENOTDIR(t *testing.T) {
	dir := trustedDir(t)
	path := writeFile(t, dir, "c.yaml", "trusted\n", 0o600)

	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	d, err := os.OpenFile("/proc/self/fd/"+strconv.Itoa(int(f.Fd()))+"/..",
		os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK, 0)
	if err == nil {
		_ = d.Close()
		t.Fatal("\"..\" under a regular file's procfs link opened; checkDirectory may now step to the parent fd-relatively")
	}
	if !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("err = %v, want ENOTDIR", err)
	}
}

// identity-config.md E13: a $TEGO_CONFIG path that does not exist is refused under run and warned
// under compile/doctor, never skipped silently; an absent etc layer stays optional.
func TestLoadSourcesMissingEnvFile(t *testing.T) {
	dir := trustedDir(t)
	missing := filepath.Join(dir, "nope.yaml")
	if _, _, err := LoadSources(Sources{EnvFile: missing}, "", os.Getuid(), TrustAbort); !errors.Is(err, ErrInvalid) {
		t.Fatalf("abort: err=%v, want ErrInvalid", err)
	}
	m, diags, err := LoadSources(Sources{EnvFile: missing}, "", os.Getuid(), TrustWarn)
	if err != nil || m == nil {
		t.Fatalf("warn: err=%v", err)
	}
	found := false
	for _, d := range diags {
		if d.File == missing && d.Severity == SeverityWarning {
			found = true
		}
	}
	if !found {
		t.Errorf("warn: no warning naming the missing file: %v", diags)
	}
	if _, _, err := LoadSources(Sources{Etc: missing}, "", os.Getuid(), TrustAbort); err != nil {
		t.Errorf("an absent etc layer must stay optional: %v", err)
	}
}

// A file the trust rule admits has one name (ADR 0059): R10 keeps every write entry off the names tego reads a
// policy file by, and no write entry is compared with a hard link's other name, so a run whose write entry holds that
// name could rewrite the file every later run loads. readTrusted (the layers, the price table) and CheckTrusted (the
// profiles, the registry's entries) refuse it, and CheckOneName (a contract given by its path) does; its one name back,
// the file is trusted again.
func TestATrustedFileHasOneName(t *testing.T) {
	uid := os.Getuid()
	dir := trustedDir(t)
	path := writeFile(t, dir, "c.yaml", "version: 0\n", 0o644)
	other := filepath.Join(t.TempDir(), "other.yaml")
	if err := os.Link(path, other); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	_, _, rerr := readTrusted(path, uid)
	_, _, lerr := LoadSources(Sources{User: path}, "", uid, TrustAbort)
	for what, err := range map[string]error{
		"readTrusted": rerr, "LoadSources": lerr, "CheckTrusted": CheckTrusted(f, path, uid), "CheckOneName": CheckOneName(f, path, uid),
	} {
		var ue *UntrustedError
		if !errors.As(err, &ue) || !errors.Is(err, ErrUntrusted) || ue.Names != 2 || !strings.Contains(ue.Reason, "2 names") ||
			!strings.Contains(ue.Fix(), "hard link") {
			t.Errorf("%s: err = %v, want *UntrustedError naming 2 names and the hard-link fix", what, err)
		}
	}
	if err := os.Remove(other); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readTrusted(path, uid); err != nil {
		t.Errorf("readTrusted with one name: %v", err)
	}
	if err := CheckOneName(f, path, uid); err != nil {
		t.Errorf("CheckOneName with one name: %v", err)
	}
}

// Machine.Layers names every layer file a Load consulted, in order, as given, whether a file was there or not and
// whether it was applied or skipped: each is a place a later Load reads, which R10 keeps every write entry off (ADR
// 0059). A layer the Sources leave empty is no place.
func TestLoadSourcesNamesEveryLayerPlace(t *testing.T) {
	dir := trustedDir(t)
	absent := filepath.Join(dir, "absent.yaml")
	user := writeFile(t, dir, "user.yaml", "stop_grace: 3s\n", 0o600)
	env := writeFile(t, dir, "env.yaml", "limits:\n  pids: 10\n", 0o600)
	lax := writeFile(t, dir, "lax.yaml", "stop_grace: 4s\n", 0o664)
	m, _, err := LoadSources(Sources{Etc: absent, User: user, EnvFile: env}, "", os.Getuid(), TrustAbort)
	if err != nil || !slices.Equal(m.Layers, []string{absent, user, env}) {
		t.Fatalf("layers = %v, err = %v, want [%s %s %s]", m.Layers, err, absent, user, env)
	}
	m, _, err = LoadSources(Sources{User: lax, EnvFile: env}, "", os.Getuid(), TrustWarn)
	if err != nil || !slices.Equal(m.Layers, []string{lax, env}) {
		t.Fatalf("warn: layers = %v, err = %v, want [%s %s]", m.Layers, err, lax, env)
	}
	if b := Builtin(); len(b.Layers) != 0 {
		t.Fatalf("the built-in layer names files: %v", b.Layers)
	}
}

// A relative layer path ($TEGO_CONFIG is the one a person may write relative) is refused, as a relative path
// setting is (parser.path): it names another file in every working directory, and R10 keeps a run's writes off only
// the one its own Load read, so a run in one directory could plant machine.yaml in another, where the next run started
// with the same environment loaded it (ADR 0059). tego run refuses it as an invalid layer and compile
// and doctor skip it with a warning, never reading it. An absolute layer is named as written and never cleaned: with
// a link before a "..", filepath.Clean names another file than the one the open read.
func TestLoadSourcesRefusesARelativeLayer(t *testing.T) {
	dir := trustedDir(t)
	for _, d := range []string{"cfg", "real", filepath.Join("real", "sub")} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(dir, "cfg"), "env.yaml", "stop_grace: 3s\n", 0o600)
	writeFile(t, filepath.Join(dir, "real"), "user.yaml", "stop_grace: 4s\n", 0o600)
	if err := os.Symlink(filepath.Join(dir, "real", "sub"), filepath.Join(dir, "lnk")); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	for _, env := range []string{"cfg/env.yaml", "./cfg/env.yaml", "lnk/../user.yaml", "absent.yaml"} {
		m, ds, err := LoadSources(Sources{EnvFile: env}, "", os.Getuid(), TrustAbort)
		if !errors.Is(err, ErrInvalid) || m != nil || !HasErrors(ds) || !strings.Contains(ds[len(ds)-1].String(), "not an absolute path") {
			t.Errorf("run's Load of $TEGO_CONFIG=%s: m %v, err %v, diagnostics %v; want refused as relative", env, m, err, ds)
		}
		m, ds, err = LoadSources(Sources{EnvFile: env}, "", os.Getuid(), TrustWarn)
		if err != nil || m == nil || len(m.Layers) != 0 || m.StopGrace.Value == 3*time.Second || m.StopGrace.Value == 4*time.Second ||
			HasErrors(ds) || len(ds) == 0 || ds[len(ds)-1].Code != CodeInvalid {
			t.Errorf("compile's Load of $TEGO_CONFIG=%s: m %+v, err %v, diagnostics %v; want the layer skipped with a warning", env, m, err, ds)
		}
	}
	m, _, err := LoadSources(Sources{User: dir + "/lnk/../user.yaml", EnvFile: dir + "/cfg/../cfg/env.yaml"}, "", os.Getuid(), TrustAbort)
	if want := []string{dir + "/lnk/../user.yaml", dir + "/cfg/../cfg/env.yaml"}; err != nil || !slices.Equal(m.Layers, want) || m.StopGrace.Value != 3*time.Second {
		t.Fatalf("absolute layers = %v, err = %v, want %v", m.Layers, err, want)
	}
}

// A layer whose path walks through procfs names a file relative to the process that opens it, as a relative layer
// does: /proc/self/cwd/machine.yaml is <cwd>/machine.yaml in every working directory, so it is refused unread the
// same way. So is every spelling the kernel's walk takes there: /proc/thread-self, a link to
// /proc/self/cwd, /dev/fd's link into /proc/self/fd followed by "..".
func TestLoadSourcesRefusesALayerThroughProcfs(t *testing.T) {
	dir := trustedDir(t)
	writeFile(t, dir, "env.yaml", "stop_grace: 3s\n", 0o600)
	if err := os.Symlink("/proc/self/cwd", filepath.Join(dir, "here")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/proc/self/fd", filepath.Join(dir, "fds")); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	for _, env := range []string{"/proc/self/cwd/env.yaml", "/proc/thread-self/cwd/env.yaml", dir + "/here/env.yaml",
		dir + "/fds/../cwd/env.yaml", "/proc/self/cwd/absent.yaml"} {
		m, ds, err := LoadSources(Sources{EnvFile: env}, "", os.Getuid(), TrustAbort)
		if !errors.Is(err, ErrInvalid) || m != nil || !HasErrors(ds) || !strings.Contains(ds[len(ds)-1].String(), "procfs") {
			t.Errorf("run's Load of $TEGO_CONFIG=%s: m %v, err %v, diagnostics %v; want refused as reaching procfs", env, m, err, ds)
		}
		m, ds, err = LoadSources(Sources{EnvFile: env}, "", os.Getuid(), TrustWarn)
		if err != nil || m == nil || len(m.Layers) != 0 || m.StopGrace.Value == 3*time.Second ||
			HasErrors(ds) || len(ds) == 0 || ds[len(ds)-1].Code != CodeInvalid {
			t.Errorf("compile's Load of $TEGO_CONFIG=%s: m %+v, err %v, diagnostics %v; want the layer skipped with a warning", env, m, err, ds)
		}
	}
	_, ds, err := LoadSources(Sources{User: "/proc/self/cwd/env.yaml"}, "", os.Getuid(), TrustAbort)
	if !errors.Is(err, ErrInvalid) || len(ds) == 0 || !strings.Contains(ds[len(ds)-1].Fix, "passwd") {
		t.Errorf("a user layer under a home through procfs: err %v, diagnostics %v; want refused, the fix naming the passwd home", err, ds)
	}
}

// manyNamesReason spares only a file no run of the invoking user could write through any name: owned by someone
// else, not group- or other-writable, and the invoking user not root (a root-owned store that deduplicates by hard
// links, as Nix's does, is one). A directory's link count counts its subdirectories, never its names.
func TestManyNamesReasonSparesAFileNoRunCouldWrite(t *testing.T) {
	const me = 1000
	reg, dir := uint32(syscall.S_IFREG), uint32(syscall.S_IFDIR)
	for _, c := range []struct {
		what        string
		mode        uint32
		nlink       uint64
		owner       uint32
		invoking    int
		wantRefused bool
	}{
		{"one name", reg | 0o644, 1, me, me, false},
		{"two names, mine", reg | 0o644, 2, me, me, true},
		{"two names, mine and read-only", reg | 0o444, 2, me, me, true}, // the owner can chmod it back
		{"two names, root's", reg | 0o644, 2, 0, me, false},
		{"two names, another user's", reg | 0o444, 3, me + 1, me, false},
		{"two names, root's and group-writable", reg | 0o664, 2, 0, me, true},
		{"two names, root's and other-writable", reg | 0o646, 2, 0, me, true},
		{"two names, root's, invoked by root", reg | 0o644, 2, 0, 0, true},
		{"a directory", dir | 0o755, 5, me, me, false},
	} {
		st := &syscall.Stat_t{Mode: c.mode, Uid: c.owner}
		setCount(&st.Nlink, c.nlink)
		if got := manyNamesReason(st, c.invoking); (got != "") != c.wantRefused {
			t.Errorf("%s: reason %q, want refused=%v", c.what, got, c.wantRefused)
		}
	}
}

// setCount sets a Stat_t count field whatever its width: Nlink is uint64 on amd64 and uint32 on arm64.
func setCount[T ~uint32 | ~uint64](p *T, n uint64) { *p = T(n) }
