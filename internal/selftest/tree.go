// SPDX-License-Identifier: Apache-2.0

package selftest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// The temporary tree (one os.MkdirTemp directory, mode 0700, removed when tego test ends):
//
//	<root>/tego/            tego's own directory for these runs: the machine config layer and the ledger
//	<root>/contract.yaml    the embedded contract, outside every write entry
//	<root>/work/            the workdir __check accepts
//	    .tego-selftest      the marker
//	    home/.ssh/id_ed25519, home/.env   decoy secrets with fake content
//	    project/README.md, project/out/   the project; out/ is its one writable folder
//	    outside.txt         the write target (absent until the baseline writes it)
//	    bin/true            a copy of /bin/true (or the true on $PATH), which the contract does not list
//	    port                the port of the loopback listener tego test owns
//
// The ledger sits in a sibling of the workdir, never in it: tego refuses a write entry inside its own directory,
// and the run would otherwise be able to read every run's ledger.
const (
	rootPattern = "tego-selftest-"
	workName    = "work"
	markerName  = ".tego-selftest"
	markerText  = "tego-selftest v1: a temporary tree tego test made; it is removed when tego test ends\n"
)

// layout names the workdir's files.
type layout struct{ work string }

func (t layout) key() string     { return filepath.Join(t.work, "home", ".ssh", "id_ed25519") }
func (t layout) env() string     { return filepath.Join(t.work, "home", ".env") }
func (t layout) project() string { return filepath.Join(t.work, "project") }
func (t layout) out() string     { return filepath.Join(t.work, "project", "out") + "/" }
func (t layout) outside() string { return filepath.Join(t.work, "outside.txt") }
func (t layout) program() string { return filepath.Join(t.work, "bin", "true") }
func (t layout) portFile() string {
	return filepath.Join(t.work, "port")
}

// port is the listener's port, from the workdir's port file.
func (t layout) port() (int, error) {
	b, err := readSmall(t.portFile())
	if err != nil {
		return 0, err
	}
	p, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || p <= 0 || p > 65535 {
		return 0, fmt.Errorf("the workdir's port file holds no port")
	}
	return p, nil
}

// errNotATree is a workdir __check refuses: not one tego test made.
var errNotATree = errors.New("not a workdir tego test made")

// openLayout accepts dir only when it is a tree's workdir: an absolute, clean path named work, in a directory named
// tego-selftest-*, a real directory (no link) owned by this user, holding the marker with its exact text, whose
// home/, home/.ssh/ and bin/ are real directories owned by this user too. Every path the checks use is fixed below
// it, and every final open refuses a link (O_NOFOLLOW), so no link in a tree someone else laid out leads a check off
// it.
func openLayout(dir string) (layout, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || filepath.Base(dir) != workName ||
		!strings.HasPrefix(filepath.Base(filepath.Dir(dir)), rootPattern) {
		return layout{}, fmt.Errorf("%s: %w", dir, errNotATree)
	}
	if err := ownDir(dir); err != nil {
		return layout{}, err
	}
	b, err := readSmall(filepath.Join(dir, markerName))
	if err != nil || !bytes.Equal(b, []byte(markerText)) {
		return layout{}, fmt.Errorf("%s: %w (no marker)", dir, errNotATree)
	}
	t := layout{work: dir}
	for _, d := range []string{filepath.Dir(filepath.Dir(t.key())), filepath.Dir(t.key()), filepath.Dir(t.program())} {
		if err := ownDir(d); err != nil {
			return layout{}, err
		}
	}
	return t, nil
}

// ownDir is nil when dir is a real directory (not a link) owned by this user, errNotATree otherwise.
func ownDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() {
		return fmt.Errorf("%s: %w", dir, errNotATree)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s: %w (not yours)", dir, errNotATree)
	}
	return nil
}

// readSmall reads a small file without following a final link.
func readSmall(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only: a close error loses nothing
	return io.ReadAll(io.LimitReader(f, 4096))
}

// tree is the temporary directory of one tego test.
type tree struct {
	root string
	layout
}

func (t tree) ledger() string   { return filepath.Join(t.root, "tego", "ledger") }
func (t tree) config() string   { return filepath.Join(t.root, "tego", "tego.yaml") }
func (t tree) contract() string { return filepath.Join(t.root, "contract.yaml") }

// newTree makes the tree under parent ("" is the system temp directory) with its decoys. The root's links are
// resolved, so the paths the ledger records are the paths the report names.
func newTree(parent string) (tree, error) {
	root, err := os.MkdirTemp(parent, rootPattern)
	if err != nil {
		return tree{}, err
	}
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	t := tree{root: root, layout: layout{work: filepath.Join(root, workName)}}
	if err := t.populate(); err != nil {
		_ = os.RemoveAll(root) // the populate error is the one reported
		return tree{}, err
	}
	return t, nil
}

// populate writes the decoys.
func (t tree) populate() error {
	for _, d := range []string{t.ledger(), filepath.Dir(t.key()), t.out(), filepath.Dir(t.program())} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	files := []struct {
		path string
		data string
		mode os.FileMode
	}{
		{filepath.Join(t.work, markerName), markerText, 0o600},
		{t.key(), "-----BEGIN FAKE TEGO SELFTEST KEY-----\nnot a key: decoy content for tego test\n-----END FAKE TEGO SELFTEST KEY-----\n", 0o600},
		{t.env(), "TEGO_SELFTEST_DECOY_TOKEN=not-a-secret\n", 0o600},
		{filepath.Join(t.project(), "README.md"), "A throwaway project tego test made.\n", 0o600},
	}
	for _, f := range files {
		if err := os.WriteFile(f.path, []byte(f.data), f.mode); err != nil {
			return err
		}
	}
	return copyFile(trueProgram(), t.program(), 0o700)
}

// trueProgram is the `true` program to copy: /bin/true, or on a system without it (NixOS) the first regular
// executable named true on $PATH; /bin/true again when there is none, so the error names the usual place. os/exec's
// LookPath is not used: the package is banned outside tests (ADR 0021 (3)).
func trueProgram() string {
	const usual = "/bin/true"
	for _, dir := range append([]string{filepath.Dir(usual)}, filepath.SplitList(os.Getenv("PATH"))...) {
		if !filepath.IsAbs(dir) {
			continue // a relative PATH entry names another program in every directory
		}
		p := filepath.Join(dir, "true")
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return p
		}
	}
	return usual
}

// writePort records the listener's port for the checks.
func (t tree) writePort(port int) error {
	return os.WriteFile(t.portFile(), []byte(strconv.Itoa(port)+"\n"), 0o600)
}

// copyFile copies src to a new file dst with mode.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }() // read-only: a close error loses nothing
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close() // the copy error is the one reported
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, mode) // the umask narrows OpenFile's mode
}
