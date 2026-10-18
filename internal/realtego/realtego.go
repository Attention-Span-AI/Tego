// SPDX-License-Identifier: Apache-2.0

// Package realtego names the ~/.tego directories of the accounts a process could reach through the passwd
// database (and through $HOME for an account it names no home for), and the runtime parents
// (<XDG_RUNTIME_DIR>/tego) where those accounts' runs keep their private directories. It is for the code that keeps a test or a test
// build away from them: internal/testutil's guards and the tegotesthooks build of internal/cli (identity-config.md
// R27). A product build imports nothing of it.
package realtego

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// tegoDir is the directory under a passwd home that tego keeps its ledger root, chain anchor, own log and
// per-user config in.
const tegoDir = ".tego"

// Dirs are the ~/.tego directories of the accounts the process could reach through the passwd database: the
// effective uid's and, under sudo, SUDO_UID's. tego resolves its home the same way (pkg/spec/config Resolve,
// through config.LookupPasswd, which never takes $HOME, not even where os/user's pure-Go LookupId would for the
// process's own uid with $USER set), which is why setting $HOME in a test isolates nothing. When one of those
// accounts has no passwd home (a containerized uid, or an LDAP/SSSD one that a CGO_ENABLED=0 build cannot look up),
// Dirs also holds $HOME/.tego as $HOME is when it is called, whatever $USER says: an unprivileged tego then keeps
// its ledger root, anchor and own log there (internal/runtime ledgerRoot, internal/cli ownLogHome), so leaving it
// out would leave the guards watching and refusing nothing on such an account. A relative or empty $HOME adds
// nothing.
func Dirs() []string {
	return dirsOf(uidsOf(os.Geteuid(), os.Getenv("SUDO_UID")), lookupHome, os.Getenv("HOME"))
}

// lookupHome is uid's passwd home, as config.Resolve reads it (config.LookupPasswd, never $HOME).
func lookupHome(uid string) (string, error) {
	n, err := strconv.Atoi(uid)
	if err != nil {
		return "", err
	}
	u, err := config.LookupPasswd(n)
	if err != nil {
		return "", err
	}
	return u.HomeDir, nil
}

// dirsOf is Dirs over explicit uids, a passwd lookup and $HOME's value. lookup is the passwd database alone
// (lookupHome), so a uid it names no home for is "unnamed" and brings in $HOME here, and only here.
func dirsOf(uids []string, lookup func(uid string) (string, error), home string) []string {
	var dirs []string
	add := func(h string) {
		if d := filepath.Join(h, tegoDir); !slices.Contains(dirs, d) {
			dirs = append(dirs, d)
		}
	}
	unnamed := false
	for _, uid := range uids {
		h, err := lookup(uid)
		if err != nil || h == "" || !filepath.IsAbs(h) {
			unnamed = true
			continue
		}
		add(h)
	}
	if unnamed && filepath.IsAbs(home) {
		add(home)
	}
	return dirs
}

// Under reports whether path is one of dirs or inside one, by its cleaned spelling and by its symbolic links
// resolved (for the longest prefix that exists), so a link into a real ~/.tego is found too. A relative path is the
// one it names from the working directory, which is where the code that uses it will look (a relative
// TEGO_TEST_CHAIN_ANCHOR of a process started in ~/.tego is ~/.tego/chain.log).
func Under(path string, dirs []string) bool {
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	var ds []string
	for _, d := range dirs {
		ds = append(ds, d, resolved(d))
	}
	for _, p := range []string{filepath.Clean(path), resolved(path)} {
		for _, d := range ds {
			if p == d || strings.HasPrefix(p, d+string(filepath.Separator)) {
				return true
			}
		}
	}
	return false
}

// resolved is path with the symbolic links of its longest existing prefix resolved.
func resolved(path string) string {
	p := filepath.Clean(path)
	var rest []string
	for {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Join(append([]string{r}, rest...)...)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return filepath.Clean(path)
		}
		rest = append([]string{filepath.Base(p)}, rest...)
		p = parent
	}
}

// UnderReal reports whether path is one of Dirs or inside one.
func UnderReal(path string) bool { return Under(path, Dirs()) }

// The runtime parent: tego's directory under an XDG_RUNTIME_DIR, which holds one private directory per run of that
// user (internal/runtime createRuntimeDir), each with a lock file its launcher holds for the run's life. Spelled
// here because a product package imports nothing of this one: internal/runtime's tests hold each to the
// product's own (agent.RuntimeDirName, runtimeLockFile, runtimeDirPending, logindRuntimeRoot).
const (
	RuntimeDirName    = "tego"
	RuntimeLockFile   = ".lock"
	RuntimeDirPending = ".new-" // the prefix of a run's directory made and not yet locked, which no sweep opens
	LogindRoot        = "/run/user"
)

// startXDG and startSudoUID are XDG_RUNTIME_DIR and SUDO_UID as the process started with, taken when this package
// is initialized: before any TestMain points XDG_RUNTIME_DIR at a test's own directory, and the same values in the
// child testutil.GuardedMain re-executes the binary as, which is started with the environment the binary started
// with. Read at call time, they would name the tests' own directory instead of the developer's.
var startXDG, startSudoUID = os.Getenv("XDG_RUNTIME_DIR"), os.Getenv("SUDO_UID")

// RuntimeDirs are the runtime parents a test process could reach: LogindRoot/<uid>/tego for the effective uid and,
// under sudo, SUDO_UID (where systemd-logind puts each user's XDG_RUNTIME_DIR, and the parent every run of that user
// checks, internal/runtime RuntimeDirBases), and <XDG_RUNTIME_DIR>/tego when the variable the process started with is
// absolute, by its resolved path (Under's resolution: a link to /run/user/<uid> is that directory). A relative or
// empty XDG_RUNTIME_DIR adds nothing: tego makes no directory under it.
func RuntimeDirs() []string {
	return runtimeDirsOf(LogindRoot, uidsOf(os.Geteuid(), startSudoUID), startXDG)
}

// uidsOf is the effective uid and, when it names another, SUDO_UID.
func uidsOf(euid int, sudoUID string) []string {
	uids := []string{strconv.Itoa(euid)}
	if sudoUID != "" && sudoUID != uids[0] {
		uids = append(uids, sudoUID)
	}
	return uids
}

// runtimeDirsOf is RuntimeDirs over an explicit logind root, uids and XDG_RUNTIME_DIR value.
func runtimeDirsOf(root string, uids []string, xdg string) []string {
	var dirs []string
	add := func(d string) {
		if !slices.Contains(dirs, d) {
			dirs = append(dirs, d)
		}
	}
	for _, uid := range uids {
		add(resolved(filepath.Join(root, uid, RuntimeDirName)))
	}
	if filepath.IsAbs(xdg) {
		add(resolved(filepath.Join(xdg, RuntimeDirName)))
	}
	return dirs
}
