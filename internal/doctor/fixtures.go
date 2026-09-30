// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// fixtureRoot is where the probes' fixtures (D8's marked file, the plane probe's tree) live: a 0700 directory of
// root's on /run, so a probe's outcome does not follow the invoking environment's $TMPDIR (a read-only, full or
// hard-link-less one would fault the probe for a reason that is not the kernel's). A variable so a test can point
// it elsewhere.
var fixtureRoot = "/run/tego"

// fixtureBase is fixtureRoot made ready, "" (the temporary directory) when it cannot be made.
func fixtureBase() string {
	if err := os.MkdirAll(fixtureRoot, 0o700); err != nil {
		return ""
	}
	return fixtureRoot
}

// fixtureStaleAge is how old a dead probe's fixture directory must be before a later probe sweeps it. A probe
// takes seconds; the age keeps the tree of a live probe whose pid looks free from here (another pid namespace
// sharing /run) out of the sweep.
const fixtureStaleAge = 10 * time.Minute

// makeFixtureDir makes a probe's fixture directory under fixtureBase, named prefix<pid>-<random>, after sweeping
// the ones a killed probe left there. A probe removes its own on return; SIGKILL or the OOM killer skips that, so
// every probe first removes each prefix<pid>… directory whose pid no longer runs and which is older than
// fixtureStaleAge.
func makeFixtureDir(prefix string) (string, error) {
	base := fixtureBase()
	dir := base
	if dir == "" {
		dir = os.TempDir()
	}
	sweepFixtures(dir, prefix, time.Now())
	return os.MkdirTemp(base, prefix+strconv.Itoa(os.Getpid())+"-")
}

// sweepFixtures removes dir's stale prefix<pid>… directories (makeFixtureDir). A name whose pid does not parse
// is left alone; a directory is never followed through a symlink (os.RemoveAll removes a link, not its target).
func sweepFixtures(dir, prefix string, now time.Time) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		rest, ok := strings.CutPrefix(e.Name(), prefix)
		if !ok || !e.IsDir() {
			continue
		}
		digits, _, _ := strings.Cut(rest, "-")
		pid, err := strconv.Atoi(digits)
		if err != nil || pid <= 0 || pid == os.Getpid() || !errors.Is(unix.Kill(pid, 0), unix.ESRCH) {
			continue
		}
		info, err := e.Info()
		if err != nil || now.Sub(info.ModTime()) < fixtureStaleAge {
			continue
		}
		_ = os.RemoveAll(filepath.Join(dir, e.Name()))
	}
}
