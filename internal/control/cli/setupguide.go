// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"runtime/debug"

	"github.com/attention-span-ai/tego/internal/buildinfo"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// guideInputs is what the Overview's guide is computed from (internal/guide, ADR 0142), for the user serve runs as:
// the machine config, the ledger root it serves and the chain anchor it checks runs against, no working folder and
// no shell (the dashboard has neither), this boot, and the build of the tego a person types (tegoBinary), with the
// version and commit of this release, which a matched tego pins. A stored check is used only when its build is that
// one: a tego of another release, or none found, leaves the check step "not checked since this machine started".
// It is read on every Overview request, and the page computes the guide again when the build changes, so a tego
// reinstalled while the dashboard runs shows at once as another build.
func guideInputs(m *config.Machine, root, anchor string) func() guide.Inputs {
	s := buildinfo.Resolve(debug.ReadBuildInfo)
	uid, _ := config.InvokingUID()
	home := ""
	if m != nil {
		home = m.Home
	}
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return func() guide.Inputs {
		path := os.Getenv("PATH")
		exe := tegoBinary(path, selfExecutable)
		in := guide.Inputs{Machine: m, Home: home, UID: uid, LedgerRoot: root, Anchor: anchor, Version: s.Version,
			Commit: s.Commit, Host: guide.ThisHost(), PATH: path, Exe: exe, RuntimeDirs: config.RuntimeDirBases()}
		if exe != "" {
			in.Build = guide.BuildIDOf(exe, s.Version, s.Commit)
		}
		return in
	}
}

// selfExecutable is os.Executable; a variable for tests.
var selfExecutable = os.Executable

// tegoBinary is the tego a person gets by typing tego: the first regular, executable file named tego in an absolute
// folder of path; else the tego beside this tego-control, when this process runs from its file (after a handoff it
// runs from a sealed copy, which names no folder); else "". It starts nothing and follows links as exec does.
func tegoBinary(path string, self func() (string, error)) string {
	for _, dir := range filepath.SplitList(path) {
		if !filepath.IsAbs(dir) {
			continue
		}
		if p := filepath.Join(dir, "tego"); runnable(p) {
			return p
		}
	}
	if exe, err := self(); err == nil && filepath.IsAbs(exe) {
		if p := filepath.Join(filepath.Dir(exe), "tego"); runnable(p) {
			return p
		}
	}
	return ""
}

// runnable reports whether p is a regular file someone may execute.
func runnable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}
