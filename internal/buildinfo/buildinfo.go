// SPDX-License-Identifier: Apache-2.0

// Package buildinfo is the version, commit and date both binaries print (tego version, tego-control version;
// docs/VERSIONING.md §1), from one set of link-time values, so a matched pair says the same.
//
// Imports: the standard library only. Both binaries link it.
package buildinfo

import (
	"runtime/debug"
	"strings"
)

// Set by goreleaser's ldflags on tagged builds (docs/VERSIONING.md §1), for both binaries alike:
// -X github.com/attention-span-ai/tego/internal/buildinfo.version=v0.1.0 (commit, date likewise). Link-time constants:
// nothing assigns them at run time.
var (
	version string
	commit  string
	date    string
)

// None is the rendering of a field this build has no value for.
const None = "none"

// Stamp is the version, the commit and the commit's date of this build.
type Stamp struct {
	Version string
	Commit  string
	Date    string
}

// Resolve assembles the stamp from the ldflags values, falling back to debug.ReadBuildInfo (read is injectable for
// tests): Main.Version from the VCS tag ("dev" for "(devel)" or empty), "+dirty" when vcs.modified, vcs.revision
// and vcs.time for commit and date. A field with no value is None ("dev" for the version).
func Resolve(read func() (*debug.BuildInfo, bool)) Stamp {
	s := Stamp{Version: version, Commit: commit, Date: date}
	if bi, ok := read(); ok && bi != nil {
		var rev, tm, dirty string
		for _, kv := range bi.Settings {
			switch kv.Key {
			case "vcs.revision":
				rev = kv.Value
			case "vcs.time":
				tm = kv.Value
			case "vcs.modified":
				dirty = kv.Value
			}
		}
		if s.Version == "" {
			v := bi.Main.Version
			if v == "" || v == "(devel)" {
				v = "dev"
			}
			// Go >= 1.24 already carries "+dirty" in Main.Version when the tree is modified; only add it when the
			// toolchain did not.
			if dirty == "true" && !strings.HasSuffix(v, "+dirty") {
				v += "+dirty"
			}
			s.Version = v
		}
		if s.Commit == "" {
			s.Commit = rev
		}
		if s.Date == "" {
			s.Date = tm
		}
	}
	if s.Version == "" {
		s.Version = "dev"
	}
	if s.Commit == "" {
		s.Commit = None
	}
	if s.Date == "" {
		s.Date = None
	}
	return s
}
