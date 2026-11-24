// SPDX-License-Identifier: Apache-2.0

package sig

// Fact is the specific observation that satisfied a rule. It carries no match input.
type Fact string

// Match facts distinguish executable names from the process-controlled argv[0] and comm.
const (
	FactExeName     Fact = "exe-name"
	FactArgv0Name   Fact = "argv0-name"
	FactCommName    Fact = "comm-name"
	FactArgvPattern Fact = "argv-pattern"
	FactPath        Fact = "path"
	FactFileID      Fact = "file-id"
)

// Evidence reports the first fact that satisfies r, in Match's existing order.
// Match remains the guard's selection API; observation callers can discard all input after this call.
func (r Rule) Evidence(f Facts) (Fact, bool) {
	switch {
	case r.Basename != "":
		if base(f.Exe) == r.Basename {
			return FactExeName, true
		}
		if len(f.Argv) > 0 && base(f.Argv[0]) == r.Basename {
			return FactArgv0Name, true
		}
		if len(r.Basename) <= maxComm && f.Comm == r.Basename {
			return FactCommName, true
		}
	case r.Path != "":
		if f.Exe == r.Path {
			return FactPath, true
		}
	case r.File != (FileID{}):
		if f.File == r.File {
			return FactFileID, true
		}
	case len(r.Argv) > 0:
		if matchArgv(r.Argv, f) {
			return FactArgvPattern, true
		}
	}
	return "", false
}
