// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Name is a contract's harness: value, the agent harness the launcher provisions for (agent-contract.md R27).
type Name string

const (
	// Auto is the default: the harness is detected from the resolved command's basename (Detect).
	Auto Name = "auto"
	// ClaudeCode is Anthropic's Claude Code CLI.
	ClaudeCode Name = "claude-code"
	// Codex is OpenAI's Codex CLI.
	Codex Name = "codex"
	// Generic is any other agent: it is told of the reason file by TEGO_REASON only.
	Generic Name = "generic"
	// None provisions nothing: the run is what it was before the key existed.
	None Name = "none"
)

// Names is every value the key takes, in the order the schema and the docs list them.
func Names() []Name { return []Name{Auto, ClaudeCode, Codex, Generic, None} }

// Parse reads a harness: value; "" (the key absent) is Auto.
func Parse(s string) (Name, error) {
	if s == "" {
		return Auto, nil
	}
	for _, n := range Names() {
		if string(n) == s {
			return n, nil
		}
	}
	return "", fmt.Errorf("harness %q is not auto, claude-code, codex, generic or none", s)
}

// Detect is the harness a command's basename names: claude is Claude Code, codex is Codex, anything else is
// generic. It looks at the name alone, never at the file: a wrapper script named claude is detected as Claude Code,
// which is what its user asked for by naming it so, and a contract that means otherwise writes harness: generic.
func Detect(basename string) Name {
	switch basename {
	case "claude":
		return ClaudeCode
	case "codex":
		return Codex
	}
	return Generic
}

// Resolve is the harness a run of command0 (its resolved argv[0]) gets: n itself, or for Auto (and "") the one
// Detect reads from command0's basename.
func (n Name) Resolve(command0 string) Name {
	if n != Auto && n != "" {
		return n
	}
	return Detect(filepath.Base(command0))
}

// Dir is the directory a provisioned File is made in.
type Dir uint8

const (
	// Runtime is the run's runtime directory, $XDG_RUNTIME_DIR/tego/<run id>: the file is made 0444, and the agent
	// cannot write there.
	Runtime Dir = iota
	// CodexHome is the run's own CODEX_HOME, which the launcher made (agent-contract.md R10a): the file is made 0600,
	// and only when the run has that directory.
	CodexHome
)

// String names the directory as compile and the docs do.
func (d Dir) String() string {
	switch d {
	case Runtime:
		return "runtime"
	case CodexHome:
		return "codex_home"
	}
	return fmt.Sprintf("dir(%d)", d)
}

// Run is what the launcher tells a provisioner about one run, before the agent exists.
type Run struct {
	// RunID is the run's id.
	RunID string
	// Tier is the enforcement tier the run uses.
	Tier string
	// Root says the launcher runs as euid 0.
	Root bool
	// RuntimeDir is the run's runtime directory, where Runtime files are made.
	RuntimeDir string
	// ReasonFile is the run's readable last-refusal.json, the file TEGO_REASON names; "" when there is none.
	ReasonFile string
	// StateDir is hook-state/, a sibling of the reason file and the one directory there the agent may write.
	StateDir string
	// CodexHome is the run's own CODEX_HOME, "" when the run has none (then no CodexHome file can be made).
	CodexHome string
	// TegoExe is the tego binary's absolute path, the program a hook execs.
	TegoExe string
	// Argv is the agent's argv as the launcher will exec it, argv[0] resolved.
	Argv []string
	// Env is the agent's environment as the launcher builds it, before the provision's additions.
	Env []string
	// AllowList says the run's images are restricted (an exec: section with an allow key, ADR 0048 (1)).
	AllowList bool
	// ReadUserFile reads one of the user's own files for the provisioner (a settings file to merge), as the
	// launcher may: refused under a deny_read entry of the run, at euid 0, for anything but a regular file, and above
	// MaxUserFile bytes. Never nil.
	ReadUserFile func(path string) ([]byte, error)
}

// MaxUserFile bounds what Run.ReadUserFile returns.
const MaxUserFile = 2 << 20

// File is one file the launcher makes for the harness.
type File struct {
	// Dir is the directory it is made in.
	Dir Dir
	// Name is one path element: no "/", no NUL, not "." or "..".
	Name string
	// Bytes is its content.
	Bytes []byte
}

// Hook is the program the harness will exec on its events: Argv is its exact full argv, the executable first. The
// launcher provisions nothing unless the run admits exactly this argv, by its exec rules or, under an allow-list
// contract, by the launcher's grant of it when Argv[0] is Run.TegoExe (ADR 0064), so a hook is never refused on every
// tool call.
type Hook struct {
	Argv []string
}

// Provision is what a provisioner returns for one run. The zero value changes nothing.
type Provision struct {
	// Argv is the agent's whole new argv; nil keeps the launcher's. Its argv[0] must be Run.Argv[0].
	Argv []string
	// Env holds additions to the agent's environment, each NAME=value with a TEGO_ name.
	Env []string
	// Files are made by the launcher, each in its Dir, exclusively and without following a link.
	Files []File
	// Hook is the program the harness execs, nil for none.
	Hook *Hook
	// Summary is one line saying what was provisioned, for compile and the own log.
	Summary string
}

// EnvPrefix is the prefix every Provision.Env name carries.
const EnvPrefix = "TEGO_"

// CheckName refuses a File.Name that is not exactly one path element.
func CheckName(name string) error {
	switch {
	case name == "", name == ".", name == "..":
		return fmt.Errorf("harness file name %q is not a file name", name)
	case strings.ContainsAny(name, "/\x00"):
		return fmt.Errorf("harness file name %q holds a '/' or a NUL", name)
	}
	return nil
}

// CheckEnv refuses a Provision.Env entry that is not NAME=value with a TEGO_ name of upper-case letters, digits and
// underscores.
func CheckEnv(kv string) error {
	name, _, ok := strings.Cut(kv, "=")
	if !ok || !strings.HasPrefix(name, EnvPrefix) || len(name) == len(EnvPrefix) {
		return fmt.Errorf("harness environment entry %q is not %sNAME=value", kv, EnvPrefix)
	}
	for _, c := range name {
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return fmt.Errorf("harness environment name %q holds %q", name, c)
		}
	}
	return nil
}

// Check refuses a provision the launcher must not make for run: a file name that is not one path element or that
// two files share in one directory, a CodexHome file for a run with no CODEX_HOME, an environment entry CheckEnv
// refuses or a name given twice, an Argv whose argv[0] is not the run's, and a Hook with an empty argv. It reads
// nothing; whether a name already exists is the launcher's O_EXCL to find.
func (p Provision) Check(run Run) error {
	seen := map[[2]string]bool{}
	for _, f := range p.Files {
		if err := CheckName(f.Name); err != nil {
			return err
		}
		if f.Dir != Runtime && f.Dir != CodexHome {
			return fmt.Errorf("harness file %q names directory %s, which is not runtime or codex_home", f.Name, f.Dir)
		}
		if f.Dir == CodexHome && run.CodexHome == "" {
			return fmt.Errorf("harness file %q is for the run's CODEX_HOME, and this run has none", f.Name)
		}
		k := [2]string{f.Dir.String(), f.Name}
		if seen[k] {
			return fmt.Errorf("harness file %q is given twice in %s", f.Name, f.Dir)
		}
		seen[k] = true
	}
	names := map[string]bool{}
	for _, kv := range p.Env {
		if err := CheckEnv(kv); err != nil {
			return err
		}
		name, _, _ := strings.Cut(kv, "=")
		if names[name] {
			return fmt.Errorf("harness environment name %s is given twice", name)
		}
		names[name] = true
	}
	if p.Argv != nil && (len(p.Argv) == 0 || len(run.Argv) == 0 || p.Argv[0] != run.Argv[0]) {
		return fmt.Errorf("harness argv %q does not start with the resolved command %q", p.Argv, first(run.Argv))
	}
	if p.Hook != nil && (len(p.Hook.Argv) == 0 || p.Hook.Argv[0] == "") {
		return fmt.Errorf("harness hook has no argv")
	}
	return nil
}

func first(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	return argv[0]
}
