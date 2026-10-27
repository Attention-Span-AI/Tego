// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/presets"
)

// CheckEnv is the machine a composed contract is checked against. The caller supplies it, so this package reads no
// machine config and holds no engine code: `tego init` passes the machine config it loaded and the options
// `tego compile` uses (PATH, home, the tiers its binary builds, the chain anchor); a dashboard passes its own.
type CheckEnv struct {
	// Machine is the machine config; nil is config.Builtin().
	Machine *config.Machine
	// Profiles resolves the contract's extends: names; nil is the built-in presets alone, which is all a composed
	// contract names.
	Profiles agent.ProfileSource
	// Options are added to the compile's own (Offline and the project directory as the cwd); WithPATH belongs here,
	// since without it no command basename resolves.
	Options []agent.CompileOption
}

// Check loads contract as the agent.yaml in dir and compiles it offline, as `tego compile --offline agent.yaml`
// run from dir does: relative entries resolve against dir, an unresolvable host is a warning. It returns every
// diagnostic, labelled with dir/agent.yaml, sorted as compile prints them; ok is false when any is an error.
// It reads the paths the contract names and writes nothing.
func Check(contract []byte, dir string, env CheckEnv) (diags []agent.Diagnostic, ok bool) {
	label := filepath.Join(dir, ContractFile)
	profiles := env.Profiles
	if profiles == nil {
		profiles = (&agent.ProfileChain{}).WithBuiltin(presets.Source{})
	}
	c, ds, err := agent.LoadBytes(label, contract, profiles)
	if err != nil {
		if !agent.HasErrors(ds) {
			ds = append(ds, agent.Diagnostic{File: label, Code: agent.CodeSchema, Message: err.Error(), Severity: agent.SeverityError})
		}
		return ds, false
	}
	m := env.Machine
	if m == nil {
		m = config.Builtin()
	}
	opts := append([]agent.CompileOption{agent.Offline(), agent.WithCwd(dir)}, env.Options...)
	_, cds, err := agent.Compile(c, m, opts...)
	ds = append(ds, cds...)
	if err != nil && !agent.HasErrors(ds) {
		ds = append(ds, agent.Diagnostic{File: label, Code: agent.CodeSchema, Message: err.Error(), Severity: agent.SeverityError})
	}
	return ds, !agent.HasErrors(ds)
}

// ContractFile is the file name init writes the contract to, in the project directory.
const ContractFile = "agent.yaml"

// Draft is the whole composition without a write: Compose, then Check of the bytes against env, with the
// diagnostics in the result. It is the entry a "set up a new agent" page calls on every change of its form, since it
// creates nothing: a write folder that does not exist yet (one of MakeDirs) is reported by compile as path-missing
// only when its parent is missing too, and Draft drops exactly those diagnostics, which Create makes untrue. An
// options mistake is a UsageError; a contract that does not compile is not an error but a Result with OK false.
func Draft(o Options, env CheckEnv) (*Result, error) {
	res, err := Compose(o)
	if err != nil {
		return nil, err
	}
	ds, _ := Check(res.Contract, o.Dir, env)
	for _, d := range ds {
		if d.Code == agent.CodePathMissing && res.created(d.Message) {
			continue
		}
		res.Diagnostics = append(res.Diagnostics, d)
	}
	res.OK = !agent.HasErrors(res.Diagnostics)
	return res, nil
}

// created reports whether msg is compile's path-missing message for an fs.write entry naming one of MakeDirs.
func (r *Result) created(msg string) bool {
	for _, v := range r.makeEntries {
		if strings.HasPrefix(msg, fmt.Sprintf("fs.write %q:", v)) {
			return true
		}
	}
	return false
}

// Apply is Create followed by Check of r.Contract in dir, now that every folder it names exists: compile stops
// checking an fs.write entry at its path-missing error, so a check Draft could not make (an entry inside tego's own
// directory, R10) shows up only here. When that compile finds an error, or Create fails, Apply removes the folders
// Create made, the deepest first and only while empty, and returns ok false with the diagnostics: the caller writes
// nothing. made are the folders Create made, relative to dir, in creation order.
func Apply(r *Result, dir string, env CheckEnv) (made []string, diags []agent.Diagnostic, ok bool, err error) {
	made, err = Create(r, dir)
	if err == nil {
		if diags, ok = Check(r.Contract, dir, env); ok {
			return made, diags, true, nil
		}
	}
	for i := len(made) - 1; i >= 0; i-- {
		p := made[i]
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, filepath.FromSlash(p))
		}
		_ = os.Remove(p) // only while empty: os.Remove refuses a folder that holds anything, which stays
	}
	return nil, diags, false, err
}

// Create makes the folders r.MakeDirs names (mode 0755) and returns every folder it made, a missing parent included,
// in creation order (a parent before its child), each relative to dir when inside it. A folder that already exists
// is not returned. It stops at the first failure, returning what it made until then.
func Create(r *Result, dir string) ([]string, error) {
	var made []string
	for _, d := range r.MakeDirs {
		var missing []string
		for p := filepath.Clean(d); !exists(p); p = filepath.Dir(p) {
			missing = append(missing, p)
			if filepath.Dir(p) == p {
				break
			}
		}
		for i := len(missing) - 1; i >= 0; i-- {
			p := missing[i]
			if err := os.Mkdir(p, 0o755); err != nil {
				return made, fmt.Errorf("mkdir %s: %w", p, err)
			}
			if rel, err := filepath.Rel(dir, p); err == nil && filepath.IsLocal(rel) {
				p = filepath.ToSlash(rel)
			}
			made = append(made, p)
		}
	}
	return made, nil
}
