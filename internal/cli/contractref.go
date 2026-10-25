// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/attention-span-ai/tego/internal/registry"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// contractRef is the contract a command was given (compile's and run's argument, watch's and adopt's --boundary): a
// file named by its path, or an agent's name, which the registry resolved to its file (agent-contract.md R26).
type contractRef struct {
	// arg is the argument as given: a path, "-" for standard input (compile only), or a name.
	arg string
	// entry is the resolved name, nil for a path.
	entry *registry.Entry
}

// resolveContract reads arg: an agent name ([a-z0-9-]{1,40}: no '/' and no '.', so never a path to a .yaml file)
// is resolved in the registries, anything else is a path, read as before. generated is a contract tego wrote itself
// (watch's or adopt's with no --boundary), which is a path whatever its spelling.
func resolveContract(arg string, generated bool, m *config.Machine) (contractRef, *registry.Error) {
	if generated || !registry.IsName(arg) {
		return contractRef{arg: arg}, nil
	}
	places, rerr := registryPlaces(m)
	if rerr != nil {
		return contractRef{}, rerr
	}
	e, err := places.Resolve(arg)
	if err != nil {
		var re *registry.Error
		if !errors.As(err, &re) {
			re = &registry.Error{Code: registry.CodeEntry, What: err.Error(), Fix: "give the contract's path", Err: err}
		}
		return contractRef{}, re
	}
	return contractRef{arg: arg, entry: e}, nil
}

// registryPlaces are the registries a name resolves in: the working directory, the machine config's registry:, the
// invoking user, and tego's own paths, which no entry may lie in (its directory, the ledger root, the profiles).
func registryPlaces(m *config.Machine) (registry.Places, *registry.Error) {
	wd, err := os.Getwd()
	if err != nil {
		return registry.Places{}, &registry.Error{Code: codeIO, What: "the working directory: " + err.Error(),
			Fix: "give the contract's path", Err: err}
	}
	uid, _ := config.InvokingUID()
	p := registry.Places{Dir: wd, User: m.Registry.Value, UID: uid, Own: []string{m.LedgerRoot.Value, m.Profiles.Value}}
	if a, err := anchorPath(m); err == nil {
		p.Own = append(p.Own, filepath.Dir(a))
	}
	return p, nil
}

// printRefusedName prints a refused name under its own code, naming the file it is about.
func printRefusedName(stderr io.Writer, cmd string, e *registry.Error) {
	message(stderr, e.Path, 0, 0, cmd+": "+e.Error(), e.Code)
}

// load is agent.Load of the file: for a name, the bytes the registry read through the descriptor it checked, labelled
// with the file's path, so the file recorded is the one compiled.
func (c contractRef) load(profiles agent.ProfileSource) (*agent.Contract, []agent.Diagnostic, error) {
	if c.entry != nil {
		return agent.LoadBytes(c.entry.Path, c.entry.Data, profiles)
	}
	return loadContract(c.arg, profiles)
}

// label is the file the command's own messages name.
func (c contractRef) label() string {
	if c.entry != nil {
		return c.entry.Path
	}
	return contractLabel(c.arg)
}

// source is what run_start records of the contract (record.ContractSource): the file's absolute path (the one the
// table was compiled from), and the name and registry it was resolved from. nil for standard input.
func (c contractRef) source(rt *agent.RuleTable) *record.ContractSource {
	if c.entry != nil {
		return &record.ContractSource{Path: c.entry.Path, Name: c.entry.Name, Registry: c.entry.Registry}
	}
	if c.arg == stdinContract || rt == nil || rt.ContractPath == "" {
		return nil
	}
	return &record.ContractSource{Path: rt.ContractPath}
}
