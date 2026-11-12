// SPDX-License-Identifier: Apache-2.0

package guide

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/internal/nextrun"
	"github.com/attention-span-ai/tego/internal/registry"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// contract is one registry entry and what compiling it now said.
type contract struct {
	name, path string
	// err is why it does not compile now, or why the registry refused it; nil when it compiles.
	err error
	// linked is the newest run that ran this file (run_start.contract_source.path), nil for none; the compile is
	// made in that run's context, as tego rule makes it (internal/nextrun).
	linked *run
}

// maxContracts is how many registry names the contract step compiles: registry.Places.Names' bound, after which
// it lists "...".
const maxContracts = 20

// contracts is what the guide read of the registries.
type contracts struct {
	all []*contract
	// unreadable names the registry's agents folder (the project's or the user's) that exists and cannot be listed,
	// "" when both could be; err is why.
	unreadable string
	err        error
	// more is true when the registries hold more names than maxContracts, which were not compiled.
	more bool
	// places are where the names were looked up.
	places registry.Places
}

// readContracts lists the agents the registries hold (registry.Places.Names, at most maxContracts) and compiles each
// one as tego would compile its next run (nextrun.Compile): offline, through the machine's profile sources, in the
// context of the newest run that ran the same file when there is one, else from the contract's own folder with no
// tiers named, so an auto contract resolves to the machine's ceiling, as the dashboard compiles it. Nothing tego
// setup stores reaches the compile.
func readContracts(ctx context.Context, in *Inputs, rs *runs) *contracts {
	out := &contracts{}
	m := in.Machine
	p := registry.Places{Dir: in.Dir, User: m.Registry.Value, UID: in.UID, Own: []string{m.LedgerRoot.Value, m.Profiles.Value}}
	if in.Anchor != "" {
		p.Own = append(p.Own, filepath.Dir(in.Anchor))
	}
	out.places = p
	// An agents folder that exists and cannot be listed is a registry not read (Names would skip it): the step is
	// not known, never "no contract".
	var dirs [][2]string // what, folder
	if p.Dir != "" {
		dirs = append(dirs, [2]string{"the project registry", filepath.Join(p.Dir, registry.ProjectDir, registry.AgentsDir)})
	}
	if p.User != "" {
		dirs = append(dirs, [2]string{"the user registry", filepath.Join(p.User, registry.AgentsDir)})
	}
	for _, d := range dirs {
		if _, err := os.ReadDir(d[1]); err != nil && !errors.Is(err, fs.ErrNotExist) {
			out.unreadable, out.err = d[0]+" "+d[1], err
			return out
		}
	}
	for _, name := range p.Names() {
		if !registry.IsName(name) {
			out.more = true // Names' "..." after its maxContracts
			continue
		}
		c := &contract{name: name}
		out.all = append(out.all, c)
		e, err := p.Resolve(name)
		if err != nil {
			c.err = err
			var re *registry.Error
			if errors.As(err, &re) {
				c.path = re.Path
			}
			continue
		}
		c.path = e.Path
		c.linked = rs.newest(func(r *run) bool { return r.start.ContractSource != nil && r.start.ContractSource.Path == e.Path })
		cc := nextrun.Context{Contract: e.Path, PATH: in.PATH, Home: in.Home, Anchor: in.Anchor,
			RuntimeDirs: in.RuntimeDirs, Exe: in.Exe}
		if r := c.linked; r != nil {
			cc.Cwd, cc.Tier, cc.RunCommandGrant, cc.RunDir = r.start.Cwd, r.start.Tier, r.start.RunCommandGrant, r.dir
		}
		_, c.err = nextrun.Compile(ctx, m, cc, e.Data)
	}
	return out
}

// compiling is the first contract that compiles now, nil for none.
func (cs *contracts) compiling() *contract {
	for _, c := range cs.all {
		if c.err == nil {
			return c
		}
	}
	return nil
}

// firstLine is err's first line, printable: a compile's first diagnostic.
func firstLine(err error) string {
	s, _, _ := strings.Cut(err.Error(), "\n")
	return record.Printable(s)
}

// errText is err as a not-known line says it.
func errText(err error) string { return record.Printable(fmt.Sprint(err)) }
