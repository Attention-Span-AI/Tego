// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
)

// LiveCommands is the command matcher of a run's live command-word blocks (internal/liveblock, ADR 0171): an index
// holding each block's text as an exec.deny entry, so a block refuses exactly what the same entry in the contract's
// exec.deny would refuse, read by the contract's own parser, rows and interpretations. The run's own command rules are
// not in it and are not changed by it: the supervisor asks this index in addition to the run's own, only while a block
// stands, and a run's lines, pins and warnings stay as they were.
type LiveCommands struct {
	// Index decides an exec's facts as the contract's does (execmatch.Index.Decide); every pattern in it is a block's.
	Index *execmatch.Index
	// entries maps each block's pattern to the text it was built from (the block's value).
	entries map[*execmatch.Pattern]string
}

// ValueOf is the text of the block p belongs to (a Result's Pattern), false for a pattern of no block.
func (l *LiveCommands) ValueOf(p *execmatch.Pattern) (string, bool) {
	if l == nil {
		return "", false
	}
	v, ok := l.entries[p]
	return v, ok
}

// NewLiveCommands compiles the command-word blocks values (normalized as liveblock.NormalizeWords, which this accepts
// only if execmatch.Parse accepts it as an exec.deny entry) into the matcher of a run compiled to rt. It carries what the
// contract's command rules already know of the commands: the identities of the ruled commands' files, git's
// autocorrect candidates, the host's dynamic loaders and the tools an implicit grant keeps unconstrained. A block's
// program that the contract holds no command rule for is also looked up on the run's PATH (rt.PATH, relative entries
// under cwd), and a file of one link found there is the tool's identity, as compile resolves a ruled command's file
// (interpretation 2): without it a hard link of the program under another name is matched by the names the exec
// gives it only. An index with nothing to decide returns nil.
func NewLiveCommands(rt *RuleTable, cwd string, values []string) (*LiveCommands, error) {
	if len(values) == 0 {
		return nil, nil
	}
	l := &LiveCommands{entries: map[*execmatch.Pattern]string{}}
	var patterns []*execmatch.Pattern
	for _, v := range values {
		p, err := execmatch.Parse(v, execmatch.ListDeny, rows.Builtin())
		if err != nil {
			return nil, fmt.Errorf("live command block %q: %w", v, err)
		}
		if p.Bare {
			return nil, fmt.Errorf("live command block %q names a program and no words", v)
		}
		patterns = append(patterns, p)
		l.entries[p] = v
	}
	opts := execmatch.IndexOptions{Identities: map[execmatch.ID]string{}}
	if rt != nil && rt.ExecCommands != nil {
		ec := rt.ExecCommands
		opts.Candidates, opts.Loaders = ec.Candidates, ec.Loaders
		for id, tool := range ec.Identities {
			opts.Identities[id] = tool
		}
		opts.Unconstrained = map[string]bool{}
		for t := range ec.Unconstrained {
			opts.Unconstrained[t] = true
		}
	}
	if opts.Loaders == nil {
		opts.Loaders = execLoaders(loaderDirs(), nil)
	}
	var dirs []string
	if rt != nil && rt.PATH != "" {
		dirs = strings.Split(rt.PATH, ":")
	}
	seen := map[string]bool{}
	for _, p := range patterns {
		if seen[p.Command] {
			continue
		}
		seen[p.Command] = true
		if id, ok := liveToolIdentity(p, dirs, cwd); ok {
			opts.Identities[id] = p.Tool
		}
	}
	l.Index = execmatch.NewIndex(rows.Builtin(), patterns, opts)
	return l, nil
}

// liveToolIdentity is the identity of the file the command word of p names on dirs (a PATH, searched as execvp does),
// when it is a regular file of one link and the tool's row is not a multicall one: compile's rule for a ruled
// command's file (execIdentities).
func liveToolIdentity(p *execmatch.Pattern, dirs []string, cwd string) (execmatch.ID, bool) {
	for _, d := range dirs {
		if !filepath.IsAbs(d) {
			if cwd == "" {
				continue
			}
			d = filepath.Join(cwd, d)
		}
		cand := filepath.Join(d, p.Command)
		fi, err := os.Stat(cand)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 {
			continue
		}
		res := resolvePath(cand)
		if res == "" {
			return execmatch.ID{}, false
		}
		var st syscall.Stat_t
		if err := syscall.Stat(res, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
			return execmatch.ID{}, false
		}
		if st.Nlink != 1 || p.Row != nil && p.Row.Multicall {
			return execmatch.ID{}, false
		}
		return execmatch.ID{Dev: uint64(st.Dev), Ino: st.Ino}, true //nolint:unconvert // Dev's type differs by platform
	}
	return execmatch.ID{}, false
}
