// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// guardLoadMachine gives every new adoption its own trusted decision snapshot.
// A guard can outlive config edits; its startup snapshot belongs to older runs.
var guardLoadMachine = loadMachine

func (g *guard) prepareAdoption(t adopt.Process, uid int) (*preparedAdoption, error) {
	m, err := g.currentMachine()
	if err != nil {
		return nil, err
	}
	if g.shared != nil {
		return g.sharedTable(uid, m)
	}
	var diagnostics bytes.Buffer
	a, code := adoptPrepare(g.ctx, m, g.o, t, uid, &diagnostics)
	if a == nil {
		return nil, fmt.Errorf("its run could not be prepared (exit %d)%s", code, guardDiagnostics(diagnostics.String()))
	}
	return a, nil
}

func (g *guard) currentMachine() (*config.Machine, error) {
	m, ds, err := guardLoadMachine(config.TrustAbort)
	var diagnostics bytes.Buffer
	writeConfigDiagnostics(&diagnostics, ds)
	if err != nil {
		return nil, fmt.Errorf("current machine configuration could not be loaded: %w%s", err, guardDiagnostics(diagnostics.String()))
	}
	if m == nil || !m.BaselineKnown() {
		return nil, fmt.Errorf("current machine baseline is UNKNOWN; repair and reload the selected layers%s", guardDiagnostics(diagnostics.String()))
	}
	if g.m != nil {
		if err := g.sameRecordLocation(m); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// guardRecordLocation retains the resolved output directory, or the existing
// ancestor and missing suffix when the output directory has not been created yet.
// os.SameFile compares that directory's device and inode; timestamps do not move it.
type guardRecordLocation struct {
	resolved, existing string
	identity           os.FileInfo
}

func (g *guard) captureRecordLocations() error {
	for i, path := range []string{g.recordRoot, filepath.Dir(g.recordAnchor)} {
		location, err := resolveGuardRecordDirectory(path)
		if err != nil {
			return guardLocationError([]string{"ledger", "anchor"}[i], err)
		}
		g.recordLocations[i] = location
	}
	return nil
}

// sameRecordLocation checks placement before every adoption, even with unchanged
// configuration bytes. An absent directory can be created beneath its pinned
// ancestor; once observed, its own identity replaces the ancestor's identity.
func (g *guard) sameRecordLocation(m *config.Machine) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, location := range []struct {
		name    string
		resolve func(*config.Machine) (string, error)
	}{{"ledger", ledgerRootOf}, {"anchor", anchorPath}} {
		current, err := location.resolve(m)
		if err != nil {
			return guardLocationError(location.name, err)
		}
		path := current
		if location.name == "anchor" {
			path = filepath.Dir(current)
		}
		observed, err := resolveGuardRecordDirectory(path)
		if err != nil {
			return guardLocationError(location.name, err)
		}
		startup := &g.recordLocations[i]
		// Constructors capture both identities before watching begins. A guard
		// without those facts cannot safely decide that a location stayed put.
		if startup.identity == nil {
			return guardLocationError(location.name, fmt.Errorf("startup directory identity was not captured"))
		}
		if location.name == "anchor" && filepath.Base(current) != filepath.Base(g.recordAnchor) {
			return fmt.Errorf("the guard's anchor filename changed from %q to %q; restart the guard to select the new record location", filepath.Base(g.recordAnchor), filepath.Base(current))
		}
		if observed.resolved != startup.resolved {
			return fmt.Errorf("the guard's %s location changed from %q to %q; restart the guard to select the new record location", location.name, startup.resolved, observed.resolved)
		}
		existing, err := os.Stat(startup.existing)
		if err != nil {
			return guardLocationError(location.name, fmt.Errorf("startup directory %q changed or is unavailable: %w", startup.existing, err))
		}
		if !os.SameFile(startup.identity, existing) {
			return fmt.Errorf("the guard's %s directory %q changed identity; restart the guard to select the new record location", location.name, startup.existing)
		}
		// Ordinary first use may create an initially absent directory. Retain
		// the deepest observed identity so its later replacement also refuses.
		*startup = observed
	}
	return nil
}

// resolveGuardRecordDirectory follows links before '..', as the kernel does.
// Absence is supported only beneath an existing directory with a literal suffix;
// a dangling link or '..' after a missing name does not establish placement.
func resolveGuardRecordDirectory(path string) (guardRecordLocation, error) {
	return resolveGuardDirectory(path, false, 0)
}

// A passwd home may be a link to a still-absent home. Preserve that supported
// absence, pinning the link's resolved target ancestor rather than its spelling.
func resolveAdoptionHome(path string) (guardRecordLocation, error) {
	return resolveGuardDirectory(path, true, 0)
}

func resolveGuardDirectory(path string, absentHome bool, links int) (guardRecordLocation, error) {
	if links > 40 {
		return guardRecordLocation{}, fmt.Errorf("too many home symlinks")
	}
	if !filepath.IsAbs(path) {
		return guardRecordLocation{}, fmt.Errorf("record directory %q is not absolute", path)
	}
	resolved := string(filepath.Separator)
	parts := strings.Split(path, string(filepath.Separator))
	for i, part := range parts {
		if part == "" || part == "." {
			continue
		}
		next := resolved + "/" + part
		walked, err := filepath.EvalSymlinks(next)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return guardRecordLocation{}, err
			}
			if info, lerr := os.Lstat(next); lerr == nil {
				if info.Mode()&os.ModeSymlink != 0 {
					if absentHome {
						target, err := os.Readlink(next)
						if err != nil {
							return guardRecordLocation{}, err
						}
						if !filepath.IsAbs(target) {
							target = resolved + "/" + target
						}
						return resolveGuardDirectory(target+"/"+strings.Join(parts[i+1:], "/"), true, links+1)
					}
					return guardRecordLocation{}, fmt.Errorf("record directory has a dangling symlink at %q", next)
				}
				return guardRecordLocation{}, fmt.Errorf("record directory component %q changed while resolving it", next)
			} else if !errors.Is(lerr, fs.ErrNotExist) {
				return guardRecordLocation{}, lerr
			}
			suffix := parts[i:]
			for _, missing := range suffix {
				if missing == ".." {
					return guardRecordLocation{}, fmt.Errorf("record directory %q has '..' beneath a missing name", path)
				}
			}
			info, err := os.Stat(resolved)
			if err != nil {
				return guardRecordLocation{}, err
			}
			if !info.IsDir() {
				return guardRecordLocation{}, fmt.Errorf("record directory ancestor %q is not a directory", resolved)
			}
			return guardRecordLocation{resolved: filepath.Join(resolved, filepath.Join(suffix...)), existing: resolved, identity: info}, nil
		}
		info, err := os.Stat(walked)
		if err != nil {
			return guardRecordLocation{}, err
		}
		if !info.IsDir() {
			return guardRecordLocation{}, fmt.Errorf("record location %q is not a directory", walked)
		}
		resolved = walked
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return guardRecordLocation{}, err
	}
	return guardRecordLocation{resolved: resolved, existing: resolved, identity: info}, nil
}

func guardLocationError(name string, err error) error {
	return fmt.Errorf("the guard cannot establish its %s location: %w; repair the configuration and restart the guard", name, err)
}

func guardDiagnostics(text string) string {
	if text = strings.TrimSpace(text); text != "" {
		return ": " + text
	}
	return ""
}
