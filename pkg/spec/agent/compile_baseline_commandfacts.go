// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// baselineLoadedProgram mirrors the supervisor's loader operand interpretation.
// A direct loader can run its program without another exec, so its own name and
// argv are insufficient facts for a machine command refusal (ADR 0048).
func (rt *RuleTable) baselineLoadedProgram(f execmatch.Facts) (execmatch.Facts, error) {
	loader := func(name, image string, id execmatch.ID, known bool) bool {
		return execmatch.LoaderName(name) || execmatch.LoaderName(image) ||
			known && rt.ExecCommands != nil && rt.ExecCommands.Loaders[id]
	}
	argv := f.Argv
	if f.Form == execmatch.FormScript && len(f.Interp) > 0 {
		stage := f.Interp[len(f.Interp)-1]
		if !loader(stage.Path, stage.Image, stage.ID, stage.HasID) {
			return f, nil
		}
		argv = f.ScriptArgv()
	} else if !loader(f.Requested, f.Image, f.ID, f.HasID) {
		return f, nil
	}
	fail := func(why string, err error) (execmatch.Facts, error) {
		f.Form = execmatch.FormUnknown
		if err != nil {
			return f, fmt.Errorf("loader program %s: %w", why, err)
		}
		return f, fmt.Errorf("loader program %s", why)
	}
	i, program, outcome := execmatch.LoaderProgram(argv)
	switch outcome {
	case execmatch.LoaderExits:
		return f, nil
	case execmatch.LoaderUnknown:
		return fail("has unsupported options", nil)
	case execmatch.LoaderRuns:
	default:
		return fail("has an unknown interpretation", nil)
	}
	operand := argv[i]
	// As at supervision, an operand without '/' may be selected by mutable
	// loader search paths. It is not a proven image in the compile context.
	if !strings.Contains(operand, "/") {
		return fail("operand has no explicit path", nil)
	}
	placed := operand
	if !filepath.IsAbs(placed) {
		if rt.Workdir == "" {
			return fail("relative operand has no working directory", nil)
		}
		placed = strings.TrimSuffix(rt.Workdir, "/") + "/" + placed
	}
	if via, proc := config.ThroughProc(placed); proc {
		return fail("uses process-relative procfs at "+via, nil)
	}
	resolved, err := filepath.EvalSymlinks(placed)
	if err != nil {
		return fail("cannot be placed", err)
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return fail("cannot be inspected", err)
	}
	if !fi.Mode().IsRegular() {
		return fail("is not a regular executable image", nil)
	}
	loaded := &execmatch.Loaded{Path: operand, Image: filepath.Base(resolved), Argv: program}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		loaded.ID = execmatch.ID{Dev: uint64(st.Dev), Ino: st.Ino}
		loaded.HasID, loaded.Links = true, uint64(st.Nlink)
	}
	if loader(operand, loaded.Image, loaded.ID, loaded.HasID) {
		return fail("is itself a loader", nil)
	}
	if _, err := ReadInterp(resolved); err != nil {
		return fail("has an unreadable or unsupported ELF header", err)
	}
	f.Loaded = loaded
	return f, nil
}
