// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func (k *compiler) baselineConflicts() {
	b := k.rt.Baseline
	if b == nil || !b.Applied || len(b.Entries) == 0 {
		return
	}
	if k.c.HostSockets {
		k.baselineConflict(&b.Entries[0], "host_sockets", "host sockets can start processes outside the run, where baseline rules do not apply")
	}
	for i := range b.Entries {
		e := &b.Entries[i]
		switch e.Key {
		case config.BaselineDenyRead, config.BaselineDenyWrite:
			k.baselineFSConflicts(e)
		case config.BaselineDenyExec:
			k.baselineExecConflicts(e)
		case config.BaselineDenyEnv:
			// Environment conflicts are checked after launch producers are compiled.
		}
	}
	if k.c.Net != nil && k.rt.Builtins != nil {
		var socketMounts *MountTable
		var socketMountErr error
		mountsRead := false
		for _, list := range []struct {
			key     string
			entries []string
		}{{"net.allow", k.c.Net.Allow}, {"net.ask", k.c.Net.Ask}} {
			for i, raw := range list.entries {
				p, ok := strings.CutPrefix(raw, "unix:")
				if !ok || !filepath.IsAbs(p) {
					continue
				}
				names := []string{p, builtinResolvedPath(p, k.namePredictionUnavailable)}
				protected := false
				for _, name := range names {
					if rule := k.rt.Builtins.UnixRule(name, false); rule == BuiltinHostIPC || rule == BuiltinTegoSurface {
						protected = true
						break
					}
				}
				if !protected {
					protected = k.baselineSocketIdentity(p)
				}
				if !protected {
					if !mountsRead {
						socketMounts, _, socketMountErr = ReadMountSnapshot(k.o.mountInfo)
						mountsRead = true
					}
					if socketMountErr != nil {
						k.ds.errorf(k.pos(list.key+"."+strconv.Itoa(i)), CodeBaselinePlacement, "cannot establish socket aliases for baseline sources %v: %s", b.Entries[0].Sources, socketMountErr)
						continue
					}
					aliases, ok := socketMounts.TreeAliases(names[1])
					if !ok {
						k.ds.errorf(k.pos(list.key+"."+strconv.Itoa(i)), CodeBaselinePlacement, "cannot place socket grant %q in the mount inventory for baseline sources %v", raw, b.Entries[0].Sources)
						continue
					}
					for _, alias := range aliases {
						if k.rt.Builtins.UnixRule(alias, false) != "" {
							protected = true
							break
						}
					}
				}
				if protected {
					k.baselineConflict(&b.Entries[0], list.key+"."+strconv.Itoa(i), "protected host socket "+raw+" can start processes outside the run, where baseline rules do not apply")
				}
			}
		}
	}
}

func (k *compiler) baselineSocketIdentity(p string) bool { return k.rt.baselineSocketIdentity(p) }

func (rt *RuleTable) baselineSocketIdentity(p string) bool {
	b := rt.Builtins
	fi, err := os.Stat(p)
	if err != nil {
		return false
	}
	known := append([]string{}, b.Nodes...)
	for _, root := range b.Runtime {
		known = append(known, filepath.Join(root, "bus"), filepath.Join(root, "systemd/private"))
	}
	for _, name := range known {
		if other, err := os.Stat(name); err == nil && os.SameFile(fi, other) {
			return true
		}
	}
	// Match alternate names of protected parents by identity, preserving the
	// fixed SSH exceptions through the same UnixRule classifier.
	for _, root := range append(append(append([]string{}, b.Runtime...), b.IPCDirs...), b.TegoDirs...) {
		parent, err := os.Stat(root)
		if err != nil || !parent.IsDir() {
			continue
		}
		suffix := filepath.Base(p)
		for at := filepath.Dir(p); ; at = filepath.Dir(at) {
			if other, err := os.Stat(at); err == nil && os.SameFile(parent, other) {
				if b.UnixRule(filepath.Join(root, suffix), false) != "" {
					return true
				}
			}
			if at == "/" || at == "." {
				break
			}
			suffix = filepath.Join(filepath.Base(at), suffix)
		}
	}
	return false
}

// ValidateBaselineSockets checks final runtime grants through the same protected
// endpoint classifier as compilation, including declared, resolved and mount aliases.
func (rt *RuleTable) ValidateBaselineSockets() error {
	if rt == nil || rt.Baseline == nil || !rt.Baseline.Applied || len(rt.Baseline.Entries) == 0 {
		return nil
	}
	if c := rt.DecisionContract(); c != nil && c.HostSockets {
		return fmt.Errorf("baseline-conflict: host_sockets conflicts with the nonempty baseline")
	}
	var mt *MountTable
	for _, list := range [][]NetRule{rt.Net, rt.NetAsk} {
		for _, r := range list {
			if r.Proto != ProtoUnix || r.Abstract {
				continue
			}
			if rt.Builtins == nil {
				return fmt.Errorf("baseline: protected socket classifier is unavailable")
			}
			names := []string{r.UnixPath, r.UnixResolved, builtinResolvedPath(r.UnixPath, nil)}
			for _, p := range names {
				if !filepath.IsAbs(p) {
					continue
				}
				if rt.Builtins.UnixRule(p, false) != "" || rt.baselineSocketIdentity(p) {
					return fmt.Errorf("baseline-conflict: socket grant %q conflicts with baseline sources %v", r.Raw, rt.Baseline.Entries[0].Sources)
				}
				if mt == nil {
					var err error
					mt, _, err = ReadMountSnapshot(rt.Baseline.MountInfo)
					if err != nil {
						return fmt.Errorf("baseline: cannot establish final socket aliases: %w", err)
					}
				}
				aliases, ok := mt.TreeAliases(p)
				if !ok {
					return fmt.Errorf("baseline: final socket grant %q cannot be placed", r.Raw)
				}
				for _, alias := range aliases {
					if rt.Builtins.UnixRule(alias, false) != "" {
						return fmt.Errorf("baseline-conflict: socket grant %q reaches protected alias %q", r.Raw, alias)
					}
				}
			}
		}
	}
	return nil
}

func (k *compiler) baselineFSConflicts(e *BaselineRule) {
	for _, g := range slices.Concat(k.rt.FS, k.rt.FSAsk) {
		if detail := k.rt.baselineFSGrantConflict(e, g); detail != "" {
			k.baselineConflict(e, baselineFSGrantKey(g), detail, g.Pos)
		}
	}
	if e.Key != config.BaselineDenyRead {
		return
	}
	if k.rt.Live != nil {
		for _, g := range k.rt.Live.Entries {
			if g.Kind != LiveKindRead {
				continue
			}
			inside, enclosing := baselineGrantRelation(e, g.Value)
			if inside || enclosing {
				k.baselineConflict(e, "live.fence.read", "compiled live read fence overlaps the refused scope", g.Pos)
			}
		}
	}
	for _, r := range k.rt.Exec {
		for _, p := range []string{r.Path, r.Resolved, r.Interp} {
			if p == "" {
				continue
			}
			inside, enclosing := baselineGrantRelation(e, p)
			if (inside || enclosing && r.IsDir) && k.mayLand("landlock") {
				k.baselineConflict(e, "exec.allow", "exec grant or implicit "+r.Source+" image "+p+" carries read access at Landlock", r.Pos)
			}
		}
	}
}

func baselineFSGrantKey(g FSRule) string {
	if g.AskRead {
		return "fs.ask_read"
	}
	if g.Kind == FSAsk {
		return "fs.ask"
	}
	return "fs.write"
}

// All callers use placed compiler output, including generated grants. The
// relation and the ADR 0144 direction rules also govern preparation rechecks.
func (rt *RuleTable) baselineFSGrantConflict(e *BaselineRule, g FSRule) string {
	if g.Kind != FSWrite && g.Kind != FSAsk && !(e.Key == config.BaselineDenyRead && g.AskRead) {
		return ""
	}
	inside, enclosing := baselineGrantRelation(e, g.Canonical())
	if !inside && !enclosing {
		return ""
	}
	if inside || g.Kind != FSWrite {
		return fmt.Sprintf("compiled grant %q reopens the refused scope, including known aliases and identities", g.Canonical())
	}
	if e.Key == config.BaselineDenyRead && rt.Reads.Mode == ReadsDirect {
		return fmt.Sprintf("direct reads beneath enclosing compiled write grant %q cannot hold this read refusal", g.Canonical())
	}
	// Enclosing writes require held reads or a decision plane, checked at the
	// actual mechanism by BaselineAt rather than treated as a nested reopening.
	return ""
}

func ancestorIdentity(path string, dev, ino uint64) bool {
	for p := path; ; p = filepath.Dir(p) {
		if fi, err := os.Stat(p); err == nil {
			if st, ok := fi.Sys().(*syscall.Stat_t); ok && uint64(st.Dev) == dev && st.Ino == ino {
				return true
			}
		}
		if p == "/" || p == "." {
			return false
		}
	}
}

func (k *compiler) baselineExecConflicts(e *BaselineRule) {
	ec := k.rt.ExecCommands
	if ec == nil {
		return
	}
	deny, err := execmatch.Parse(e.Expanded, execmatch.ListDeny, rows.Builtin())
	if err != nil {
		return
	} // combined validation already refused it
	if k.c.Exec != nil && k.c.Exec.Anonymous && !k.c.ExecUnrestricted() {
		k.baselineConflict(e, "exec.anonymous", "anonymous executable images escape restricted image coverage")
	}
	// The intersection solver runs on actual parsed command patterns. Bare image
	// grants carry no command exception and are deliberately absent from Entries.
	for _, en := range ec.Entries {
		if en.Pattern.List != execmatch.ListAllow {
			continue
		}
		k.baselineCommandIntersection(e, deny, en, ec)
	}
	check := func(argv []string, key string) {
		if len(argv) == 0 {
			return
		}
		f, err := k.rt.baselineCommandFacts(argv)
		if err != nil {
			k.baselineConflict(e, key, "cannot establish the required command's image and interpreter facts: "+err.Error())
			return
		}
		ix := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{deny}, execmatch.IndexOptions{Candidates: ec.Candidates, Identities: ec.Identities, Loaders: ec.Loaders})
		if ix.Decide(&f).Outcome == execmatch.OutcomeRefused {
			k.baselineConflict(e, key, "the required launch command is refused; it cannot start")
		}
	}
	check(k.c.Command, "command")
	for i, s := range k.c.MCP {
		check(s.Command, "mcp."+strconv.Itoa(i)+".command")
	}
	if len(k.o.runArgv) > 0 {
		check(k.o.runArgv, "run command after --")
	} else if k.o.runCommand != "" {
		check([]string{k.o.runCommand}, "run command after --")
	}
}

// The implementation is supplied beside execmatch's parser; keep diagnostics here
// so every conflict has the same source/owner/tier shape.
func (k *compiler) baselineCommandIntersection(e *BaselineRule, deny *execmatch.Pattern, en ExecCommandEntry, ec *ExecCommands) {
	command := en.Pattern.Command
	facts, err := k.rt.baselineCommandFacts([]string{command})
	if err != nil {
		k.baselineConflict(e, "exec.allow", "cannot rule out command intersection: "+err.Error())
		return
	}
	result := execmatch.Intersect(rows.Builtin(), deny, en.Pattern, execmatch.IntersectionOptions{IndexOptions: execmatch.IndexOptions{Candidates: ec.Candidates, Identities: ec.Identities, Loaders: ec.Loaders}, AllowImage: &facts})
	if result.Kind == execmatch.IntersectionDisjoint {
		return
	}
	detail := fmt.Sprintf("command allow %q: %s", en.Pattern.Entry, result.Reason)
	if result.Witness != nil {
		detail += fmt.Sprintf("; intersection witness %q", result.Witness.Argv)
	}
	key := "exec.allow"
	if k.c.Exec != nil {
		for i, raw := range k.c.Exec.Allow {
			if raw == en.Pattern.Entry {
				key += "." + strconv.Itoa(i)
				break
			}
		}
	}
	k.baselineConflict(e, key, detail)
}

// ValidateBaselineCommand checks the actual launcher/harness command, which can
// differ from the source command. It never prints environment values.
func (rt *RuleTable) ValidateBaselineCommand(argv []string) error {
	if rt == nil || rt.Baseline == nil || !rt.Baseline.Applied || len(argv) == 0 {
		return nil
	}
	var patterns []*execmatch.Pattern
	for _, e := range rt.Baseline.Entries {
		if e.Key != config.BaselineDenyExec {
			continue
		}
		p, err := execmatch.Parse(e.Expanded, execmatch.ListDeny, rows.Builtin())
		if err != nil {
			return fmt.Errorf("baseline command %q is invalid: %w", e.Value, err)
		}
		patterns = append(patterns, p)
	}
	if len(patterns) == 0 {
		return nil
	}
	opts := execmatch.IndexOptions{}
	if rt.ExecCommands != nil {
		opts = execmatch.IndexOptions{Candidates: rt.ExecCommands.Candidates, Identities: rt.ExecCommands.Identities, Loaders: rt.ExecCommands.Loaders}
	}
	f, err := rt.baselineCommandFacts(argv)
	if err != nil {
		return fmt.Errorf("baseline-conflict: cannot establish the launch command's image: %w", err)
	}
	if r := execmatch.NewIndex(rows.Builtin(), patterns, opts).Decide(&f); r.Outcome == execmatch.OutcomeRefused {
		return fmt.Errorf("baseline-conflict: required launch command is refused by %s", r.Rule())
	}
	return nil
}

func (rt *RuleTable) baselineCommandFacts(argv []string) (execmatch.Facts, error) {
	if len(argv) == 0 || argv[0] == "" {
		return execmatch.Facts{Form: execmatch.FormUnknown}, fmt.Errorf("required command has no program")
	}
	image := argv[0]
	if !strings.ContainsAny(argv[0], "/") {
		for _, r := range rt.Exec {
			if r.Raw == argv[0] || r.Basename == argv[0] {
				image = r.Path
				break
			}
		}
	}
	requested := image
	if !filepath.IsAbs(image) && rt.Workdir != "" {
		image = strings.TrimSuffix(rt.Workdir, "/") + "/" + image
	}
	if via, proc := config.ThroughProc(image); proc {
		return execmatch.Facts{Form: execmatch.FormUnknown}, fmt.Errorf("required command uses process-relative procfs at %s", via)
	}
	if resolved, err := filepath.EvalSymlinks(image); err == nil {
		image = resolved
	}
	f := execmatch.Facts{Requested: filepath.Base(argv[0]), Image: filepath.Base(image), Path: requested, Argv0: argv[0], Argv: argv, ArgvComplete: true, Form: execmatch.FormDirect}
	if fi, err := os.Stat(image); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			f.ID = execmatch.ID{Dev: uint64(st.Dev), Ino: st.Ino}
			f.HasID = true
			f.Links = uint64(st.Nlink)
		}
	} else {
		// A missing override has always ended with exec's 127. It cannot start an
		// image, so retain its declared facts; preparation/exec still resolves it.
		if os.IsNotExist(err) {
			return f, nil
		}
		return f, err
	}
	for depth := 0; depth < 5; depth++ {
		interp, arg, emptyArg, script, err := ReadShebangDetails(image)
		if err != nil {
			f.Form = execmatch.FormUnknown
			return f, err
		}
		if !script {
			return rt.baselineLoadedProgram(f)
		}
		f.Form = execmatch.FormScript
		stage := execmatch.Stage{Path: interp, Arg: arg, EmptyArg: emptyArg, Image: filepath.Base(interp)}
		placed := interp
		if !filepath.IsAbs(placed) {
			if rt.Workdir == "" {
				f.Form = execmatch.FormUnknown
				return f, fmt.Errorf("relative interpreter %q needs an explicit placed context", interp)
			}
			placed = strings.TrimSuffix(rt.Workdir, "/") + "/" + placed
		}
		if via, proc := config.ThroughProc(placed); proc {
			f.Form = execmatch.FormUnknown
			return f, fmt.Errorf("interpreter uses process-relative procfs at %s", via)
		}
		resolved, err := filepath.EvalSymlinks(placed)
		if err != nil {
			f.Form = execmatch.FormUnknown
			return f, err
		}
		stage.Image = filepath.Base(resolved)
		fi, err := os.Stat(resolved)
		if err != nil {
			f.Form = execmatch.FormUnknown
			return f, err
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			stage.ID = execmatch.ID{Dev: uint64(st.Dev), Ino: st.Ino}
			stage.HasID = true
			stage.Links = uint64(st.Nlink)
		}
		f.Interp = append(f.Interp, stage)
		image = resolved
	}
	f.Form = execmatch.FormUnknown
	return f, fmt.Errorf("interpreter chain exceeds the kernel's supported depth")
}

func execRulePath(r ExecRule) string {
	if r.Resolved != "" {
		return r.Resolved
	}
	return r.Path
}
