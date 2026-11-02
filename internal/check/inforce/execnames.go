// SPDX-License-Identifier: Apache-2.0

package inforce

import (
	"path"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// execNames is what a run's lines call each program entry of a compiled table. An entry's text is not always a name
// a line carries. Compile resolves each entry to a file and keeps one rule per path it resolved to. An entry that
// resolves to the path an earlier one did (cat and the /usr/bin/cat it is on PATH, or the command named again) adds
// no rule: it is that rule, named after the first spelling (pkg/spec/agent compile_exec.go add). Two paths that lead
// to one file (python3 and the python3.13 it links to) are two rules, and a run names every exec of that file after
// the first of them in table order: tier 1 matches the file the exec landed on before its spelling (the supervisor's
// execGranted), and decide's matchExec takes the first rule that names either. An exec.allow entry with words
// compiles to its program's rule, which its lines carry ("git status" runs as exec[git], the entry in the line's
// command_rule). So each program entry is given the rule key of the file it resolved to, the name its lines carry,
// and covers the other rules of that file: every entry that resolved to one file shows that file's hits.
//
// A tool with helper images is more than one file: compile grants git's exec-path git and the dashed helpers its
// closure runs as rules of their own (helperImages, Source helper:git), and git re-executes itself from there (an
// allowed git commit runs /usr/lib/git-core/git maintenance, a line named exec[/usr/lib/git-core/git]). Every
// exec.allow entry of the tool covers those rules too. A command that is a script is more than one file as well:
// compile grants the interpreter its #! line names, and env's argument after it (Source interpreter:<script>), and an
// agent that runs that interpreter again (a `sh -c` from a #!/bin/sh script) writes a line named after it, so the
// command's file covers its interpreters' files.
type execNames struct {
	rt *agent.RuleTable
	// byFile is each file's rules, as indexes into rt.Exec in table order (fileKey).
	byFile map[string][]int
	// helpers is each tool's helper images, as indexes into rt.Exec: the rules whose sources name helper:<tool>.
	helpers map[string][]int
	// interps is, for the rule of the contract's command and of the run command, the rules its #! line was granted.
	interps map[int][]int
}

func newExecNames(rt *agent.RuleTable) *execNames {
	n := &execNames{rt: rt, byFile: map[string][]int{}, helpers: map[string][]int{}, interps: map[int][]int{}}
	for i := range rt.Exec {
		r := &rt.Exec[i]
		k := fileKey(r)
		if k == "" {
			continue
		}
		n.byFile[k] = append(n.byFile[k], i)
		for _, s := range strings.Split(r.Source, ",") {
			if tool, ok := strings.CutPrefix(s, agent.ExecSourceHelper+":"); ok && tool != "" {
				n.helpers[tool] = append(n.helpers[tool], i)
			}
		}
	}
	for i := range rt.Exec {
		// A script's interpreters carry interpreter:<the script's basename> (compile_exec.go script); MCP servers'
		// scripts have theirs too, but the view lists no MCP server's rules.
		r := &rt.Exec[i]
		if fileKey(r) == "" || !fromSource(r.Source, agent.ExecSourceCommand) {
			continue
		}
		src := agent.ExecSourceInterpreter + ":" + r.Basename
		for j := range rt.Exec {
			if j != i && fileKey(&rt.Exec[j]) != "" && fromSource(rt.Exec[j].Source, src) {
				n.interps[i] = append(n.interps[i], j)
			}
		}
	}
	return n
}

// fileKey is where rule r's grant lands, as the run matches it: its resolved path (Path where the table has none), a
// directory apart from a file. Hard links of one binary keep their own paths, as the run tells them apart by path. ""
// for a rule whose lines a run names after something else than a file: a rule a live fence entry marked, named
// live.fence[...] (the fence entry's own, or an exec.allow entry's that runs only because the fence took an exec.deny
// name out), and the runtime's own grant (the harness hook's).
func fileKey(r *agent.ExecRule) string {
	if r.Fence || r.Runtime != "" || r.Path == "" {
		return ""
	}
	p := r.Resolved
	if p == "" {
		p = r.Path
	}
	if r.IsDir {
		return "dir " + p
	}
	return "file " + p
}

// keys is the rule key and the covers of an entry that resolved to rule i: the name of the first rule of its file,
// which a run's lines carry, and the names of the file's other rules, which a line can carry too (one whose spelling
// matched before its file did), and, when the file is a script command's, the names of the files its #! line was
// granted. ok is false for a rule that stands for no entry's file (fileKey ""): a rule a live fence entry marked is
// named after the fence (live.fence[exec:<path>]), and its lines are the fence's refusals and lifts, even where the
// rule is an exec.allow entry's (a fence entry that took out an exec.deny name and names the entry's path,
// pkg/spec/agent liveExecMark).
func (n *execNames) keys(i int) (key string, covers []string, ok bool) {
	same := n.byFile[fileKey(&n.rt.Exec[i])]
	if len(same) == 0 {
		return "", nil, false
	}
	key = n.rt.Exec[same[0]].RuleName()
	for _, j := range same[1:] {
		covers = addCover(covers, key, n.rt.Exec[j].RuleName())
	}
	for _, j := range same {
		for _, k := range n.interps[j] {
			for _, m := range n.byFile[fileKey(&n.rt.Exec[k])] {
				covers = addCover(covers, key, n.rt.Exec[m].RuleName())
			}
		}
	}
	return key, covers, true
}

// allowKeys is the rule key and the covers of an exec.allow entry: the names of the file it resolved to (keys), or its
// text's (ruleKey) when the table cannot place it or its rule is a fence's; its text's name, a cover whatever file the
// entry resolved to here; and the names of the helper images compile granted its tool.
//
// The text's name is the one the run gives the entry's own rule when the entry was the first spelling of its file in
// the run's table, and that table need not be this one: the dashboard compiles a run's contract on its own PATH, not
// the run's, which no line records (internal/control/rulesview loadCopy). A bare name that resolved to another file in
// the run than here leaves a path entry that the run kept as a rule of its own (named after its text) merged here into
// the bare name's rule, and the run's lines for it would otherwise match no rule.
func (n *execNames) allowKeys(it item) (key string, covers []string) {
	own := ruleKey(kExecAllow, it.entry)
	key = own
	if i, ok := n.ofAllow(it); ok {
		if k, c, ok := n.keys(i); ok {
			key, covers = k, c
		}
	}
	covers = addCover(covers, key, own)
	for _, h := range n.helpers[entryTool(it.entry)] {
		covers = addCover(covers, key, n.rt.Exec[h].RuleName())
	}
	return key, covers
}

// addCover is covers with name added, unless name is the key or a cover already.
func addCover(covers []string, key, name string) []string {
	if name == "" || name == key || slices.Contains(covers, name) {
		return covers
	}
	return append(covers, name)
}

// ofAllow is the rule an exec.allow entry resolved to: the rule that carries the entry's position, which compile
// stamps on the rule an entry adds, or, for an entry that added none, the rule its program resolved to (ofWord). ok
// is false when neither tells.
func (n *execNames) ofAllow(it item) (int, bool) {
	if it.pos.Line > 0 {
		for i := range n.rt.Exec {
			if r := &n.rt.Exec[i]; r.Pos == it.pos && fromSource(r.Source, agent.ExecSourceAllow) {
				return i, true
			}
		}
	}
	return n.ofWord(programWord(it.entry))
}

// ofWord is the rule program word w resolved to, found as compile resolved it but without looking at a file. A bare
// name was searched on the run's PATH, and only a bare spelling marks a rule ByName, so it is the one rule of that
// name so marked. A path is the rule at that path, "~" expanded against the table's home. A relative path was
// resolved against a working directory the table does not keep, so it is the one rule whose path ends in it. ok is
// false when no rule, or more than one, answers.
func (n *execNames) ofWord(w string) (int, bool) {
	one := func(match func(r *agent.ExecRule) bool) (int, bool) {
		found := -1
		for i := range n.rt.Exec {
			r := &n.rt.Exec[i]
			if fileKey(r) == "" || !match(r) {
				continue
			}
			if found >= 0 {
				return -1, false
			}
			found = i
		}
		return found, found >= 0
	}
	switch {
	case w == "":
		return -1, false
	case !strings.Contains(w, "/"):
		return one(func(r *agent.ExecRule) bool { return r.ByName && !r.IsDir && r.Basename == w })
	case w == "~" || strings.HasPrefix(w, "~/"):
		if n.rt.Home == "" {
			return -1, false
		}
		w = path.Join(n.rt.Home, w[1:])
	case !path.IsAbs(w):
		rel := path.Clean(w)
		if rel == ".." || strings.HasPrefix(rel, "../") {
			return -1, false
		}
		return one(func(r *agent.ExecRule) bool { return strings.HasSuffix(r.Path, "/"+rel) })
	}
	p := path.Clean(w)
	return one(func(r *agent.ExecRule) bool { return r.Path == p })
}

// commandRule is the index of the contract command's exec rule, -1 when the table has none: the first rule whose
// sources name the command, which compile adds before any other (the run command's grant, added after every
// declared entry, names it too).
func commandRule(rt *agent.RuleTable) int {
	for i := range rt.Exec {
		if fromSource(rt.Exec[i].Source, agent.ExecSourceCommand) {
			return i
		}
	}
	return -1
}

// fromSource reports whether a rule's Source names src: one binary that is both the command and an exec.allow entry
// compiles to one rule whose Source is "command,exec.allow".
func fromSource(sources, src string) bool {
	return slices.Contains(strings.Split(sources, ","), src)
}

// withWords reports whether an exec.allow entry is a command pattern, a program and words after it, as compile reads
// it ('/opt/My Tools/run' quoted is one word).
func withWords(entry string) bool { return execmatch.IsPattern(entry) }

// programWord is the program an exec.allow entry names, read as compile reads it: the first word of an entry with
// words (a command pattern), and the one word of any other with its quotes taken off ('/opt/My Tools/run' is
// /opt/My Tools/run). An entry that does not split is returned as written.
func programWord(entry string) string {
	if !withWords(entry) {
		return execmatch.Word(entry)
	}
	if words, _, err := execmatch.SplitWords(entry); err == nil && len(words) > 0 {
		return words[0]
	}
	return entry
}

// entryTool is the tool an exec.allow entry names, read as compile's helperImages reads it (execmatch.Parse with the
// built-in rows): its row's tool ("git" for "git commit" and for /usr/bin/git), "" for a program no row describes or
// an entry that does not parse. Only a row's tool has helper images.
func entryTool(entry string) string {
	p, err := execmatch.Parse(entry, execmatch.ListAllow, rows.Builtin())
	if err != nil || p.Row == nil {
		return ""
	}
	return p.Tool
}
