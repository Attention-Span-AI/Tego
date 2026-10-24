// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/attention-span-ai/tego/internal/maze/scan"
	"github.com/attention-span-ai/tego/internal/maze/scope"
	"github.com/attention-span-ai/tego/internal/platform/proc"
)

// agentID is the agent Release 1 sets up.
const agentID = "claude"

// saved is what saving did, for the lines that stay on the terminal afterwards.
type saved struct {
	// gaps are rules the engine doesn't enforce yet, in plain words.
	gaps []string
	// checks is how many engine checks the verdict table holds; passed how many passed, when the engine ran.
	checks, passed int
	// checked reports whether the engine ran the checks; note says why not, or what failed.
	checked bool
	note    string
	// hook is what happened to the pre-push check.
	hook scope.HookResult
}

// save writes the approved rules: the project's to .maze/workspace.yaml (and records them as approved), the
// person's own to ~/.maze/personal.yaml (keeping rules saved there from other projects), the engine contract
// and its checks to .maze/compiled/, then asks the engine to check the contract where the engine exists.
func save(ctx context.Context, r Report, rules []Rule) (saved, error) {
	// Everything below is one change: nothing else may write the rules meanwhile.
	unlock, err := scope.Lock(ctx, r.Home)
	if err != nil {
		return saved{}, err
	}
	defer unlock()
	return saveLocked(ctx, r, rules)
}

// saveLocked is save for a caller that already holds the lock, because it read the rules it changes under it
// (maze allow/block): reading and writing under one lock is what keeps two commands from losing a change.
func saveLocked(ctx context.Context, r Report, rules []Rule) (saved, error) {
	root, home := r.Workspace.Root, r.Home
	var ws, personal []Rule
	for _, rl := range rules {
		if rl.Scope == "personal" {
			personal = append(personal, rl)
			continue
		}
		ws = append(ws, rl)
	}
	if !r.personalLoaded {
		// A first setup suggests personal rules from this project's look around; the person may already have
		// rules from other projects, which stay. Rules loaded from the files are already all of them.
		existing, _, err := scope.LoadPersonal(home)
		if err != nil {
			return saved{}, err
		}
		personal = mergeRules(existing.Rules, personal)
	}
	// What can fail is done first, in memory or outside the project; the approval record is written last, so a
	// save that fails halfway never leaves rules marked approved without their contract and hook.
	key, err := scope.EnsureAgentKey(home)
	if err != nil {
		return saved{}, err
	}
	c, err := scope.Compile(scope.Input{Root: root, Home: home, Name: r.Workspace.ID, Rules: append(append([]Rule(nil), ws...), personal...), LookPath: r.env.LookPath, Agent: &key})
	if err != nil {
		return saved{}, err
	}
	if err := scope.SavePersonal(home, scope.Personal{Rules: personal}); err != nil {
		return saved{}, err
	}
	if r.loaded != nil && !r.keepFile {
		if now, err := scope.CurrentWorkspace(root); err == nil && !bytes.Equal(now, r.loaded) {
			return saved{}, errStale
		}
	}
	var data []byte
	if r.keepFile {
		data, err = scope.CurrentWorkspace(root)
	} else {
		data, err = scope.SaveWorkspace(root, scope.Workspace{Name: r.Workspace.Name, Owner: os.Getenv("USER"), Agent: agentID, Rules: ws})
	}
	if err != nil {
		return saved{}, err
	}
	contract, err := scope.SaveCompiled(home, root, c, agentID)
	if err != nil {
		return saved{}, err
	}
	// A pre-push check that can't be added is said after saving; it never stops the rules from being saved.
	hook, err := scope.InstallPrePush(home, root)
	if err != nil {
		hook = scope.HookResult{Skipped: err.Error()}
	}
	if err := scope.Approve(home, root, data); err != nil {
		return saved{}, err
	}
	out := saved{gaps: c.Gaps, checks: c.Checks, hook: hook}
	out.checked, out.passed, out.note = verifyEngine(ctx, r.env, root, contract)
	return out, nil
}

// errStale is a save refused because the rules file changed while the person was editing.
var errStale = errors.New("the rules for this project changed while you were editing (another maze command, or an edit). Nothing was saved: run maze again to see the latest")

// mergeRules keeps old rules and replaces the ones fresh also has, by key, so rules saved from another project
// aren't lost when this one is saved.
func mergeRules(old, fresh []Rule) []Rule {
	byKey := map[string]int{}
	out := append([]Rule(nil), old...)
	for i, r := range out {
		byKey[r.Key()] = i
	}
	for _, r := range fresh {
		if i, ok := byKey[r.Key()]; ok {
			out[i] = r
			continue
		}
		byKey[r.Key()] = len(out)
		out = append(out, r)
	}
	for i := range out {
		out[i].Scope = "personal"
	}
	return out
}

// loadSaved reads the rules saved for this project and the person's own, or ok false when the project isn't set
// up.
func loadSaved(r Report) (rules []Rule, ok bool, err error) {
	w, ok, err := scope.LoadWorkspace(r.Workspace.Root)
	if err != nil || !ok {
		return nil, ok, err
	}
	p, _, err := scope.LoadPersonal(r.Home)
	if err != nil {
		return nil, true, err
	}
	return ensureLocked(r, append(w.Rules, p.Rules...)), true, nil
}

// passedLine is the summary `tego compile --test` ends with.
var passedLine = regexp.MustCompile(`(\d+) rows: (\d+) passed, (\d+) failed`)

// verifyEngine runs the engine's check of the contract where the engine runs: on Linux, with tego on PATH,
// from the project folder (so its built-in .env protection covers it). Elsewhere it says why it didn't run,
// rather than pretend.
func verifyEngine(ctx context.Context, env scan.Env, root, contract string) (checked bool, passed int, note string) {
	if runtime.GOOS != "linux" {
		return false, 0, "" // the engine runs on Linux; "Not active yet" already covers this Mac
	}
	tego := env.LookPath("tego")
	if tego == "" {
		return false, 0, "The engine isn't installed, so these rules weren't checked."
	}
	// A tego the project ships (direnv's PATH_add bin, node_modules/.bin) is the project's code, not the engine:
	// it would run on every save, so it is never run.
	if inside(root, tego) {
		return false, 0, "The tego first on PATH (" + tego + ") is inside this project, so it wasn't run and these rules weren't checked."
	}
	verdicts := strings.TrimSuffix(contract, ".yaml") + ".verdicts.yaml"
	cmd := proc.Command(tego, "compile", contract, "--test", verdicts, "--offline")
	cmd.Dir = root
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if _, err := proc.Start(cmd); err != nil {
		return false, 0, "The engine didn't start: " + err.Error()
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return false, 0, "Stopped before the engine finished."
	}
	m := passedLine.FindStringSubmatch(out.String())
	if m == nil {
		// No summary: the engine stopped before checking (its machine config, a contract it can't read). Its first
		// line says why.
		if line := firstLine(out.String()); line != "" {
			return false, 0, "The engine didn't check the rules: " + line
		}
		return false, 0, "The engine refused the rules; run `" + filepath.Base(tego) + " compile " + contract + "` to see why."
	}
	var total, ok, failed int
	if _, err := fmt.Sscan(m[1]+" "+m[2]+" "+m[3], &total, &ok, &failed); err != nil {
		return false, 0, "Couldn't read the engine's answer."
	}
	if failed > 0 || waitErr != nil {
		return true, ok, fmt.Sprintf("%d of %d engine checks failed; run `tego compile %s --test %s` to see which.", failed, total, contract, verdicts)
	}
	return true, ok, ""
}

// inside reports whether path is root or beneath it, with links resolved on both sides.
func inside(root, path string) bool {
	for _, pair := range [][2]string{{root, path}, {resolved(root), resolved(path)}} {
		if rel, err := filepath.Rel(pair[0], pair[1]); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// resolved is p with its links resolved, or p when that fails.
func resolved(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

// firstLine is the first non-blank line of out, cut at 200 characters, or "" when it holds an unprintable
// character (the engine's own messages never do).
func firstLine(out string) string {
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if r := []rune(l); len(r) > 200 {
			l = string(r[:200]) + "…"
		}
		if !scope.Printable(l) {
			return ""
		}
		return l
	}
	return ""
}
