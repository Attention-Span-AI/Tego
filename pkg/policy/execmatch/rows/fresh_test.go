// SPDX-License-Identifier: Apache-2.0

package rows

import (
	"bytes"
	"maps"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
)

// installedGit is the installed git, skipping the test when there is none.
func installedGit(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git installed")
	}
	return p
}

// gitEnv is an environment with no system, global or user configuration (so no alias or help.autocorrect setting
// reaches the probe) and a C locale.
func gitEnv(home string) []string {
	return []string{"HOME=" + home, "PATH=" + os.Getenv("PATH"), "LANG=C", "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=a", "GIT_AUTHOR_EMAIL=a@b", "GIT_COMMITTER_NAME=a", "GIT_COMMITTER_EMAIL=a@b",
		"GIT_TERMINAL_PROMPT=0"}
}

// gitList runs git --list-cmds=<what>.
func gitList(t *testing.T, git, what string) []string {
	t.Helper()
	cmd := exec.Command(git, "--list-cmds="+what)
	cmd.Env = gitEnv(t.TempDir())
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git --list-cmds=%s: %v", what, err)
	}
	return strings.Fields(string(out))
}

// TestGitRowFresh is the freshness test of ADR 0048 (2): the installed git's built-ins and common group are supersets
// of the row's, so the autocorrect candidate set stays a subset of git's own (R4: drift there is a fail-open
// regression, so it fails the build).
func TestGitRowFresh(t *testing.T) {
	git := installedGit(t)
	have := map[string]bool{}
	for _, n := range gitList(t, git, "builtins") {
		have[n] = true
	}
	for _, n := range gitBuiltins {
		if !have[n] {
			t.Errorf("the row lists built-in %q, which the installed git does not have: drop it from gitBuiltins", n)
		}
	}
	common := map[string]bool{}
	for _, n := range gitList(t, git, "list-init,list-worktree,list-info,list-history,list-remote") {
		common[n] = true
	}
	for _, n := range gitCommon {
		if !common[n] {
			t.Errorf("the row's common group holds %q, which the installed git's does not", n)
		}
	}
	// git remote's rm alias: the installed git must still accept `git remote rm`, or the
	// row's alias of remove no longer tracks git and `git remote rm` would slip a deny: [git remote remove]. git
	// answers "No such remote" for an alias it accepts and "Unknown subcommand: rm" for one it does not.
	dir := t.TempDir()
	if out, err := gitAt(git, dir, "init", "-q", dir); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	for _, sub := range []string{"rm", "remove"} {
		out, _ := gitAt(git, dir, "remote", sub, "no-such-remote")
		if strings.Contains(out, "Unknown subcommand") {
			t.Errorf("git remote %s is no longer accepted by the installed git: %s", sub, strings.TrimSpace(out))
		}
	}
	gitGlobalOptionsFresh(t, git, dir)
	gitVerbsFresh(t, git, dir)
}

// gitGlobalOptionValues are the values the global-option probe passes to the row's value-taking global options, by
// the option's name: each is one git accepts without touching anything outside the probe's directory. A global option
// the row adds needs an entry here, or the probe fails naming it.
var gitGlobalOptionValues = map[string]string{
	"C": ".", "c": "a.b=c", "config-env": "a.b=HOME", "git-dir": ".git", "work-tree": ".", "namespace": "x",
	"attr-source": "HEAD", "shallow-file": "shallow", "exec-path": "/nonexistent-exec-path", "list-cmds": "builtins",
}

// gitGlobalOptionsFresh holds the row's global options (the root level's) to the installed git: git.c's
// handle_options answers "unknown option: <opt>" for one it does not have. A row that still lists such an option reads
// it as a global option and eats the next word as its value, misreading the subcommand after it (git 2.49 removed
// --super-prefix, which the row listed as taking a value); dropped, the word is unknown and read both ways, as a flag
// and as taking the next word (ambiguous), which covers the older gits that still have it. Every spelling is probed,
// each with a value when it takes one. An option the installed git has and the row does not (a newer git's) is not a
// failure, for the same reason: an unknown word is read both ways.
func gitGlobalOptionsFresh(t *testing.T, git, dir string) {
	t.Helper()
	probed := 0
	for _, o := range Git().Root.Opts {
		var spellings []string
		for _, l := range o.Long {
			spellings = append(spellings, "--"+l)
		}
		for i := 0; i < len(o.Short); i++ {
			spellings = append(spellings, "-"+o.Short[i:i+1])
		}
		v, hasValue := gitGlobalOptionValues[o.Name]
		if o.Arg != execmatch.ArgNone && !hasValue {
			t.Errorf("the git row's global option %q takes a value and the probe has none for it: add it to gitGlobalOptionValues", o.Name)
			continue
		}
		for _, sp := range spellings {
			var args []string
			switch {
			case o.AsSub != "":
				args = []string{sp} // --help and --version run git help and git version on their own
			case o.Arg == execmatch.ArgNone:
				args = []string{sp, "version"}
			case o.Arg == execmatch.ArgOptional:
				args = []string{sp + "=" + v, "version"} // --exec-path=, --list-cmds=: attached only
			default:
				// The separate form, which every value-taking global option of git.c has (--shallow-file has no
				// attached form; the row reading `--shallow-file=x` as the option is the over-reading direction:
				// git refuses that spelling and runs nothing).
				args = []string{sp, v, "version"}
			}
			out, _ := gitAt(git, dir, args...)
			probed++
			if strings.Contains(out, "unknown option") {
				t.Errorf("the git row lists global option %s, which the installed git does not have (%s): drop it from the row's root level",
					sp, strings.TrimSpace(strings.SplitN(out, "\n", 2)[0]))
			}
		}
	}
	if probed == 0 {
		t.Fatal("no global option probed: the probe proves nothing")
	}
}

// gitVerbWord reports a word spelled as git spells a verb: lower-case letters and dashes, a letter first.
func gitVerbWord(w string) bool {
	if w == "" || w[0] < 'a' || w[0] > 'z' {
		return false
	}
	return strings.Trim(w, "abcdefghijklmnopqrstuvwxyz-") == ""
}

// gitUsageVerb reads one usage line of `git <cmd> -h` ("usage: git <cmd> ..." or "or: git <cmd> ...") into the
// verbs it names, after any leading option group ("[--quiet]", "[<options>]"): a plain word, an alternation
// "(good|bad)", "( pop | apply )" or "[clear | forget <pathspec>... | gc]" (the first word of each alternative), or an
// optional default "[show]". A line that puts <subcommand> where the verb stands ("git maintenance <subcommand>
// [<options>]") names none, and reports it: the command has verbs this usage does not name.
func gitUsageVerb(line, cmd string) (verbs []string, unnamed bool) {
	line = strings.TrimSpace(line)
	for _, p := range []string{"usage:", "or:"} {
		line = strings.TrimSpace(strings.TrimPrefix(line, p))
	}
	rest, ok := strings.CutPrefix(line, "git "+cmd+" ")
	if !ok {
		return nil, false
	}
	rest = strings.TrimSpace(rest)
	// group is the content of the bracketed group rest starts with, up to its matching closer, and what follows it.
	group := func(s string) (inner, after string, ok bool) {
		depth := 0
		for i := 0; i < len(s); i++ {
			switch s[i] {
			case '[', '(':
				depth++
			case ']', ')':
				if depth--; depth == 0 {
					return s[1:i], strings.TrimSpace(s[i+1:]), true
				}
			}
		}
		return "", "", false
	}
	for strings.HasPrefix(rest, "[-") || strings.HasPrefix(rest, "[<") {
		var ok bool
		if _, rest, ok = group(rest); !ok {
			return nil, false
		}
	}
	if !strings.HasPrefix(rest, "(") && !strings.HasPrefix(rest, "[") {
		f := strings.Fields(rest)
		if len(f) > 0 && gitVerbWord(f[0]) {
			return []string{f[0]}, false
		}
		return nil, len(f) > 0 && f[0] == "<subcommand>"
	}
	inner, _, ok := group(rest)
	if !ok {
		return nil, false
	}
	var out []string
	alt := func(a string) {
		if f := strings.Fields(a); len(f) > 0 && gitVerbWord(f[0]) {
			out = append(out, f[0])
		}
	}
	depth, from := 0, 0
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '[', '(':
			depth++
		case ']', ')':
			depth--
		case '|':
			if depth == 0 {
				alt(inner[from:i])
				from = i + 1
			}
		}
	}
	alt(inner[from:])
	return out, false
}

// gitCompletionVerbs reads a command's completion listing (`git <cmd> --git-completion-helper-all`, which
// git-completion.bash reads) into the subcommands it names. parse-options prints the command's OPT_SUBCOMMAND table
// there bare, its hidden entries too (git remote rm, git stash save), beside its options, which keep their dashes;
// git 2.39 through 2.56 print it the same way (parse-options.c show_gitcomp). A command that is not parse-options'
// (git submodule's script) answers with its usage and fails, and the caller passes no listing for it.
func gitCompletionVerbs(listing string) []string {
	var verbs []string
	for _, w := range strings.Fields(listing) {
		if gitVerbWord(w) {
			verbs = append(verbs, w)
		}
	}
	return verbs
}

// gitListedVerbs are the verbs git lists for one two-level command, each once: those its usage names (`git <cmd>
// -h`) and those its completion listing names ("" when the command does not answer it). unnamed reports a usage that
// puts <subcommand> where the verb stands: `git maintenance -h` names none of its verbs in any supported git, and
// only the completion listing does.
func gitListedVerbs(cmd, usage, listing string) (verbs []string, unnamed bool) {
	seen := map[string]bool{}
	add := func(vs []string) {
		for _, v := range vs {
			if !seen[v] {
				seen[v] = true
				verbs = append(verbs, v)
			}
		}
	}
	for _, line := range strings.Split(usage, "\n") {
		vs, u := gitUsageVerb(line, cmd)
		add(vs)
		unnamed = unnamed || u
	}
	add(gitCompletionVerbs(listing))
	return verbs, unnamed
}

// gitVerbGaps are the verbs git lists for a two-level command that the row's level has neither as a subcommand nor
// as an alias, one failure line each.
func gitVerbGaps(cmd string, lv *execmatch.Level, verbs []string) []string {
	var gaps []string
	for _, v := range verbs {
		_, sub := lv.Subs[v]
		_, alias := lv.Alias[v]
		if !sub && !alias {
			gaps = append(gaps, "git "+cmd+" "+v+": the installed git lists the verb, and the row's "+cmd+
				" level has no such subcommand or alias")
		}
	}
	return gaps
}

// gitVerbsFresh holds every two-level command of the row (a level with subcommands: stash, remote, bisect, ...) to
// the verbs the installed git lists for it in its usage and its completion listing (gitListedVerbs): each must be a
// subcommand or an alias of the row's level. A word a level lacks is read as an unknown subcommand, matched only as
// written. When git added it as an alias of a verb (git remote rm for remove), a rule on the verb misses it, which
// fails open (R4); when it is a verb of its own (git bisect next, git reflog write), the row no longer says what
// the command takes. Either way git's manual says which it is, and the row must follow. A verb the row has and the
// installed git does not (another version's) is not reported: the row covers every supported git. A command whose
// usage puts <subcommand> where its verbs stand and whose completion listing names none fails, rather than going
// unchecked.
func gitVerbsFresh(t *testing.T, git, dir string) {
	t.Helper()
	row := Git()
	checked := 0
	for _, name := range slices.Sorted(maps.Keys(row.Root.Subs)) {
		lv := row.Root.Subs[name]
		if len(lv.Subs) == 0 {
			continue
		}
		usage, _ := gitAt(git, dir, name, "-h")
		listing, err := gitStdoutAt(git, dir, name, "--git-completion-helper-all")
		if err != nil {
			listing = "" // not parse-options' (a script): it printed its usage and failed
		}
		verbs, unnamed := gitListedVerbs(name, usage, listing)
		switch {
		case len(verbs) == 0 && unnamed:
			t.Errorf("git %s has verbs its usage does not name, and its completion listing names none, so none is checked: %s",
				name, strings.TrimSpace(usage))
			continue
		case len(verbs) == 0:
			t.Logf("git %s lists no verb (its verbs are not checked): %s", name, strings.TrimSpace(usage))
			continue
		}
		checked++
		for _, gap := range gitVerbGaps(name, lv, verbs) {
			t.Error(gap)
		}
	}
	if checked == 0 {
		t.Fatal("no two-level command's verbs read from the installed git: the probe proves nothing")
	}
}

// gitRecorded is what two gits print for `git <cmd> -h` and `git <cmd> --git-completion-helper-all`, for the
// two-level commands whose verbs changed after 2.51.0 and for git maintenance, whose usage names none. 2.51.0 is this
// host's git (Ubuntu 25.10), captured. 2.56.0 is the git of the first CI run on GitHub's runners (2026-11-02,
// ubuntu-24.04 and ubuntu-24.04-arm), rebuilt from v2.56.0's builtin/hook.c, reflog.c, multi-pack-index.c and gc.c
// as parse-options.c's usage_with_options and show_gitcomp print them; that run's log quotes the maintenance usage
// line as it stands here.
var gitRecorded = []struct {
	git, cmd, usage, listing string
	verbs                    string // what the probe reads, sorted
}{
	{"2.51.0", "hook", `usage: git hook run [--ignore-missing] [--to-stdin=<path>] <hook-name> [-- <hook-args>]

`, "run\n", "run"},
	{"2.51.0", "reflog", `usage: git reflog [show] [<log-options>] [<ref>]
   or: git reflog list
   or: git reflog expire [--expire=<time>] [--expire-unreachable=<time>]
                         [--rewrite] [--updateref] [--stale-fix]
                         [--dry-run | -n] [--verbose] [--all [--single-worktree] | <refs>...]
   or: git reflog delete [--rewrite] [--updateref]
                         [--dry-run | -n] [--verbose] <ref>@{<specifier>}...
   or: git reflog drop [--all [--single-worktree] | <refs>...]
   or: git reflog exists <ref>

`, "show list expire delete exists drop\n", "delete drop exists expire list show"},
	{"2.51.0", "multi-pack-index", `usage: git multi-pack-index [<options>] write [--preferred-pack=<pack>][--refs-snapshot=<path>]
   or: git multi-pack-index [<options>] verify
   or: git multi-pack-index [<options>] expire
   or: git multi-pack-index [<options>] repack [--batch-size=<size>]

    --[no-]object-dir <directory>
                          object directory containing set of packfile and pack-index pairs

`, "repack write verify expire --object-dir= --no-object-dir\n", "expire repack verify write"},
	{"2.51.0", "maintenance", `usage: git maintenance <subcommand> [<options>]

`, "run start stop register unregister\n", "register run start stop unregister"},
	{"2.56.0", "hook", `usage: git hook run [--allow-unknown-hook-name] [--ignore-missing] [--to-stdin=<path>] [(-j|--jobs) <n>]
       <hook-name> [-- <hook-args>]
   or: git hook list [--allow-unknown-hook-name] [-z] [--show-scope] <hook-name>

`, "run list\n", "list run"},
	{"2.56.0", "reflog", `usage: git reflog [show] [<log-options>] [<ref>]
   or: git reflog list
   or: git reflog exists <ref>
   or: git reflog write <ref> <old-oid> <new-oid> <message>
   or: git reflog delete [--rewrite] [--updateref]
                         [--dry-run | -n] [--verbose] <ref>@{<specifier>}...
   or: git reflog drop [--all [--single-worktree] | <refs>...]
   or: git reflog expire [--expire=<time>] [--expire-unreachable=<time>]
                         [--rewrite] [--updateref] [--stale-fix]
                         [--dry-run | -n] [--verbose] [--all [--single-worktree] | <refs>...]

`, "show list exists write delete drop expire\n", "delete drop exists expire list show write"},
	{"2.56.0", "multi-pack-index", `usage: git multi-pack-index [<options>] write [--preferred-pack=<pack>]
         [--[no-]bitmap] [--[no-]incremental] [--[no-]stdin-packs]
         [--refs-snapshot=<path>] [--[no-]write-chain-file]
         [--base=<checksum>]
   or: git multi-pack-index [<options>] compact [--[no-]incremental]
         [--[no-]bitmap] [--base=<checksum>] [--[no-]write-chain-file]
         <from> <to>
   or: git multi-pack-index [<options>] verify
   or: git multi-pack-index [<options>] expire
   or: git multi-pack-index [<options>] repack [--batch-size=<size>]

    --[no-]object-dir <directory>
                          object directory containing set of packfile and pack-index pairs
    --[no-]progress       force progress reporting

`, "repack write compact verify expire --object-dir= --progress --no-object-dir -- --no-progress\n",
		"compact expire repack verify write"},
	{"2.56.0", "maintenance", `usage: git maintenance <subcommand> [<options>]

`, "run start stop register unregister is-needed\n", "is-needed register run start stop unregister"},
}

// TestGitVerbsRecorded runs TestGitRowFresh's verb probe over recorded output of this host's git and of a newer one:
// it reads every verb each git lists, git maintenance's from the completion listing alone, and the row's levels hold
// them all. Against git 2.56.0's output, the row without the verbs gits 2.51.1 and 2.54 added fails with the three
// lines the first CI run on git 2.56.0 failed TestGitRowFresh with.
func TestGitVerbsRecorded(t *testing.T) {
	row := Git()
	for _, rec := range gitRecorded {
		verbs, unnamed := gitListedVerbs(rec.cmd, rec.usage, rec.listing)
		if got := strings.Join(slices.Sorted(slices.Values(verbs)), " "); got != rec.verbs {
			t.Errorf("git %s %s: the probe reads %q, want %q", rec.git, rec.cmd, got, rec.verbs)
		}
		if rec.cmd == "maintenance" {
			// Its usage alone names no verb: without the listing the live probe fails, rather than skipping it.
			if fromUsage, _ := gitListedVerbs(rec.cmd, rec.usage, ""); len(fromUsage) != 0 || !unnamed {
				t.Errorf("git %s maintenance -h: read %v from the usage (unnamed %v), want none and its <subcommand> seen",
					rec.git, fromUsage, unnamed)
			}
		}
		for _, gap := range gitVerbGaps(rec.cmd, row.Root.Subs[rec.cmd], verbs) {
			t.Errorf("git %s: %s", rec.git, gap)
		}
	}
	before := Git()
	delete(before.Root.Subs["hook"].Subs, "list")
	delete(before.Root.Subs["reflog"].Subs, "write")
	delete(before.Root.Subs["multi-pack-index"].Subs, "compact")
	var gaps []string
	for _, rec := range gitRecorded {
		if rec.git == "2.56.0" {
			verbs, _ := gitListedVerbs(rec.cmd, rec.usage, rec.listing)
			gaps = append(gaps, gitVerbGaps(rec.cmd, before.Root.Subs[rec.cmd], verbs)...)
		}
	}
	slices.Sort(gaps)
	want := []string{
		"git hook list: the installed git lists the verb, and the row's hook level has no such subcommand or alias",
		"git multi-pack-index compact: the installed git lists the verb, and the row's multi-pack-index level has no such subcommand or alias",
		"git reflog write: the installed git lists the verb, and the row's reflog level has no such subcommand or alias",
	}
	if !slices.Equal(gaps, want) {
		t.Errorf("the row before 2026-11-02 against git 2.56.0:\n%s\nwant the first CI run's:\n%s",
			strings.Join(gaps, "\n"), strings.Join(want, "\n"))
	}
}

// gitAt runs git in dir with a hermetic environment and returns its combined output.
func gitAt(git, dir string, args ...string) (string, error) {
	cmd := exec.Command(git, args...)
	cmd.Dir, cmd.Env = dir, gitEnv(dir)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// gitStdoutAt runs git in dir with a hermetic environment and returns its standard output alone.
func gitStdoutAt(git, dir string, args ...string) (string, error) {
	cmd := exec.Command(git, args...)
	cmd.Dir, cmd.Env = dir, gitEnv(dir)
	out, err := cmd.Output()
	return string(out), err
}

// gitTarget asks the installed git where it would autocorrect a token: in its default hint mode it lists the commands
// it finds most similar, and lists exactly one when help.autocorrect=immediate would run that one.
func gitTarget(git, dir, tok string) (string, error) {
	cmd := exec.Command(git, tok)
	cmd.Dir = dir
	cmd.Env = gitEnv(dir)
	cmd.Stdin = nil
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return "", err
	}
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
	out := stderr.String()
	if _, after, ok := strings.Cut(out, "The most similar command is\n"); ok {
		return strings.TrimSpace(strings.SplitN(after, "\n", 2)[0]), nil
	}
	return "", nil
}

// TestGitAutocorrectDifferential is the differential test of ADR 0048 (2) against the installed git: with git's own
// candidate set the port reaches exactly what git reaches, and with the row's subset it reaches every target git
// reaches that the subset holds. Tokens are single edits of the commands deny entries name, a seeded sample of double
// edits and random tokens, and the measured tokens; TEGO_GIT_DIFF_FULL=1 runs single edits of every common command.
func TestGitAutocorrectDifferential(t *testing.T) {
	git := installedGit(t)
	main := gitList(t, git, "main,others")
	common := gitList(t, git, "list-init,list-worktree,list-info,list-history,list-remote")
	own := execmatch.NewCandidates(main, common)
	sub := execmatch.NewCandidates(gitBuiltins, gitCommon)
	isCmd := map[string]bool{}
	for _, n := range main {
		isCmd[n] = true
	}
	base := []string{"push", "pull", "commit", "reset", "clean", "rebase", "fetch", "status", "gc", "rm"}
	if os.Getenv("TEGO_GIT_DIFF_FULL") == "1" {
		base = append(base, gitCommon...)
	}
	toks := map[string]bool{}
	for _, w := range []string{"psh", "pusg", "psuh", "puhs", "Push", "push ", "pυsh", "pus", "lfs", "gui", "ls", "sh", "stauts", "comit", "rset"} {
		toks[w] = true
	}
	alphabet := "abcdefghijklmnopqrstuvwxyz"
	rng := rand.New(rand.NewSource(48))
	for _, w := range base {
		for _, e := range edits(w, alphabet) {
			toks[e] = true
		}
		singles := edits(w, "aehiklmnorstu")
		for i := 0; i < 20; i++ {
			e := singles[rng.Intn(len(singles))]
			es := edits(e, "aehiklmnorstu")
			toks[es[rng.Intn(len(es))]] = true
		}
	}
	for i := 0; i < 100; i++ {
		n := 1 + rng.Intn(8)
		b := make([]byte, n)
		for j := range b {
			b[j] = alphabet[rng.Intn(len(alphabet))]
		}
		toks[string(b)] = true
	}
	var list []string
	for tk := range toks {
		if tk != "" && tk[0] != '-' && !isCmd[tk] && !strings.ContainsAny(tk, "/\x00") {
			list = append(list, tk)
		}
	}
	sort.Strings(list)
	dir := t.TempDir()
	type res struct{ tok, git string }
	out := make([]res, len(list))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, tk := range list {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			g, err := gitTarget(git, dir, tk)
			if err != nil {
				t.Errorf("git %q: %v", tk, err)
			}
			out[i] = res{tk, g}
		}()
	}
	wg.Wait()
	reached := 0
	for _, r := range out {
		p, _ := execmatch.Autocorrect(r.tok, own)
		if p != r.git {
			t.Errorf("token %q: git reaches %q, the port with git's own candidates %q", r.tok, r.git, p)
		}
		if r.git != "" && sub.Has(r.git) {
			reached++
			if q, _ := execmatch.Autocorrect(r.tok, sub); q != r.git {
				t.Errorf("token %q: git reaches %q, the port with the row's subset %q (a fail-open miss)", r.tok, r.git, q)
			}
		}
	}
	t.Logf("%d tokens, %d reach a row candidate", len(out), reached)
}

// edits are the single edits of w over an alphabet: deletions, adjacent transpositions, substitutions, insertions.
func edits(w, alphabet string) []string {
	var out []string
	for i := 0; i < len(w); i++ {
		out = append(out, w[:i]+w[i+1:])
		if i+1 < len(w) {
			out = append(out, w[:i]+string(w[i+1])+string(w[i])+w[i+2:])
		}
		for j := 0; j < len(alphabet); j++ {
			out = append(out, w[:i]+string(alphabet[j])+w[i+1:])
		}
	}
	for i := 0; i <= len(w); i++ {
		for j := 0; j < len(alphabet); j++ {
			out = append(out, w[:i]+string(alphabet[j])+w[i:])
		}
	}
	return out
}

// TestRmRowDifferential holds the rm row to the installed rm: every spelling that removes a tree without a tty is
// read as recursive, so `deny: rm -r` refuses it.
func TestRmRowDifferential(t *testing.T) {
	rm, err := exec.LookPath("rm")
	if err != nil {
		t.Skip("no rm installed")
	}
	ix := rules(t, "deny: rm -r")
	spellings := [][]string{
		{"-r"}, {"-R"}, {"-rf"}, {"-fr"}, {"-dr"}, {"-fR"}, {"--recursive"}, {"--rec"}, {"--recu"}, {"-v", "-r"},
		{"-rv"}, {"-f", "--recursive"}, {"@", "--recursive"}, {"@", "-r"}, {"-d"}, {"-f"}, {"--", "-r"}, {"-I", "-r"},
		{"--one-file-system", "-r"}, {"--preserve-root", "-r"}, {"--interactive=never", "-r"}, {"-rd"},
	}
	for _, sp := range spellings {
		dir := t.TempDir()
		tree := filepath.Join(dir, "tree")
		if err := os.MkdirAll(filepath.Join(tree, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tree, "sub", "f"), []byte("x"), 0o444); err != nil {
			t.Fatal(err)
		}
		args := []string{}
		placed := false
		for _, a := range sp {
			if a == "@" {
				args, placed = append(args, tree), true
				continue
			}
			args = append(args, a)
		}
		if !placed {
			args = append(args, tree)
		}
		cmd := exec.Command(rm, args...)
		cmd.Stdin = nil
		_ = cmd.Run()
		_, statErr := os.Stat(tree)
		removed := os.IsNotExist(statErr)
		argv := append([]string{"rm"}, args...)
		denied := run(ix, argv...).Outcome == execmatch.OutcomeRefused
		if removed && !denied {
			t.Errorf("rm %s removed the tree, and deny rm -r does not refuse it", strings.Join(args, " "))
		}
		if !removed && denied {
			t.Logf("rm %s left the tree; deny rm -r refuses it (an over-approximation)", strings.Join(args, " "))
		}
	}
}

// TestGitHelperClosureFresh holds git's helper closure to the installed git: every git child an operation runs, read
// from GIT_TRACE against a local bare repository, is in the closure of the operation (R4: a new helper fails closed,
// and this test names it).
func TestGitHelperClosureFresh(t *testing.T) {
	git := installedGit(t)
	if testing.Short() {
		t.Skip("runs git operations")
	}
	w := t.TempDir()
	env := gitEnv(w)
	runGit := func(dir string, trace bool, args ...string) string {
		t.Helper()
		cmd := exec.Command(git, args...)
		cmd.Dir = dir
		cmd.Env = env
		if trace {
			cmd.Env = append(cmd.Env, "GIT_TRACE=1")
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	runGit(w, false, "-c", "init.defaultBranch=main", "init", "-q", "--bare", "remote.git")
	runGit(w, false, "-c", "init.defaultBranch=main", "init", "-q", "work")
	work := filepath.Join(w, "work")
	for _, f := range []string{"a", "b", "c"} {
		if err := os.WriteFile(filepath.Join(work, f), []byte(f), 0o644); err != nil {
			t.Fatal(err)
		}
		runGit(work, false, "add", f)
		runGit(work, false, "commit", "-q", "-m", f)
	}
	runGit(work, false, "remote", "add", "origin", filepath.Join(w, "remote.git"))
	ops := [][]string{
		{"-c", "gc.auto=1", "push", "-q", "origin", "main"},
		{"fetch", "-q", "origin"},
		{"pull", "-q", "--no-rebase", "origin", "main"},
		{"-c", "gc.auto=1", "-c", "maintenance.autoDetach=false", "-c", "gc.autoDetach=false", "commit", "-q", "--allow-empty", "-m", "d"},
		{"gc", "-q"},
		{"repack", "-q", "-a", "-d"},
	}
	seen := 0
	for _, op := range ops {
		out := runGit(work, true, op...)
		p, err := execmatch.Parse("git "+strings.Join(op, " "), execmatch.ListDeny, Builtin())
		if err != nil {
			t.Fatal(err)
		}
		closure := execmatch.Closure(Git(), p.Path[0])
		children := traceChildren(out)
		seen += len(children)
		t.Logf("git %s runs %v", p.Path[0], children)
		for _, child := range children {
			if child == p.Path[0] {
				continue
			}
			first, _, _ := strings.Cut(child, " ")
			if !closure[child] && !closure[first] {
				t.Errorf("git %s runs git %s, which its closure does not list", p.Path[0], child)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no git child seen in any trace: the probe proves nothing")
	}
}

// traceChildren extracts the git subcommands a GIT_TRACE log shows run as children (run_command lines naming git or
// a git-<cmd> helper), each as its subcommand and second word.
func traceChildren(log string) []string {
	var out []string
	nz := execmatch.NewNormalizer(Git(), nil)
	for _, line := range strings.Split(log, "\n") {
		_, cmd, ok := strings.Cut(line, "trace: run_command: ")
		if !ok {
			continue
		}
		if i := strings.LastIndex(cmd, "; "); i >= 0 {
			cmd = cmd[i+2:] // the local transport's "unset GIT_DIR ...; 'git-upload-pack ...'"
		}
		fields := strings.Fields(strings.NewReplacer("'", "", "\"", "").Replace(cmd))
		for len(fields) > 0 && strings.Contains(fields[0], "=") {
			fields = fields[1:]
		}
		if len(fields) == 0 {
			continue
		}
		var toks []string
		switch {
		case fields[0] == "git":
			toks = fields[1:]
		case strings.HasPrefix(fields[0], "git-"):
			toks = append([]string{strings.TrimPrefix(fields[0], "git-")}, fields[1:]...)
		default:
			continue
		}
		for _, r := range nz.Normalize(toks) {
			if len(r.Path) > 0 {
				out = append(out, strings.Join(r.Path[:min(2, len(r.Path))], " "))
			}
		}
	}
	return out
}
