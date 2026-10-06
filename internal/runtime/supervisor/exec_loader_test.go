// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"encoding/binary"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// elfHead is the start of a little-endian ELF64 of type etype whose program headers have the given types.
func elfHead(etype uint16, phdrs ...uint32) []byte {
	b := make([]byte, 64+56*len(phdrs))
	copy(b, "\x7fELF")
	b[4], b[5], b[6] = 2, 1, 1
	binary.LittleEndian.PutUint16(b[16:], etype)
	binary.LittleEndian.PutUint64(b[32:], 64)
	binary.LittleEndian.PutUint16(b[54:], 56)
	binary.LittleEndian.PutUint16(b[56:], uint16(len(phdrs)))
	for i, t := range phdrs {
		binary.LittleEndian.PutUint32(b[64+56*i:], t)
	}
	return b
}

// withLoaders rebuilds a command policy's index with the given files as the host's dynamic loaders, as compile's
// loader identities give them.
func withLoaders(pol *Policy, paths ...string) *Policy {
	ec := pol.Rules.ExecCommands
	var ps []*execmatch.Pattern
	for _, e := range ec.Entries {
		ps = append(ps, e.Pattern)
	}
	lds := map[execmatch.ID]bool{}
	for _, p := range paths {
		id := fakeID(p)
		lds[execmatch.ID{Dev: id.dev, Ino: id.ino}] = true
	}
	ec.Index = execmatch.NewIndex(rows.Builtin(), ps, execmatch.IndexOptions{Loaders: lds})
	return pol
}

// TestExecCommandLoaderProgram: a dynamic loader run as a command runs its program in-process, with no execve of the
// program's own, so the program is decided as the exec's image (ADR 0048 (3)). Under deny:
// [rm -r, git push], `ld-linux-x86-64.so.2 /usr/bin/rm -rf tree` was allowed unmatched, and is refused via loader:
// by the operand's name, through a symlink the walk follows, behind loader options, under --argv0, and through a hard
// link to the loader under another name, known by its identity. A loader whose program cannot be read as the loader
// will is refused loader-unresolved; one that runs nothing (--help) is left alone. An image that is no loader by name
// or identity is no loader, whatever its ELF: a static-pie program has a loader's shape (ET_DYN,
// no PT_INTERP), and `rg git push` or `backup /usr/bin/rm -rf old` were refused as git push and rm -r. A copy of the
// loader is R2's copy.
func TestExecCommandLoaderProgram(t *testing.T) {
	nr := nrFor(t, "execve")
	const ld = "/lib64/ld-linux-x86-64.so.2"
	loaderHead := elfHead(3, 1, 1)
	ldImg := execImage{id: fakeID("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"), linked: true, link: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", here: true, head: loaderHead}
	rmImg := execImage{id: fakeID("/usr/bin/rm"), linked: true, link: "/usr/bin/rm", here: true, head: []byte("\x7fELF")}
	for _, c := range []struct {
		name    string
		path    string
		argv    []string
		verdict record.Verdict
		rule    string
	}{
		{"the operand names rm", ld, []string{ld, "/usr/bin/rm", "-rf", "tree"}, record.VerdictRefused, "exec.deny[rm -r]"},
		{"a symlink to rm", ld, []string{ld, "/work/x", "-r", "tree"}, record.VerdictRefused, "exec.deny[rm -r]"},
		{"behind loader options", ld, []string{ld, "--library-path", "/x", "--inhibit-cache", "--", "/usr/bin/rm", "-r", "tree"}, record.VerdictRefused, "exec.deny[rm -r]"},
		{"git under --argv0", ld, []string{ld, "--argv0", "ls", "/usr/bin/git", "push"}, record.VerdictRefused, "exec.deny[git push]"},
		{"a hard link to the loader", "/work/hardld", []string{"hardld", "/usr/bin/rm", "-r", "tree"}, record.VerdictRefused, "exec.deny[rm -r]"},
		{"a hard link to the loader and a word", "/work/hardld", []string{"hardld", "rm", "-r"}, record.VerdictRefused, ruleLoaderUnresolved},
		{"rm -f runs", ld, []string{ld, "/usr/bin/rm", "-f", "x"}, record.VerdictAllow, ruleUnmatched},
		{"--help runs nothing", ld, []string{ld, "--help"}, record.VerdictAllow, ruleUnmatched},
		{"an option no loader has", ld, []string{ld, "--frob", "x", "/usr/bin/rm", "-r", "t"}, record.VerdictRefused, ruleLoaderUnresolved},
		{"an operand with no slash", ld, []string{ld, "rm", "-r", "t"}, record.VerdictRefused, ruleLoaderUnresolved},
		{"an operand that does not resolve", ld, []string{ld, "/work/gone", "-r", "t"}, record.VerdictRefused, ruleLoaderUnresolved},
		{"a loader loading a loader", ld, []string{ld, ld, "/usr/bin/rm", "-r", "t"}, record.VerdictRefused, ruleLoaderUnresolved},
		{"a static-pie program and a word", "/work/rg", []string{"rg", "git", "push"}, record.VerdictAllow, ruleUnmatched},
		{"a static-pie program and a word naming rm", "/work/rg", []string{"rg", "rm", "-r"}, record.VerdictAllow, ruleUnmatched},
		{"a static-pie program and a path", "/work/backup", []string{"backup", "/usr/bin/rm", "-rf", "/old"}, record.VerdictAllow, ruleUnmatched},
		{"a static-pie program's option", "/work/rg", []string{"rg", "--files", "/usr/bin/rm", "-r"}, record.VerdictAllow, ruleUnmatched},
		{"a copy of the loader (R2)", "/work/myld", []string{"myld", "/usr/bin/rm", "-r", "tree"}, record.VerdictAllow, ruleUnmatched},
	} {
		f := newFake()
		f.images = map[string]execImage{
			ld:             ldImg,
			"/work/myld":   {id: fakeID("/work/myld"), linked: true, link: "/work/myld", here: true, head: loaderHead},
			"/work/rg":     {id: fakeID("/work/rg"), linked: true, link: "/work/rg", here: true, head: loaderHead},
			"/work/backup": {id: fakeID("/work/backup"), linked: true, link: "/work/backup", here: true, head: loaderHead},
			"/work/hardld": {id: ldImg.id, linked: true, link: "/work/hardld", here: true, head: loaderHead},
			"/usr/bin/rm":  rmImg,
			"/work/x":      rmImg,
		}
		f.imageErrs = map[string]error{"/work/gone": unix.ENOENT}
		l, sink := newTestLoop(t, f, withLoaders(commandPolicy(t, "deny: rm -r", "deny: git push"), "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"))
		execAt(l, f, nr, 42, 0, c.path, c.argv...)
		ev := sink.one(t)
		if ev.Verdict != c.verdict || ev.Rule != c.rule {
			t.Errorf("%s: %s %s, want %s %s", c.name, ev.Verdict, ev.Rule, c.verdict, c.rule)
		}
		if c.verdict == record.VerdictRefused && c.rule[0] == 'e' && execPayloadOf(t, ev).CommandVia != "loader" {
			t.Errorf("%s: via %q, want loader", c.name, execPayloadOf(t, ev).CommandVia)
		}
		wantExecAnswer(t, f, c.verdict)
	}
}

// TestExecCommandStaticPieIsNoLoader re-checks the fourth round's fix (a406e838) beyond the deny-list cases above: a
// static-pie program has a loader's ELF shape (ET_DYN, no PT_INTERP), and it is a loader neither in a run whose images
// are restricted, where it was refused loader-program-unmatched for a first word naming a program no entry grants,
// nor as a script's #! interpreter, where the script's words were read as a loaded program's. A ruled tool's name or
// path as its first word stays its own word: the exec is decided on the static-pie program's own grant.
func TestExecCommandStaticPieIsNoLoader(t *testing.T) {
	nr := nrFor(t, "execve")
	pieHead := elfHead(3, 1) // ET_DYN, one PT_LOAD, no PT_INTERP
	for _, c := range []struct {
		name    string
		allow   bool // a restricted run (allow: [git status] beside a grant of /work/rg), else deny: [git push, rm -r]
		path    string
		argv    []string
		verdict record.Verdict
		rule    string
	}{
		{"restricted, a ruled tool's name", true, "/work/rg", []string{"rg", "git", "push"}, record.VerdictAllow, "exec[/work/rg]"},
		{"restricted, a path no entry grants", true, "/work/rg", []string{"rg", "/usr/bin/rm", "-rf", "x"}, record.VerdictAllow, "exec[/work/rg]"},
		{"restricted, a granted tool's path", true, "/work/rg", []string{"rg", "/usr/bin/git", "push"}, record.VerdictAllow, "exec[/work/rg]"},
		{"a #! line naming it", false, "/work/s", []string{"./s", "push"}, record.VerdictAllow, ruleUnmatched},
		{"a #! line naming it, restricted", true, "/work/s", []string{"./s", "/usr/bin/rm", "-r"}, record.VerdictAllow, "exec[/work/s]"},
	} {
		f := newFake()
		f.images = map[string]execImage{
			"/work/rg":     {id: fakeID("/work/rg"), linked: true, link: "/work/rg", here: true, head: pieHead},
			"/work/s":      {id: fakeID("/work/s"), linked: true, link: "/work/s", here: true, head: []byte("#!/work/rg git\n")},
			"/usr/bin/rm":  {id: fakeID("/usr/bin/rm"), linked: true, link: "/usr/bin/rm", here: true},
			"/usr/bin/git": {id: fakeID("/usr/bin/git"), linked: true, link: "/usr/bin/git", here: true},
		}
		pol := commandPolicy(t, "deny: git push", "deny: rm -r")
		if c.allow {
			pol = commandPolicy(t, "allow: git status")
			for _, p := range []string{"/work/rg", "/work/s"} {
				pol.Rules.Exec = append(pol.Rules.Exec, agent.ExecRule{Raw: p, Path: p, Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow})
			}
		}
		l, sink := newTestLoop(t, f, withLoaders(pol, "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"))
		execAt(l, f, nr, 42, 0, c.path, c.argv...)
		ev := sink.one(t)
		if ev.Verdict != c.verdict || ev.Rule != c.rule {
			t.Errorf("%s: %s %s, want %s %s", c.name, ev.Verdict, ev.Rule, c.verdict, c.rule)
		}
		if via := execPayloadOf(t, ev).CommandVia; via == "loader" {
			t.Errorf("%s: read via loader", c.name)
		}
		wantExecAnswer(t, f, c.verdict)
	}
}

// TestExecCommandLoaderShebang: a #! line whose interpreter is the loader, with a program as its argument, runs that
// program over the script and the exec's arguments: `#!/lib64/ld-linux-x86-64.so.2 /usr/bin/rm` run as `./s -r tree`
// is rm -r and refused via loader.
func TestExecCommandLoaderShebang(t *testing.T) {
	nr := nrFor(t, "execve")
	const ld = "/lib64/ld-linux-x86-64.so.2"
	f := newFake()
	f.images = map[string]execImage{
		"/work/s":     {id: fakeID("/work/s"), linked: true, link: "/work/s", here: true, head: []byte("#!" + ld + " /usr/bin/rm\n")},
		ld:            {id: fakeID(ld), linked: true, link: ld, here: true, head: elfHead(3, 1)},
		"/usr/bin/rm": {id: fakeID("/usr/bin/rm"), linked: true, link: "/usr/bin/rm", here: true, head: []byte("\x7fELF")},
	}
	l, sink := newTestLoop(t, f, commandPolicy(t, "deny: rm -r"))
	execAt(l, f, nr, 42, 0, "/work/s", "./s", "-r", "tree")
	if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Rule != "exec.deny[rm -r]" {
		t.Errorf("%s %s, want refused exec.deny[rm -r]", ev.Verdict, ev.Rule)
	}
	wantExecAnswer(t, f, record.VerdictRefused)
}

// TestExecCommandLoaderRestricted: in a run whose images are restricted, a loader an entry grants (here by a directory
// entry above it) maps its program PROT_EXEC after an O_RDONLY open, which no EXECUTE right governs, so its program
// must be granted as an exec of it would be: rm, which no entry grants, is refused loader-program-unmatched, while
// git status through the loader is admitted by its entry (the floor's line names the directory, its command rule
// git status) and git push refused unlisted.
func TestExecCommandLoaderRestricted(t *testing.T) {
	nr := nrFor(t, "execve")
	const ld = "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
	for _, c := range []struct {
		argv    []string
		verdict record.Verdict
		rule    string
	}{
		{[]string{ld, "/usr/bin/rm", "x"}, record.VerdictRefused, ruleLoaderProgram},
		{[]string{ld, "/usr/bin/git", "status"}, record.VerdictAllow, "exec[/usr/lib/x86_64-linux-gnu/]"},
		{[]string{ld, "/usr/bin/git", "push"}, record.VerdictRefused, "exec.args[git]"},
	} {
		f := newFake()
		f.images = map[string]execImage{
			ld:             {id: fakeID(ld), linked: true, link: ld, here: true, head: elfHead(3, 1)},
			"/usr/bin/rm":  {id: fakeID("/opt/rm"), linked: true, link: "/opt/rm", here: true},
			"/usr/bin/git": {id: fakeID("/usr/bin/git"), linked: true, link: "/usr/bin/git", here: true},
		}
		pol := commandPolicy(t, "allow: git status")
		pol.Rules.Exec = append(pol.Rules.Exec, agent.ExecRule{Raw: "/usr/lib/x86_64-linux-gnu/", Path: "/usr/lib/x86_64-linux-gnu/", IsDir: true, Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow})
		l, sink := newTestLoop(t, f, pol)
		execAt(l, f, nr, 42, 0, ld, c.argv...)
		ev := sink.one(t)
		if ev.Verdict != c.verdict || ev.Rule != c.rule {
			t.Errorf("%v: %s %s, want %s %s", c.argv, ev.Verdict, ev.Rule, c.verdict, c.rule)
		}
		if p := execPayloadOf(t, ev); c.verdict == record.VerdictAllow && (p.CommandRule != "git status" || p.CommandVia != "loader") {
			t.Errorf("%v: command rule %q via %q, want git status via loader", c.argv, p.CommandRule, p.CommandVia)
		}
		wantExecAnswer(t, f, c.verdict)
	}
}

// TestExecCommandLoaderProgramIsJudgedWhereItIsNamed: a loader's program spelled with a ".." is judged on its walk's
// name, as an exec is (TestExecIsDecidedWhereItIsNamed), never on R6's lexical clean. /grant/lk/../x cleans to the file
// entry's /grant/x (missing at the start, so matched by name), while the loader maps /elsewhere/x, which nothing
// grants.
func TestExecCommandLoaderProgramIsJudgedWhereItIsNamed(t *testing.T) {
	nr := nrFor(t, "execve")
	const ld = "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
	f := newFake()
	f.statErrs["/grant/x"] = unix.ENOENT
	walked := execImage{id: fakeID("/elsewhere/x"), linked: true, link: "/elsewhere/x", here: true, name: "/elsewhere/x"}
	f.images = map[string]execImage{
		ld:         {id: fakeID(ld), linked: true, link: ld, here: true, head: elfHead(3, 1)},
		"/grant/x": walked, // the lexical clean of the operand: the fake keys its walk so
	}
	pol := commandPolicy(t, "allow: git status")
	pol.Rules.Exec = append(pol.Rules.Exec,
		agent.ExecRule{Raw: "/usr/lib/x86_64-linux-gnu/", Path: "/usr/lib/x86_64-linux-gnu/", IsDir: true, Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow},
		agent.ExecRule{Raw: "/grant/x", Path: "/grant/x", Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow})
	l, sink := newTestLoop(t, f, pol)
	execAt(l, f, nr, 42, 0, ld, ld, "/grant/lk/../x")
	if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Rule != ruleLoaderProgram {
		t.Errorf("%s %s, want refused %s: the program the loader maps is granted by no entry", ev.Verdict, ev.Rule, ruleLoaderProgram)
	}
}

// TestDenyListRefusesExecFromTheCodexHome isagent-contract.md R10a's deny-list half: a deny-list
// leaves images unrestricted, so the run's own CODEX_HOME grant would be a directory the agent writes to and runs
// from, and a copy of a denied id there under another name ran. An image there is refused codex-home-exec, and so is a
// directly-invoked loader's program there; a symlink there to a program elsewhere (Codex's tmp/arg0 links to its own
// binary) is that program and runs, and an image elsewhere is decided as before. A restricted run refuses the copy
// unmatched already, and a run with no exec: section denies nothing.
func TestDenyListRefusesExecFromTheCodexHome(t *testing.T) {
	nr := nrFor(t, "execve")
	const (
		ld   = "/lib64/ld-linux-x86-64.so.2"
		home = "/run/user/1000/tego/r-1/codex"
	)
	grant := agent.FSRule{Path: home, Resolved: home, Kind: agent.FSWrite, Access: agent.AccessWriteSet, Runtime: agent.CodexHomeGrant}
	images := map[string]execImage{
		ld:                        {id: fakeID(ld), linked: true, link: ld, here: true, head: elfHead(3, 1, 1)},
		home + "/notid":           {id: fakeID(home + "/notid"), linked: true, link: home + "/notid", here: true, head: []byte("\x7fELF")},
		home + "/tmp/arg0/a/tool": {id: fakeID("/usr/bin/true"), linked: true, link: "/usr/bin/true", here: true, head: []byte("\x7fELF")},
		home + "x/run":            {id: fakeID(home + "x/run"), linked: true, link: home + "x/run", here: true, head: []byte("\x7fELF")},
		"/usr/bin/id":             {id: fakeID("/usr/bin/id"), linked: true, link: "/usr/bin/id", here: true, head: []byte("\x7fELF")},
		// The copy opened, unlinked and run through its descriptor, and a copy in a memfd.
		"/proc/42/fd/9": {id: fakeID(home + "/notid"), link: home + "/notid (deleted)", here: true, head: []byte("\x7fELF")},
		"/proc/42/fd/8": {id: fakeID("/memfd:x"), link: "/memfd:x (deleted)", here: true, head: []byte("\x7fELF")},
		// A linked copy in a directory of the home that the agent made unsearchable, run through
		// its descriptor. The supervisor's re-walk of the kernel's spelling fails, so here is false, and the exec's own
		// spelling, /proc/42/fd/7, is no path in the home: the exec was judged on that spelling and allowed.
		"/proc/42/fd/7": {id: fakeID(home + "/sub/notid"), linked: true, link: home + "/sub/notid", head: []byte("\x7fELF")},
		// The same where another hard link survives elsewhere: the kernel spells the removed name, marked deleted.
		"/proc/42/fd/6": {id: fakeID(home + "/sub/old"), linked: true, link: home + "/sub/old (deleted)", head: []byte("\x7fELF")},
		// A linked image elsewhere that cannot be confirmed here is not the home's.
		"/proc/42/fd/5": {id: fakeID("/usr/bin/true"), linked: true, link: "/usr/bin/true", head: []byte("\x7fELF")},
	}
	for _, c := range []struct {
		name    string
		pol     func() *Policy
		path    string
		argv    []string
		verdict record.Verdict
		rule    string
	}{
		{"the copy", nil, home + "/notid", []string{"notid", "-u"}, record.VerdictRefused, ruleCodexHomeExec},
		{"the copy through the loader", nil, ld, []string{ld, home + "/notid", "-u"}, record.VerdictRefused, ruleCodexHomeExec},
		{"a symlink to a program elsewhere", nil, home + "/tmp/arg0/a/tool", []string{"tool"}, record.VerdictAllow, ruleUnmatched},
		{"a sibling directory is not the home", nil, home + "x/run", []string{"run"}, record.VerdictAllow, ruleUnmatched},
		{"the denied program", nil, "/usr/bin/id", []string{"id", "-u"}, record.VerdictRefused, "exec.deny[id]"},
		// R10a's stated residual, as compile's exec-rule-coverage says on every deny-list: images are unrestricted, so
		// a fileless copy (unlinked from the home, or a memfd) runs, recorded allow unmatched, never codex-home-exec.
		{"the copy unlinked runs fileless", nil, "/proc/42/fd/9", []string{"notid", "-u"}, record.VerdictAllow, ruleUnmatched},
		{"a memfd copy runs fileless", nil, "/proc/42/fd/8", []string{"notid", "-u"}, record.VerdictAllow, ruleUnmatched},
		{"a linked copy not confirmed here", nil, "/proc/42/fd/7", []string{"notid", "-u"}, record.VerdictRefused, ruleCodexHomeExec},
		{"a linked copy not confirmed here, through the loader", nil, ld, []string{ld, "/proc/42/fd/7", "-u"}, record.VerdictRefused, ruleCodexHomeExec},
		{"a surviving hard link's removed name in the home", nil, "/proc/42/fd/6", []string{"old"}, record.VerdictRefused, ruleCodexHomeExec},
		{"a surviving hard link's removed name, through the loader", nil, ld, []string{ld, "/proc/42/fd/6"}, record.VerdictRefused, ruleCodexHomeExec},
		{"a program elsewhere not confirmed here", nil, "/proc/42/fd/5", []string{"true"}, record.VerdictAllow, ruleUnmatched},
		{"a program elsewhere not confirmed here, through the loader", nil, ld, []string{ld, "/proc/42/fd/5"}, record.VerdictAllow, ruleUnmatched},
		{"no exec: section denies nothing", func() *Policy {
			return contractPolicy(&agent.Contract{}, nil, []agent.FSRule{grant})
		}, home + "/notid", []string{"notid"}, record.VerdictAllow, ruleUnmatched},
		{"a restricted run refuses it unmatched", func() *Policy {
			pol := commandPolicy(t, "allow: git status")
			pol.Rules.FS = append(pol.Rules.FS, grant)
			return pol
		}, home + "/notid", []string{"notid"}, record.VerdictRefused, ruleUnmatched},
	} {
		f := newFake()
		f.images = images
		pol := commandPolicy(t, "deny: id")
		pol.Rules.FS = append(pol.Rules.FS, grant)
		if c.pol != nil {
			pol = c.pol()
		}
		l, sink := newTestLoop(t, f, pol)
		execAt(l, f, nr, 42, 0, c.path, c.argv...)
		ev := sink.one(t)
		if ev.Verdict != c.verdict || ev.Rule != c.rule {
			t.Errorf("%s: %s %s, want %s %s", c.name, ev.Verdict, ev.Rule, c.verdict, c.rule)
		}
		if c.verdict == record.VerdictRefused && ev.Reason != record.ReasonExecNotAllowed {
			t.Errorf("%s: reason %s, want exec-not-allowed", c.name, ev.Reason)
		}
		if p := execPayloadOf(t, ev); p.Fileless != images[c.path].fileless() {
			t.Errorf("%s: fileless %v: the record must say whether the image had a name", c.name, p.Fileless)
		}
		wantExecAnswer(t, f, c.verdict)
	}
}

// TestExecDroppedIsOneFactEveryOwnerCarries is the dropped flag as one fact of the exec, whoever writes its line and whatever
// the image floor answers. A file the run wrote under a write entry that the exec
// names to the kernel to load sets dropped: its own image, and in a run with command rules each #! interpreter and a
// directly-invoked loader's program, the file the loader maps and jumps to (`ld-linux-x86-64.so.2 /work/proj/tool`
// carried no flag). The owners are this loop's line, the naming a kernel recorder's line takes when
// a run with command rules or an exec gate hands the decided exec over, and the fast handover's naming. The kernel's
// copy had no test, and an exec the floor refused, or an observe run's would-be refusal (which runs), was never
// walked past its own image. A run without command rules walks only the exec's own image, so only it is judged. A
// loaded file older than the run, or outside every write entry, is not flagged.
func TestExecDroppedIsOneFactEveryOwnerCarries(t *testing.T) {
	nr := nrFor(t, "execve")
	const ld = "/lib64/ld-linux-x86-64.so.2"
	const ldReal = "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
	denyList := func(t *testing.T) *Policy { return withLoaders(commandPolicy(t, "deny: rm -r"), ldReal) }
	allowList := func(t *testing.T) *Policy {
		return withLoaders(commandPolicy(t, "allow: git status", "deny: rm -r"), ldReal)
	}
	observed := func(t *testing.T) *Policy {
		pol := allowList(t)
		pol.Observe = true
		return pol
	}
	plain := func(*testing.T) *Policy { return contractPolicy(&agent.Contract{}, nil, nil) } // no exec: section
	gated := func(t *testing.T) *Policy {
		pol := plain(t)
		pol.Rules.Gate = testGate(t, gate.ExecMatches, "rm", 40)
		return pol
	}
	for _, a := range []struct {
		name   string
		pol    func(*testing.T) *Policy
		kernel bool           // a kernel recorder is ready and a plane decides the run's execs
		loads  bool           // the run walks the images an exec loads beyond its own: it has command rules
		handed bool           // the kernel's recorder writes the line, from the naming this loop handed it
		line   record.Verdict // this loop's line otherwise, and the answer either way
	}{
		{"command rules, the floor allows, this loop's line", denyList, false, true, false, record.VerdictAllow},
		{"command rules, the floor allows, handed to the kernel", denyList, true, true, true, record.VerdictAllow},
		{"command rules, the floor refuses", allowList, false, true, false, record.VerdictRefused},
		{"command rules, the floor refuses, a recorder ready", allowList, true, true, false, record.VerdictRefused},
		{"command rules, an observe run's would-be refusal", observed, false, true, false, record.VerdictObserved},
		{"command rules, an observe run's would-be refusal, a recorder ready", observed, true, true, false, record.VerdictObserved},
		{"no command rules, this loop's line", plain, false, false, false, record.VerdictAllow},
		{"no command rules, the fast handover", plain, true, false, true, record.VerdictAllow},
		{"an exec gate, this loop's line", gated, false, false, false, record.VerdictAllow},
		{"an exec gate, handed to the kernel", gated, true, false, true, record.VerdictAllow},
	} {
		for _, c := range []struct {
			name        string
			path        string
			argv        []string
			own, loaded bool // the exec's own image, or an image it loads beyond its own, was written in the run
		}{
			{"its own image the run wrote", "/work/proj/own", []string{"own"}, true, false},
			{"a loader's program the run wrote", ld, []string{ld, "/work/proj/tool", "x"}, false, true},
			{"a loader's program older than the run", ld, []string{ld, "/work/proj/old", "x"}, false, false},
			{"a loader's program outside every write entry", ld, []string{ld, "/usr/bin/tool", "x"}, false, false},
			{"a #! interpreter the run wrote", "/usr/local/bin/s", []string{"s"}, false, true},
			{"a #! loader's program the run wrote", "/usr/local/bin/l", []string{"l"}, false, true},
		} {
			t.Run(a.name+"/"+c.name, func(t *testing.T) {
				f := newFake()
				f.stats[42] = procStat{ppid: 1, start: 1234}
				pol := a.pol(t)
				pol.Rules.FS = []agent.FSRule{{Path: "/work/proj", Kind: agent.FSWrite, Raw: "./proj"}}
				l, sink := newTestLoop(t, f, pol)
				l.mono = func() uint64 { return 100 }
				if a.kernel {
					l.kernelExecHandoff = func() bool { return true }
					l.kernelExecs = func() bool { return true }
				}
				run, old := l.started.Add(time.Second), l.started.Add(-time.Hour)
				elf := []byte("\x7fELF")
				f.images = map[string]execImage{
					ld:                  {id: fakeID(ldReal), linked: true, link: ldReal, here: true, head: elfHead(3, 1, 1), changed: old},
					"/work/proj/own":    {id: fakeID("/work/proj/own"), linked: true, link: "/work/proj/own", here: true, head: elf, changed: run},
					"/work/proj/tool":   {id: fakeID("/work/proj/tool"), linked: true, link: "/work/proj/tool", here: true, head: elf, changed: run},
					"/work/proj/old":    {id: fakeID("/work/proj/old"), linked: true, link: "/work/proj/old", here: true, head: elf, changed: old},
					"/usr/bin/tool":     {id: fakeID("/usr/bin/tool"), linked: true, link: "/usr/bin/tool", here: true, head: elf, changed: run},
					"/usr/local/bin/s":  {id: fakeID("/usr/local/bin/s"), linked: true, link: "/usr/local/bin/s", here: true, head: []byte("#!/work/proj/interp\n"), changed: old},
					"/work/proj/interp": {id: fakeID("/work/proj/interp"), linked: true, link: "/work/proj/interp", here: true, head: elf, changed: run},
					"/usr/local/bin/l":  {id: fakeID("/usr/local/bin/l"), linked: true, link: "/usr/local/bin/l", here: true, head: []byte("#!" + ld + " /work/proj/tool\n"), changed: old},
				}
				execAt(l, f, nr, 42, 0, c.path, c.argv...)
				wantExecAnswer(t, f, a.line)
				var dropped bool
				if a.handed {
					if lines := sink.all(); len(lines) != 0 {
						t.Fatalf("the kernel's recorder owns the line, and this loop wrote %d", len(lines))
					}
					n, ok := l.ContinuedExec(42, 42, 1234*proc.NanosPerTick, 110)
					if !ok || n.SupervisorOwned {
						t.Fatalf("no naming handed to the kernel's line: %+v %v", n, ok)
					}
					dropped = n.Dropped
				} else {
					ev := sink.one(t)
					if ev.Verdict != a.line {
						t.Fatalf("verdict %s %s, want %s", ev.Verdict, ev.Rule, a.line)
					}
					dropped = execPayloadOf(t, ev).Dropped
				}
				if want := c.own || a.loads && c.loaded; dropped != want {
					t.Errorf("dropped %v, want %v", dropped, want)
				}
			})
		}
	}
}
