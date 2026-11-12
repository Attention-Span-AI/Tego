// SPDX-License-Identifier: Apache-2.0

package rows

import (
	"path"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
)

// uutilsLinks is the link count of Ubuntu 26.04.1's uutils file (rust-coreutils 0.10.0-1ubuntu2~26.04.1, measured on
// the guest of 2026-11-11: /usr/bin/ls -> ../lib/cargo/bin/coreutils/ls, 116 links).
const uutilsLinks = 116

// multicallFacts are an exec's facts on a file of links links whose walk ended at the link named image: requested
// pathname, image, then argv.
func multicallFacts(links uint64, requested, image string, argv ...string) execmatch.Facts {
	f := facts(requested, image, argv...)
	f.Links = links
	return f
}

// nameForms are nine name forms measured against the matcher on 2026-11-11 (deny: [rm -r], Ubuntu 25.10's uutils file;
// ADR 0048's amendment of that date, What was measured), each an exec that upstream uutils (main a4b65e12 and
// 0.12.0, src/bin/coreutils.rs and src/common/validation.rs, read, not run) runs as rm -r: the program name is
// AT_EXECFN's file stem, or argv[0]'s when the exec path starts with /proc/ or /dev/fd/ (or on musl), and the applet is
// the longest utility name it ends with; a stem ending in utils or box runs the applet argv[1] names.
var nameForms = []struct {
	name      string
	requested string
	argv      []string
	// before is what the matcher answered before it read these forms: "" for none.
	before string
}{
	{"uutils link ls, argv0 rm", "/usr/bin/ls", []string{"rm", "-r", "x"}, "exec.deny[rm -r]"},
	{"coreutils rm -r", "/usr/bin/coreutils", []string{"coreutils", "rm", "-r", "x"}, "exec.deny[rm -r]"},
	{"/proc/self/fd/3 of ls, argv0 xrm (suffix)", "/proc/self/fd/3", []string{"xrm", "-r", "x"}, ""},
	{"/proc/self/fd/3 of ls, argv0 rm.x (file stem)", "/proc/self/fd/3", []string{"rm.x", "-r", "x"}, ""},
	{"/proc/self/fd/3 of ls, argv0 farm (suffix)", "/proc/self/fd/3", []string{"farm", "-r", "x"}, ""},
	{"symlink ./xrm to ls (AT_EXECFN suffix)", "/w/xrm", []string{"xrm", "-r", "x"}, ""},
	{"/proc/self/fd/3 of ls, argv0 myutils, argv1 rm (*utils)", "/proc/self/fd/3", []string{"myutils", "rm", "-r", "x"}, ""},
	{"/proc/self/fd/3 of ls, argv0 xbox, argv1 rm (*box)", "/proc/self/fd/3", []string{"xbox", "rm", "-r", "x"}, ""},
	{"symlink ./uu-rm to ls", "/w/uu-rm", []string{"uu-rm", "-r", "x"}, ""},
}

// TestMulticallNameFormsMeetDenyRules: on a multicall image every form of nameForms is refused by deny: [rm -r], as
// upstream uutils would run each as rm -r; the image of /usr/bin/coreutils is named coreutils. Before 2026-11-11 seven
// of the nine gave none (each form's before field; on the Ubuntu 26.04.1 guest of that day, with deny: ["rm -r"], 7 of
// 11 forms on the ls file were recorded exec[/bin/ls] allow: docs/GAPS.md C63).
func TestMulticallNameFormsMeetDenyRules(t *testing.T) {
	ix := rules(t, "deny: rm -r")
	for _, c := range nameForms {
		image := "ls"
		if c.requested == "/usr/bin/coreutils" {
			image = "coreutils"
		}
		f := multicallFacts(uutilsLinks, c.requested, image, c.argv...)
		r := ix.Decide(&f)
		if r.Outcome != execmatch.OutcomeRefused || r.Rule() != "exec.deny[rm -r]" {
			t.Errorf("%s: %s via %s, want refused exec.deny[rm -r]", c.name, decided(r), r.Via)
			continue
		}
		if c.before == "" && r.Via != execmatch.ViaMulticall {
			t.Errorf("%s: via %s, want multicall", c.name, r.Via)
		}
		if !ix.Guarded(&f) {
			t.Errorf("%s: not guarded, so the supervisor would read no argv past argv[0] for it", c.name)
		}
	}
}

// TestMulticallFormsNeedAMulticallImage: the same forms on a file of one link, or of a link count nobody read (compile
// --test, the gate), answer as before: a deny or ask outcome changes only on a multicall image.
func TestMulticallFormsNeedAMulticallImage(t *testing.T) {
	ix := rules(t, "deny: rm -r")
	for _, links := range []uint64{0, 1} {
		for _, c := range nameForms {
			image := "ls"
			if c.requested == "/usr/bin/coreutils" {
				image = "coreutils"
			}
			f := multicallFacts(links, c.requested, image, c.argv...)
			r := ix.Decide(&f)
			if c.before == "" {
				if r.Outcome != execmatch.OutcomeNone {
					t.Errorf("%d links, %s: %s, want none", links, c.name, decided(r))
				}
				continue
			}
			if r.Outcome != execmatch.OutcomeRefused || r.Rule() != c.before {
				t.Errorf("%d links, %s: %s, want refused %s", links, c.name, decided(r), c.before)
			}
		}
	}
}

// TestMulticallLongestApplet: the applet is the longest utility name the stem ends with (uutils' matched_utility,
// "Prefer stty over tty"), so a name that is itself a utility runs that utility, never a shorter one it ends with; a
// stem ending in utils never runs its suffix; file_stem drops the last extension; and Rust's file_name skips a
// trailing "." component and has none for "..".
func TestMulticallLongestApplet(t *testing.T) {
	ix := rules(t, "deny: od", "deny: link", "deny: sum", "deny: dir", "deny: tty", "deny: env", "deny: rm -r")
	cases := []struct {
		argv0 string
		argv  []string
		want  string
	}{
		{"chmod", nil, ""},
		{"mknod", nil, ""},
		{"readlink", nil, ""},
		{"unlink", nil, ""},
		{"md5sum", nil, ""},
		{"sha256sum", nil, ""},
		{"mkdir", nil, ""},
		{"rmdir", nil, ""},
		{"vdir", nil, ""},
		{"stty", nil, ""},
		{"printenv", nil, ""},
		{"xod", nil, "exec.deny[od]"},
		{"xlink", nil, "exec.deny[link]"},
		{"xsum", nil, "exec.deny[sum]"},
		{"x.tty", nil, ""},
		{"tty.x", nil, "exec.deny[tty]"},
		{"rm/.", []string{"-r", "x"}, "exec.deny[rm -r]"},
		{"rm/..", []string{"-r", "x"}, ""},
		{"rmutils", []string{"-r", "x"}, ""},
		{"xrm", []string{"-f", "x"}, ""},
		{"myutils", []string{"ls", "-r"}, ""},
		{"myutils", []string{"-r", "rm"}, ""},
	}
	for _, c := range cases {
		argv := append([]string{c.argv0}, c.argv...)
		if c.argv == nil {
			argv = append(argv, "x")
		}
		f := multicallFacts(uutilsLinks, "/proc/self/fd/3", "ls", argv...)
		r := ix.Decide(&f)
		if c.want == "" {
			if r.Outcome != execmatch.OutcomeNone {
				t.Errorf("argv %q: %s via %s, want none", argv, decided(r), r.Via)
			}
			continue
		}
		if r.Outcome != execmatch.OutcomeRefused || r.Rule() != c.want {
			t.Errorf("argv %q: %s, want refused %s", argv, decided(r), c.want)
		}
	}
}

// TestMulticallScriptAndLoader: a #! interpreter that is a multicall image is read by the #! path's name (uutils takes
// argv[0] when AT_EXECFN names a file that starts with #!), and a dynamic loader's program by the operand and its
// argv[0] (musl uutils reads argv[0]); each only when the walked file is a multicall image.
func TestMulticallScriptAndLoader(t *testing.T) {
	ix := rules(t, "deny: rm -r")
	script := func(links uint64) execmatch.Facts {
		return execmatch.Facts{Requested: "s", Path: "./s", Image: "s", Argv0: "./s", Argv: []string{"./s", "out/tree"},
			ArgvComplete: true, Form: execmatch.FormScript,
			Interp: []execmatch.Stage{{Path: "/w/xrm", Arg: "-rf", Image: "ls", Links: links}}}
	}
	loader := func(links uint64) execmatch.Facts {
		return execmatch.Facts{Requested: "ld-linux-x86-64.so.2", Path: "/lib64/ld-linux-x86-64.so.2", Image: "ld-linux-x86-64.so.2",
			Argv0: "ld-linux-x86-64.so.2", Argv: []string{"ld-linux-x86-64.so.2", "/w/xrm", "-r", "x"}, ArgvComplete: true,
			Loaded: &execmatch.Loaded{Path: "/w/xrm", Image: "ls", Links: links, Argv: []string{"/w/xrm", "-r", "x"}}}
	}
	for _, c := range []struct {
		name  string
		facts execmatch.Facts
		want  string
	}{
		{"#! /w/xrm -rf, a multicall interpreter", script(uutilsLinks), "exec.deny[rm -r]"},
		{"#! /w/xrm -rf, one link", script(1), ""},
		{"ld.so /w/xrm -r, a multicall program", loader(uutilsLinks), "exec.deny[rm -r]"},
		{"ld.so /w/xrm -r, one link", loader(1), ""},
	} {
		r := ix.Decide(&c.facts)
		if c.want == "" {
			if r.Outcome != execmatch.OutcomeNone {
				t.Errorf("%s: %s, want none", c.name, decided(r))
			}
			continue
		}
		if r.Outcome != execmatch.OutcomeRefused || r.Rule() != c.want {
			t.Errorf("%s: %s, want refused %s", c.name, decided(r), c.want)
		}
	}
}

// TestMulticallArgv1PrefixIsNotFinal: a name that dispatches on argv[1] (xbox, myutils) decided on an argv prefix that
// ends before argv[1] has not read its applet, so the decision is not Final and the supervisor's staged read goes on
// to argv[1]. An argv[0] of 8191 bytes or more fills the first stage (32 entries, 8 KiB), and a Final none there let
// `xbox rm -r` run unread (found in review on 2026-11-11). The whole argv is refused.
func TestMulticallArgv1PrefixIsNotFinal(t *testing.T) {
	ix := rules(t, "deny: rm -r")
	long := strings.Repeat("A", 8191)
	for _, c := range []struct{ name, path, argv0 string }{
		{"symlink /w/xbox, long argv0", "/w/xbox", long},
		{"symlink /w/myutils, long argv0", "/w/myutils", long},
		{"/proc/self/fd/3, argv0 ...xbox", "/proc/self/fd/3", long[:8187] + "xbox"},
		{"/proc/self/fd/3, argv0 myutils", "/proc/self/fd/3", "myutils"},
	} {
		for _, prefix := range [][]string{{c.argv0}, {}} {
			f := execmatch.Facts{Requested: path.Base(c.path), Path: c.path, Image: "ls", Links: uutilsLinks, Argv0: c.argv0,
				Argv: prefix}
			if r := ix.Decide(&f); r.Final && r.Outcome != execmatch.OutcomeRefused {
				t.Errorf("%s, prefix of %d: %s and Final, so argv[1] is never read", c.name, len(prefix), decided(r))
			}
		}
		f := execmatch.Facts{Requested: path.Base(c.path), Path: c.path, Image: "ls", Links: uutilsLinks, Argv0: c.argv0,
			Argv: []string{c.argv0, "rm", "-r", "x"}, ArgvComplete: true}
		if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused || r.Rule() != "exec.deny[rm -r]" {
			t.Errorf("%s, whole argv: %s, want refused exec.deny[rm -r]", c.name, decided(r))
		}
	}
}

// TestMulticallScriptReadByItsOwnName: for a #! exec uutils takes argv[0] (the #! path) only when it can open the
// script and read #!; an execute-only script (mode 0111) it cannot open, and then it takes AT_EXECFN, the script's own
// pathname (validation.rs binary_path, main a4b65e12 and 0.12.0, read). So a script ./xrm whose interpreter is a
// multicall file runs rm, and is read by its requested name too (found in review on 2026-11-11).
func TestMulticallScriptReadByItsOwnName(t *testing.T) {
	ix := rules(t, "deny: rm -r")
	for _, links := range []uint64{1, uutilsLinks} {
		f := execmatch.Facts{Requested: "xrm", Path: "./xrm", Image: "xrm", Links: 1, Argv0: "./xrm", Argv: []string{"./xrm", "x"},
			ArgvComplete: true, Form: execmatch.FormScript,
			Interp: []execmatch.Stage{{Path: "/usr/bin/ls", Arg: "-r", Image: "ls", Links: links}}}
		r := ix.Decide(&f)
		switch {
		case links > 1 && (r.Outcome != execmatch.OutcomeRefused || r.Rule() != "exec.deny[rm -r]"):
			t.Errorf("interpreter of %d links: %s, want refused exec.deny[rm -r] (uutils runs rm -r ./xrm x)", links, decided(r))
		case links == 1 && r.Outcome != execmatch.OutcomeNone:
			t.Errorf("interpreter of one link: %s, want none", decided(r))
		}
		if links > 1 && !ix.Guarded(&f) {
			t.Errorf("interpreter of %d links: not guarded", links)
		}
	}
}

// TestMulticallGateNeedsAUtilityName: the link count gates a file only when its walked name is one a uutils build
// links its file under: a name ending with a listed utility (ls, xrm, uu-rm), one ending in utils or box, or one of the
// build's other link names ([, relpath). A hard-linked program that is none of these (unzip and zipinfo, perl and
// perl5.40.1 on Ubuntu 25.10, 2 links each) is read as before (found in review on 2026-11-11).
func TestMulticallGateNeedsAUtilityName(t *testing.T) {
	for _, entries := range [][]string{{"deny: zip"}, {"allow: unzip", "deny: zip"}, {"deny: zip -r"}} {
		ix := rules(t, entries...)
		for _, links := range []uint64{1, 2} {
			for _, name := range []string{"unzip", "zipinfo"} {
				f := multicallFacts(links, "/usr/bin/"+name, name, name, "-r", "a.zip")
				// A bare allow entry leaves the tool unconstrained: the image floor admits it, and the matcher says none.
				if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeNone {
					t.Errorf("%v, %s of %d links: %s via %s, want none", entries, name, links, decided(r), r.Via)
				}
			}
		}
	}
	ix := rules(t, "deny: rm -r")
	for _, c := range []struct {
		image string
		want  string
	}{
		{"perl", ""}, {"perl5.40.1", ""}, {"unzip", ""},
		{"ls", "exec.deny[rm -r]"}, {"[", "exec.deny[rm -r]"}, {"relpath", "exec.deny[rm -r]"}, {"uu-ls", "exec.deny[rm -r]"},
		{"sha3-256sum", "exec.deny[rm -r]"}, {"coreutils", "exec.deny[rm -r]"}, {"busybox", "exec.deny[rm -r]"},
	} {
		f := multicallFacts(2, "/proc/self/fd/3", c.image, "xrm", "-r", "x")
		r := ix.Decide(&f)
		if c.want == "" && r.Outcome != execmatch.OutcomeNone || c.want != "" && r.Rule() != c.want {
			t.Errorf("fd/3 of %s (2 links), argv0 xrm: %s, want %q", c.image, decided(r), c.want)
		}
	}
}

// TestMulticallDenyBeforeAsk: a deny entry an exec's multicall reading meets wins over an ask entry its plain reading
// meets, as ADR 0048 (1) orders deny before ask over every interpretation (found in review on 2026-11-11). Approving ls must never run
// rm.
func TestMulticallDenyBeforeAsk(t *testing.T) {
	ix := rules(t, "ask: ls", "deny: rm -r")
	f := multicallFacts(uutilsLinks, "/proc/self/fd/3", "ls", "xrm", "-r", "x")
	if r := ix.Decide(&f); r.Rule() != "exec.deny[rm -r]" || r.Via != execmatch.ViaMulticall {
		t.Errorf("ask ls, deny rm -r, fd/3 of ls as xrm -r: %s via %s, want refused exec.deny[rm -r] via multicall", decided(r), r.Via)
	}
	f = multicallFacts(uutilsLinks, "/proc/self/fd/3", "ls", "xrm", "-f", "x")
	if r := ix.Decide(&f); r.Rule() != "exec.ask[ls]" {
		t.Errorf("ask ls, deny rm -r, fd/3 of ls as xrm -f: %s, want refused exec.ask[ls]", decided(r))
	}
}
