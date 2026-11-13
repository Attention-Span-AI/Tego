// SPDX-License-Identifier: Apache-2.0

package rows

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
)

// TestCoreutilsSingleBinaryDispatch: GNU coreutils' single binary (coreutils-single, as UBI-minimal images install
// it) runs the program --coreutils-prog=PROG names with argv[2:], its #! form --coreutils-prog-shebang=PROG with
// argv[3:] (argv[2] is the script), and PROG when argv[0] is lt-PROG (src/coreutils.c). Each is the multicall row's
// applet, so deny: [rm -r] refuses all three; an empty program and busybox, which has no such option, read none.
func TestCoreutilsSingleBinaryDispatch(t *testing.T) {
	ix := rules(t, "deny: rm -r")
	script := func(arg string, argv ...string) execmatch.Facts {
		return execmatch.Facts{Requested: "s", Path: "./s", Image: "s", Argv0: argv[0], Argv: argv, ArgvComplete: true,
			Form: execmatch.FormScript, Interp: []execmatch.Stage{{Path: "/usr/bin/coreutils", Arg: arg}}}
	}
	cases := []struct {
		name  string
		facts execmatch.Facts
		want  string
		via   execmatch.Via
	}{
		{"--coreutils-prog=rm", facts("/usr/bin/coreutils", "coreutils", "coreutils", "--coreutils-prog=rm", "-r", "x"), "exec.deny[rm -r]", execmatch.ViaMulticall},
		{"--coreutils-prog=/bin/rm", facts("/usr/bin/coreutils", "coreutils", "coreutils", "--coreutils-prog=/bin/rm", "-fr", "x"), "exec.deny[rm -r]", execmatch.ViaMulticall},
		{"#! --coreutils-prog-shebang=rm", script("--coreutils-prog-shebang=rm -r", "./s", "x"), "", 0},
		{"#! --coreutils-prog-shebang=rm, -r from argv", script("--coreutils-prog-shebang=rm", "./s", "-r", "out/tree"), "exec.deny[rm -r]", execmatch.ViaMulticall},
		{"argv0 lt-rm", facts("/usr/bin/coreutils", "coreutils", "lt-rm", "-r", "x"), "exec.deny[rm -r]", execmatch.ViaMulticall},
		{"empty program", facts("/usr/bin/coreutils", "coreutils", "coreutils", "--coreutils-prog=", "-r", "x"), "", 0},
		{"--coreutils-prog=rm without -r", facts("/usr/bin/coreutils", "coreutils", "coreutils", "--coreutils-prog=rm", "x"), "", 0},
		{"busybox has no such option", facts("/usr/bin/busybox", "busybox", "busybox", "--coreutils-prog=rm", "-r", "x"), "", 0},
		{"busybox as lt-rm", facts("/usr/bin/busybox", "busybox", "lt-rm", "-r", "x"), "", 0},
	}
	for _, c := range cases {
		r := ix.Decide(&c.facts)
		if c.want == "" {
			if r.Outcome != execmatch.OutcomeNone {
				t.Errorf("%s: %s, want none", c.name, decided(r))
			}
			continue
		}
		if r.Outcome != execmatch.OutcomeRefused || r.Rule() != c.want || r.Via != c.via {
			t.Errorf("%s: %s via %s, want refused %s via %s", c.name, decided(r), r.Via, c.want, c.via)
		}
	}
}

// TestArgv0DispatchForms: the argv[0] forms the tools accept, probed on busybox 1.37.0 and systemd 257. busybox drops a
// leading '-' before it looks the applet up (a login shell's name), and a file whose argv[0] starts with busybox is the
// dispatcher, whatever its own name, also as an applet of itself. systemd's invoked_as is strstr on argv[0], so the file
// being systemctl is what makes xrebootx a reboot: a program called asphalt is not halt.
func TestArgv0DispatchForms(t *testing.T) {
	ix := rules(t, "deny: rm -r", "deny: systemctl reboot", "deny: systemctl halt")
	cases := []struct {
		name  string
		facts execmatch.Facts
		want  string
	}{
		{"busybox as -rm", facts("/usr/bin/busybox", "busybox", "-rm", "-rf", "x"), "exec.deny[rm -r]"},
		{"a link of busybox as -rm", facts("/bin/ls", "ls", "-rm", "-rf", "x"), "exec.deny[rm -r]"},
		{"-/bin/rm", facts("/usr/bin/busybox", "busybox", "-/bin/rm", "-rf", "x"), "exec.deny[rm -r]"},
		{"a link of busybox as busybox.x", facts("/bin/ls", "ls", "busybox.x", "rm", "-rf", "x"), "exec.deny[rm -r]"},
		{"busybox.x as an applet", facts("/usr/bin/busybox", "busybox", "busybox", "busybox.x", "rm", "-rf", "x"), "exec.deny[rm -r]"},
		{"a link of toybox as toybox.x", facts("/bin/ls", "ls", "toybox.x", "rm", "-rf", "x"), "exec.deny[rm -r]"},
		{"systemctl as xrebootx", facts("/usr/bin/systemctl", "systemctl", "xrebootx"), "exec.deny[systemctl reboot]"},
		{"systemctl as asphalt", facts("/usr/bin/systemctl", "systemctl", "asphalt", "--force"), "exec.deny[systemctl halt]"},
		{"a program called asphalt", facts("/usr/bin/asphalt", "asphalt", "asphalt"), ""},
		{"a program called xrebootx", facts("/usr/bin/xrebootx", "xrebootx", "xrebootx"), ""},
		{"systemctl as itself", facts("/usr/bin/systemctl", "systemctl", "systemctl", "status"), ""},
		{"a login shell's name", facts("/bin/bash", "bash", "-bash", "-l"), ""},
		{"-- is no login name", facts("/bin/ls", "ls", "--rm", "-rf", "x"), ""},
		{"a lone -", facts("/bin/ls", "ls", "-", "-rf", "x"), ""},
		{"a name that is not busybox", facts("/bin/ls", "ls", "busy", "rm", "-rf", "x"), ""},
		{"a busybox-named file with its own argv[0]", facts("/opt/busybox.x", "busybox.x", "ls", "rm", "-rf", "x"), ""},
	}
	for _, c := range cases {
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
		if !ix.Guarded(&c.facts) {
			t.Errorf("%s: not guarded, so no argv past argv[0] is read for it", c.name)
		}
	}
}
