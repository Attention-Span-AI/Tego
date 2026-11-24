// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/doctor"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// selfSudo is sudoSelf for the running test binary; it fails the test when that binary cannot be named.
func selfSudo(t *testing.T, args string) string {
	t.Helper()
	cmd, why := sudoSelf(args)
	if why != "" {
		t.Fatalf("sudoSelf(%q): %s", args, why)
	}
	return cmd
}

// TestRootHintsNameNoCommandWhenTheBinaryCannotBeNamed: the lines Tego prints for an administrator to paste with sudo run
// as root, so they never fall back to a lookup of tego in the reader's PATH (sudo "$(command -v tego)" selected whatever
// the reader's PATH found first) and never print a path that was not checked. When
// the executable cannot be read, or its path names a file that is not the running binary, tego agents' refusal, its
// next: step, tego doctor's root hints and tego setup's refusal name no command and say why.
func TestRootHintsNameNoCommandWhenTheBinaryCannotBeNamed(t *testing.T) {
	old := executable
	t.Cleanup(func() { executable = old })
	other := filepath.Join(t.TempDir(), "tego")
	if err := os.WriteFile(other, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	hintsAt(t, false, "on")
	for name, exe := range map[string]func() (string, error){
		"the executable cannot be read":      func() (string, error) { return "", os.ErrNotExist },
		"the path is not the running binary": func() (string, error) { return other, nil },
		"the path is gone":                   func() (string, error) { return filepath.Join(t.TempDir(), "none"), nil },
	} {
		t.Run(name, func(t *testing.T) {
			executable = exe
			cmd, why := sudoSelf("agents")
			if cmd != "" || why == "" {
				t.Fatalf("sudoSelf = %q, %q: want no command and a reason", cmd, why)
			}
			noLookup := func(what, s string) {
				t.Helper()
				if strings.Contains(s, "command -v") || strings.Contains(s, "sudo tego") || strings.Contains(s, other) {
					t.Errorf("%s names a command that was not checked: %q", what, s)
				}
			}
			msg := agentsPrivilegeMessage(nil, true)
			noLookup("the agents refusal", msg)
			if !strings.Contains(msg, why[:len(why)-1]) {
				t.Errorf("the agents refusal does not say why: %q", msg)
			}
			text, command := agentsNext([]int32{4242}, nil)
			if command != "" || text != why {
				t.Errorf("agentsNext = %q, %q, want no command and %q", text, command, why)
			}
			var b bytes.Buffer
			writeDoctorVerdict(&b, &doctor.Report{Tier: backend.TierCgroup, Root: true})
			noLookup("the root doctor's ready hint", b.String())
			if c, ok := nextCommand(b.String()); !ok || c != "" || !strings.Contains(b.String(), "next: "+why) {
				t.Errorf("the root doctor's hint: %q", b.String())
			}
			b.Reset()
			writeDoctorVerdict(&b, &doctor.Report{Tier: backend.TierLandlock, Require: backend.TierCgroup, Fix: "run as root"})
			noLookup("the --require hint", b.String())
			if c, ok := nextCommand(b.String()); !ok || c != "" || !strings.Contains(b.String(), "next: "+why) {
				t.Errorf("the --require hint: %q", b.String())
			}
		})
	}
}

// TestLearnGivesNoCommandForAFolderItCannotShow: tego learn --save ended with "cd <folder> && tego run <name>", the folder
// from run_start.cwd, which a record-only agent or a forged record chooses. record.Printable wrote a newline in the folder's
// name as backslash and n, so the line named the folder with those two characters in its name: a different folder, or
// none. The raw folder is checked before it is quoted; one that cannot be shown
// faithfully gives no command, and the sentence says why.
func TestLearnGivesNoCommandForAFolderItCannotShow(t *testing.T) {
	root, anchor, _ := saveHarness(t, "")
	base := resolvedTemp(t)
	// The sibling the altered line would name, to show the difference is real.
	lookalike := filepath.Join(base, `a\nb`)
	project := filepath.Join(base, "a\nb")
	for _, d := range []string{lookalike, project} {
		if err := os.MkdirAll(filepath.Join(d, "out"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	id := readsRun(t, root, anchor, project, &record.ReadsNotified{Why: record.ReadsNotifiedWhyRecordsOnly}, false)
	short := id[strings.LastIndexByte(id, '-')+1:]
	hintsAt(t, false, "on")
	code, _, errs := run(t, "learn", short, "--save", "bot")
	if code != identity.ExitOK {
		t.Fatalf("exit %d:\n%s", code, errs)
	}
	if c, ok := nextCommand(errs); !ok || c != "" {
		t.Errorf("a command was given for an unshowable folder: %q\n%s", c, errs)
	}
	if !strings.HasSuffix(errs, "\nnext: "+unsafeFolderText+"\n") {
		t.Errorf("the last block does not say why:\n%s", errs)
	}
	if strings.Contains(errs, `a\nb`) || strings.Contains(errs, "cd ") {
		t.Errorf("the output names an altered folder:\n%s", errs)
	}
	// The same record, a folder that prints: unchanged.
	ok := filepath.Join(base, "fine dir")
	if err := os.MkdirAll(filepath.Join(ok, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	id2 := readsRun(t, root, anchor, ok, &record.ReadsNotified{Why: record.ReadsNotifiedWhyRecordsOnly}, false)
	short2 := id2[strings.LastIndexByte(id2, '-')+1:]
	if _, _, errs := run(t, "learn", short2, "--save", "bot2"); !strings.HasSuffix(errs, "  cd '"+ok+"' && tego run bot2\n") {
		t.Errorf("a folder that prints lost its command:\n%s", errs)
	}
}

// TestNoHintPrintsAnAlteredCommand: the last funnel of every pasteable line (writeHint, runHint): a command that
// record.Printable would change (control, invisible or invalid characters) is not printed as another command; the block
// says no command is given.
func TestNoHintPrintsAnAlteredCommand(t *testing.T) {
	hintsAt(t, false, "on")
	for name, cmd := range map[string]string{
		"newline":   "tego receipt a\nsudo -i",
		"escape":    "tego receipt a\x1b[2J",
		"bidi":      "tego receipt \u202eevil",
		"invalid":   "tego receipt a\xffb",
		"folder":    "cd '/work/a\nb' && tego run bot",
		"printable": "",
	} {
		for _, via := range []string{"writeHint", "runHint"} {
			var b bytes.Buffer
			if via == "writeHint" {
				writeHint(&b, "see it:", cmd)
			} else {
				runHint(&b, "see it:", cmd)
			}
			got, ok := nextCommand(b.String())
			if name == "printable" {
				continue
			}
			if !ok || got != "" || !strings.Contains(b.String(), "next: "+unsafeCommandText) || strings.ContainsAny(b.String(), "\x1b\u202e") {
				t.Errorf("%s via %s: %q", name, via, b.String())
			}
		}
	}
	var b bytes.Buffer
	writeHint(&b, "see it:", "cd '/work/my dir' && tego run bot")
	if got, _ := nextCommand(b.String()); got != "cd '/work/my dir' && tego run bot" {
		t.Errorf("a command that prints was changed: %q", got)
	}
}

// The non-root refusal must name the checked executable, or give its refusal reason.
func TestAdoptRefusalNamesCheckedCommand(t *testing.T) {
	sandboxAdopt(t, terminalProcs(), false)
	old := namedSelf
	t.Cleanup(func() { namedSelf = old })
	for _, tc := range []struct{ name, word, reason string }{
		{"quoted executable", "'/opt/my tools/tego'", ""},
		{"unavailable", "", "this tego's path cannot be named, so no sudo line is given."},
		{"unsafe", "", "this tego's path cannot be shown safely, so no sudo line is given."},
		{"untrusted chain", "", "cannot verify that only root or you can change this tego's path, so no command is shown; install Tego in a folder only root or you can write."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			namedSelf = func() (string, string) { return tc.word, tc.reason }
			code, _, errs := runAdoptCmd(t, t.Context(), "--pid", "500")
			if code != identity.ExitLauncher || !strings.Contains(errs, "[privilege]") {
				t.Fatalf("exit %d: %s", code, errs)
			}
			if tc.reason == "" {
				if !strings.Contains(errs, "sudo "+tc.word+" adopt --pid <pid>") {
					t.Fatalf("missing checked command: %s", errs)
				}
			} else if !strings.Contains(errs, tc.reason) || strings.Contains(errs, "sudo /") || strings.Contains(errs, "sudo '") {
				t.Fatalf("want no command and reason %q: %s", tc.reason, errs)
			}
		})
	}
}
