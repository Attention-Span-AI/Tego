// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"flag"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/limits"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// A run prints a notice only when it needs the person's action or when it enforces less than the contract wrote
// (G10): the informational notes (a redundant rule, held reads' cost) are left out of the start, and -v prints
// every one. A warning about a rule the contract wrote, and an error, are never left out.
func TestRunNoticesLeaveOutInformationalNotes(t *testing.T) {
	warn := func(code string) agent.Diagnostic {
		return agent.Diagnostic{Code: code, Message: code + " message", Severity: agent.SeverityWarning}
	}
	quiet := []agent.Diagnostic{warn(agent.CodeRedundantRule), warn(agent.CodeHeldReads)}
	kept := []agent.Diagnostic{
		warn(agent.CodeUnenforced), warn(agent.CodeExecWritable), warn(agent.CodeGlobNoMatch), warn(agent.CodeMountWarning),
		warn(agent.CodeDenyReadDisabled), warn(agent.CodeExecRuleCoverage),
		{Code: agent.CodeRedundantRule, Message: "an error is never a note", Severity: agent.SeverityError},
	}
	all := append(append([]agent.Diagnostic{}, quiet...), kept...)
	got := runNotices(all, false)
	if len(got) != len(kept) {
		t.Fatalf("quiet start printed %+v, want the %d findings that need action or mean less is enforced", got, len(kept))
	}
	for i, d := range got {
		if d.Code != kept[i].Code || d.Severity != kept[i].Severity {
			t.Errorf("quiet start finding %d = %+v, want %+v", i, d, kept[i])
		}
	}
	if got := runNotices(all, true); len(got) != len(all) {
		t.Fatalf("-v printed %d findings, want all %d", len(got), len(all))
	}
	if len(all) != len(quiet)+len(kept) || all[0].Code != agent.CodeRedundantRule {
		t.Fatal("the filter edited the caller's slice")
	}
}

// The notice the owner saw above Codex: a write entry that is a mount point (/dev/pts) is a note, so a quiet start
// leaves it out and -v prints it; a mount warning that says a rule covers less (an overlay) is not a note.
func TestRunNoticesAMountPointIsANote(t *testing.T) {
	c, _, err := agent.LoadBytes("c.yaml", []byte("version: 0\nname: n\ncommand: [\"/bin/true\"]\nfs:\n  write: [\"/dev/shm/\"]\n"), nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	_, ds, err := agent.Compile(c, config.Builtin(), agent.Offline())
	if err != nil {
		t.Fatalf("compile: %v %v", err, ds)
	}
	var mounts int
	for _, d := range ds {
		if d.Code == agent.CodeMountWarning && strings.Contains(d.Message, "is a mount point") {
			mounts++
			if !d.Informational() {
				t.Errorf("%q is not informational", d.Message)
			}
		}
	}
	if mounts == 0 {
		t.Fatalf("compile gave no mount-point note for /dev/shm/: %+v", ds)
	}
	for _, d := range runNotices(ds, false) {
		if strings.Contains(d.Message, "is a mount point") {
			t.Errorf("a quiet start printed %q", d.Message)
		}
	}
	var out bytes.Buffer
	if err := agent.WriteDiagnostics(&out, runNotices(ds, true)); err != nil || !strings.Contains(out.String(), "is a mount point") {
		t.Errorf("-v lacks the mount note (%v):\n%s", err, out.String())
	}
	if (agent.Diagnostic{Code: agent.CodeMountWarning, Severity: agent.SeverityWarning}).Informational() {
		t.Error("a mount warning that is not the mount-point note is informational")
	}
}

// tego run takes -v and --verbose; neither is taken by another flag.
func TestRunTakesVerbose(t *testing.T) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cmdRun().Flags(fs)
	if err := fs.Parse([]string{"-v"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"v", "verbose"} {
		if fs.Lookup(name) == nil {
			t.Errorf("tego run has no -%s", name)
		}
	}
	if got := fs.Lookup("v").Value.String(); got != "true" {
		t.Errorf("-v = %s, want true", got)
	}
}

// internal/check/status leaves the runtime's no-price-table gap out of its gap line by this spelling, and the read
// side may not import the runtime to share the constant.
func TestStatusNoPriceTableSpellingMatchesTheRuntime(t *testing.T) {
	if limits.GapNoPriceTable != "no-price-table" {
		t.Fatalf("limits.GapNoPriceTable = %q: internal/check/status filters the literal no-price-table", limits.GapNoPriceTable)
	}
}
