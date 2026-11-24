// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestBuilderDropPreservesOtherRules(t *testing.T) {
	f := newFixture(t)
	dir := f.newProject(t, "builder")
	text := "version: 0\nname: builder\ncommand: [sh]\nfs:\n  write: [./out/]\n  deny_read: [./secret/]\nexec:\n  allow: [sh, git]\nnet:\n  allow: ['192.0.2.1:443']\nenv:\n  pass: []\n"
	req := NewReq{Dir: dir, Name: "builder", Text: []byte(text), Drop: []string{decisionID("exec.allow", "git")}}
	p, err := f.s.PlanNew(context.Background(), req)
	if err != nil || !p.OK {
		t.Fatalf("plan: %+v, %v", p, err)
	}
	if strings.Contains(string(p.Text), "git") || !strings.Contains(string(p.Text), "./secret/") {
		t.Fatalf("wrong rules: %s", p.Text)
	}
	if len(p.Decisions) != 4 {
		t.Fatalf("decisions: %+v", p.Decisions)
	}
	c, err := f.s.CreateNew(context.Background(), req, p.Base)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(c.Path)
	if err != nil || string(b) != string(p.Text) {
		t.Fatalf("save differs: %s %v", b, err)
	}
}
func TestBuilderBlankIsClosedAndFullIsExact(t *testing.T) {
	f := newFixture(t)
	dir := f.newProject(t, "blank")
	req := NewReq{Dir: dir, Name: "blank", Blank: true}
	p, _ := f.s.PlanNew(context.Background(), req)
	if !p.OK || !strings.Contains(string(p.Text), "pass: []") || !strings.Contains(string(p.Text), "allow: []") {
		t.Fatalf("blank: %+v", p)
	}
	req.Text = []byte("# keep this comment\nversion: 0\nname: blank\ncommand: [sh]\n")
	p, _ = f.s.PlanNew(context.Background(), req)
	if string(p.Text) != string(req.Text) {
		t.Fatalf("Full changed bytes: %s", p.Text)
	}
}

func TestBuilderModeSwitchDoesNotInventRules(t *testing.T) {
	text := []byte("# preserved\nversion: 0\nname: b\ncommand: [sh]\nnet:\n  allow: []\n")
	got, _, err := EditDraft(NewReq{Text: text, Switches: true})
	if err != nil || string(got) != string(text) {
		t.Fatalf("switch changed draft: %s %v", got, err)
	}
}

func TestBuilderRejectsSymlinkedRegistry(t *testing.T) {
	f := newFixture(t)
	dir := f.newProject(t, "save-link")
	outside := f.newProject(t, "elsewhere")
	registry := f.dir + "/registry-link"
	if err := os.Symlink(outside, registry); err != nil {
		t.Fatal(err)
	}
	f.s.Machine = &config.Machine{Home: f.s.Home}
	f.s.Machine.Registry.Value = registry
	req := NewReq{Dir: dir, Name: "link-draft", Registry: true, Blank: true}
	p, _ := f.s.PlanNew(context.Background(), req)
	if _, err := f.s.CreateNew(context.Background(), req, p.Base); err == nil {
		t.Fatal("followed symlinked registry")
	}
	if _, err := os.Stat(outside + "/agents/link-draft.yaml"); !os.IsNotExist(err) {
		t.Fatal("created contract outside registry")
	}
}

func TestBuilderNewDraftNeverCarriesEnvironmentValues(t *testing.T) {
	f := newFixture(t)
	dir := f.newProject(t, "env-new")
	req := NewReq{Dir: dir, Name: "env-new", Text: []byte("version: 0\nname: env-new\ncommand: [sh]\nenv:\n  set:\n    TOKEN: a-private-value\n")}
	p, _ := f.s.PlanNew(context.Background(), req)
	if p.OK {
		t.Fatal("new builder accepted environment values it cannot restore")
	}
	if strings.Contains(string(p.Text), "a-private-value") || strings.Contains(strings.Join(p.Problems, " "), "a-private-value") {
		t.Fatal("value reached response")
	}
}

func TestBuilderUnknownDropCannotAddPermission(t *testing.T) {
	text := []byte("version: 0\nname: b\ncommand: [sh]\nnet:\n  allow: []\n")
	edited, _, err := EditDraft(NewReq{Text: text, Drop: []string{"net.allow:attacker.example:443"}, NameHosts: map[string]string{"invented": "attacker.example"}})
	if err != nil || string(edited) != string(text) {
		t.Fatalf("unknown decision changed file: %s %v", edited, err)
	}
}

// moveAtReplace reproduces a directory swap after the service read its base but before the writer pins it.
type moveAtReplace struct {
	Writer
	move func() error
}

func (w moveAtReplace) Replace(ctx context.Context, path, base string, text []byte, c rulefile.Change) (*rulefile.Entry, error) {
	if err := w.move(); err != nil {
		return nil, err
	}
	return w.Writer.Replace(ctx, path, base, text, c)
}

func TestBuilderCannotFollowFolderSwappedBeforeWrite(t *testing.T) {
	f := newFixture(t)
	c := f.ref(t, f.contract)
	original, err := os.ReadFile(f.contract)
	if err != nil {
		t.Fatal(err)
	}
	outside := f.newProject(t, "outside-contracts")
	outsideFile := filepath.Join(outside, "agent.yaml")
	if err := os.WriteFile(outsideFile, original, 0600); err != nil {
		t.Fatal(err)
	}
	writer := f.s.writer()
	f.s.Writer = moveAtReplace{Writer: writer, move: func() error {
		if err := os.Rename(f.proj, f.proj+"-loaded"); err != nil {
			return err
		}
		return os.Symlink(outside, f.proj)
	}}
	req := RawReq{Ref: c.Ref, Base: c.Base, Text: append(append([]byte{}, original...), []byte("\n# checked edit\n")...)}
	p, err := f.s.PlanRaw(t.Context(), req)
	if err != nil || p.Err != "" {
		t.Fatalf("preview: %+v %v", p, err)
	}
	req.Ack = p.Ack
	if _, err := f.s.ApplyRaw(t.Context(), req); err == nil {
		t.Error("followed a contracts-folder link swapped in after the read")
	}
	b, err := os.ReadFile(outsideFile)
	if err != nil || string(b) != string(original) {
		t.Fatalf("overwrote a file outside the loaded contracts folder: %s %v", b, err)
	}
}

func TestBuilderModeSwitchPreservesAutomaticReadsAndAskComments(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		hosts      []string
	}{
		{"automatic reads", "version: 0\nname: unchanged\ncommand: [sh]\nreason:\n  reads: auto # keep this choice\n", nil},
		{"approval comments", "version: 0\nname: unchanged\ncommand: [sh]\nnet:\n  ask: # hosts reviewed by the owner\n    - 'api.example.com:443' # keep this explanation\n", []string{"api.example.com:443"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := EditDraft(NewReq{Text: []byte(tc.text), Switches: true, AskHosts: tc.hosts, WantAsk: len(tc.hosts) > 0})
			if err != nil || string(got) != tc.text {
				t.Fatalf("view switch changed an unedited rule: %s (%v)", got, err)
			}
		})
	}
}
