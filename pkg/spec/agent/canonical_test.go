// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"gopkg.in/yaml.v3"
)

const canonicalSrc = `version: 0
name: a
command: ["python", "agent.py"]   # the agent
fs:
    write:   [ "/work/out" ]
limits:
  memory: 8GiB
  wall: 2h
  cpu: "2.0"
env:
  set: {B: "2", A: "1"}
gate:
  rules:  # a comment
    - "exec matches x": 90
`

func TestCanonicalStableAcrossWhitespace(t *testing.T) {
	load := func(src string) *Contract {
		t.Helper()
		c, ds, err := LoadBytes("a.yaml", []byte(src), nil)
		if err != nil && !errors.Is(err, ErrInvalidContract) {
			t.Fatalf("%v\n%s", err, render(ds))
		}
		if c == nil {
			// gate: is not-yet-supported; load the hashable subset instead.
			t.Fatalf("contract rejected:\n%s", render(ds))
		}
		return c
	}
	src := strings.Replace(canonicalSrc, "gate:\n  rules:  # a comment\n    - \"exec matches x\": 90\n", "", 1)
	a := load(src)
	b := load("\xef\xbb\xbf" + strings.ReplaceAll(strings.ReplaceAll(src, "   # the agent", ""), "\n", "\r\n"))
	ca, err := a.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	cb, err := b.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ca, cb) {
		t.Errorf("canonical differs across whitespace/comments/BOM/CRLF:\n%s\n---\n%s", ca, cb)
	}
	ha, _ := a.Hash()
	hb, _ := b.Hash()
	if ha != hb {
		t.Error("hash differs")
	}
	want := "version: 0\nname: a\ncommand:\n  - python\n  - agent.py\nfs:\n  write:\n    - /work/out\nenv:\n  set:\n    A: \"1\"\n    B: \"2\"\nlimits:\n  cpu: \"2.0\"\n  memory: 8GiB\n  wall: 2h\n"
	if string(ca) != want {
		t.Errorf("canonical bytes:\n%s\nwant:\n%s", ca, want)
	}
	// Reloading the canonical bytes reproduces the hash (units round-trip).
	c2, ds, err := LoadBytes("b.yaml", ca, nil)
	if err != nil {
		t.Fatalf("%v\n%s", err, render(ds))
	}
	if h2, _ := c2.Hash(); h2 != ha {
		t.Error("canonical output does not reload to the same hash")
	}
	// A content change changes the hash.
	c3 := load(strings.Replace(src, "8GiB", "9GiB", 1))
	if h3, _ := c3.Hash(); h3 == ha {
		t.Error("hash ignores a value change")
	}
	if _, err := (&Contract{}).Canonical(); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("unloaded contract: %v", err)
	}
	if _, err := (*Contract)(nil).Canonical(); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("nil contract: %v", err)
	}
}

// TestCanonicalKeepsSchemaOnlyFields: a not-yet-supported field is rejected
// at Load, but a profile-free P0 build of the same bytes through the decoder
// must still emit it, so a P1 field changes the hash (R13). Exercised through
// normalizeSchemaOnly on a decoded value.
func TestCanonicalSchemaOnlyNormalized(t *testing.T) {
	l := &loader{}
	c := l.parse("g.yaml", []byte(canonicalSrc), false)
	if c == nil {
		t.Fatalf("parse failed: %s", render(l.ds.list))
	}
	if nodeEmpty(&c.Gate) || c.Gate.Line != 0 || c.Gate.Content[1].HeadComment != "" && c.Gate.Content[1].LineComment != "" {
		t.Errorf("gate node not normalized: %+v", c.Gate)
	}
	c.loaded = true
	out, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "gate:\n  rules:\n    - exec matches x: 90\n") || strings.Contains(string(out), "#") {
		t.Errorf("gate emitted with comments or missing:\n%s", out)
	}
	e := l.parse("e.yaml", []byte("version: 0\nname: a\ncommand: [x]\ndocker: {}\nask: {}\ngate: {}\n"), false)
	if e == nil || !e.Docker.IsZero() || !e.Ask.IsZero() || !e.Gate.IsZero() {
		t.Errorf("empty schema-only values must be zeroed: %+v", e)
	}
}

// agent-contract.md E25: a contract over 1MiB is refused before parse.
func TestLoadFileErrors(t *testing.T) {
	if _, ds, err := Load(filepath.Join(t.TempDir(), "missing.yaml"), nil); !errors.Is(err, os.ErrNotExist) || ds != nil {
		t.Errorf("missing file: %v %v", err, ds)
	}
	if _, _, err := Load("", nil); err == nil {
		t.Error("empty path accepted")
	}
	big := filepath.Join(t.TempDir(), "big.yaml")
	if err := os.WriteFile(big, append([]byte("version: 0\nname: a\ncommand: [x]\n# "), bytes.Repeat([]byte("x"), MaxContractSize)...), 0o644); err != nil {
		t.Fatal(err)
	}
	_, ds, err := Load(big, nil)
	if !errors.Is(err, ErrInvalidContract) || len(ds) != 1 || ds[0].Line != 1 || !strings.Contains(ds[0].Message, "exceeds 1MiB") {
		t.Errorf("oversize: %v %v", err, ds)
	}
	_, ds, err = LoadBytes("p.yaml", []byte("version: 0\nname: a\nextends: p\ncommand: [x]\n"), mapSource{"p": strings.Repeat("#", MaxContractSize+1)})
	if !errors.Is(err, ErrInvalidContract) || !strings.Contains(render(ds), "exceeds 1MiB") {
		t.Errorf("oversize profile: %v\n%s", err, render(ds))
	}
}

// TestFSSectionEmptyDenyReadKeepsEveryField holds FSSection.MarshalYAML's `deny_read: []` form to
// FSSection's own field list. That form departs from omitempty for one key (R13); every other field
// must still be encoded, under its own tag and in struct order, or a field could change the policy
// without changing contract_hash, and only when deny_read is []. The fields are filled through
// reflect, so a field added to FSSection later is covered without editing this test, and one of a
// type the test cannot fill fails it rather than passing unchecked.
func TestFSSectionEmptyDenyReadKeepsEveryField(t *testing.T) {
	var s FSSection
	v := reflect.ValueOf(&s).Elem()
	var keys []string
	for i := range v.NumField() {
		f := v.Type().Field(i)
		if !f.IsExported() {
			// Nothing Compile reads may live outside what Canonical writes, and the encoder
			// never writes an unexported field.
			t.Fatalf("FSSection.%s is unexported, so Canonical can never carry it (R13)", f.Name)
		}
		key, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		keys = append(keys, key)
		switch {
		case f.Name == "DenyRead":
			v.Field(i).Set(reflect.ValueOf([]string{}))
		case f.Type == reflect.TypeFor[[]string]():
			v.Field(i).Set(reflect.ValueOf([]string{"/" + key}))
		case f.Type == reflect.TypeFor[FSAssurance]():
			v.Field(i).Set(reflect.ValueOf(FSAssuranceKernel))
		case f.Type == reflect.TypeFor[ReadsMode]():
			v.Field(i).Set(reflect.ValueOf(ReadsHeld))
		case f.Type == reflect.TypeFor[bool]():
			v.Field(i).SetBool(true)
		default:
			t.Fatalf("FSSection.%s is a %s: extend this test to fill it", f.Name, f.Type)
		}
	}

	out, err := yaml.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var got []string
	for i := 0; i+1 < len(doc.Content[0].Content); i += 2 {
		got = append(got, doc.Content[0].Content[i].Value)
	}
	if !slices.Equal(got, keys) {
		t.Fatalf("keys = %v, want every FSSection field in struct order %v:\n%s", got, keys, out)
	}
	var back FSSection
	if err := yaml.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, s) || back.DenyRead == nil {
		t.Fatalf("round trip = %#v, want %#v with deny_read an empty, non-nil list:\n%s", back, s, out)
	}
}

// TestCanonicalEmptyDenyReadBytes pins the bytes of the `deny_read: []` form, so contract_hash of
// such a contract stays what earlier builds of this form recorded.
func TestCanonicalEmptyDenyReadBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	src := "version: 0\nname: a\ncommand: [python]\nfs:\n  watch: [\"/work/logs\"]\n  deny_read: []\n  write: [\"/work\", \"yes\"]\n"
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	c, ds, err := Load(path, nil)
	if err != nil {
		t.Fatalf("load: %v\n%s", err, render(ds))
	}
	got, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := "version: 0\nname: a\ncommand:\n  - python\nfs:\n  write:\n    - /work\n    - \"yes\"\n  deny_read: []\n  watch:\n    - /work/logs\n"
	if string(got) != want {
		t.Errorf("Canonical =\n%s\nwant\n%s", got, want)
	}
}

// Every tier decides on the canonical path (Landlock holds the link's target, tier 2's
// listener is handed the opened file's path, tier 3's hooks see the dentry). With `deny_read: [/l]` (→ /w/a)
// and `write: [/w/a/b]`, a read of /l/b/f is /w/a/b/f, which the nested write entry reopens in every tier.
// Evaluate matched each entry under both its spellings but never rewrote the row's path, so the write entry
// never covered /l/b/f and the row was refused.
func TestEvaluateRewritesDeclaredLinkPrefix(t *testing.T) {
	rt := &RuleTable{Tier: backend.TierLandlock, FS: []FSRule{
		{Kind: FSDenyRead, Path: "/l", Raw: "/l", Resolved: "/w/a"},
		{Kind: FSWrite, Path: "/w/a/b", Raw: "/w/a/b", Resolved: "/w/a/b", Access: AccessWriteSet},
	}}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		for _, k := range []ActionKind{ActionFSRead, ActionFSWrite} {
			canon := rt.Evaluate(Action{Kind: k, Path: "/w/a/b/f"}, tier)
			link := rt.Evaluate(Action{Kind: k, Path: "/l/b/f"}, tier)
			if canon.Verdict != VerdictAllow || link.Verdict != canon.Verdict {
				t.Errorf("%s %s: /l/b/f = %+v, /w/a/b/f = %+v; want both allow", tier, k, link, canon)
			}
		}
		// Beside the nested write entry the deny_read still refuses the read, by either spelling.
		if r := rt.Evaluate(Action{Kind: ActionFSRead, Path: "/l/c"}, tier); r.Verdict != VerdictRefused {
			t.Errorf("%s: read /l/c = %+v, want refused", tier, r)
		}
	}
	if d, ok := rt.FSDecider("/l/b/f", true); !ok || d.Kind != FSWrite {
		t.Errorf("FSDecider(/l/b/f, read) = %+v, %v; want the write entry", d, ok)
	}
}

// canonical allocates nothing when no symlinked entry covers the path, the recorder's common case: FSDecider
// is on its drain path.
func TestCanonicalNoLinkAllocatesNothing(t *testing.T) {
	rt := &RuleTable{FS: []FSRule{
		{Kind: FSDenyRead, Path: "/l", Resolved: "/w/a"},
		{Kind: FSWrite, Path: "/work", Resolved: "/work", Access: AccessWriteSet},
	}}
	if n := testing.AllocsPerRun(100, func() { _ = rt.canonical("/work/src/main.go") }); n != 0 {
		t.Errorf("canonical of a path no link covers: %v allocs", n)
	}
}

// An exec grant strictly inside a deny_read the Landlock tier enforces reopens reads there
// at tier 1, and compile says so.
func TestExecInsideDenyReadWarns(t *testing.T) {
	f := newFixture(t)
	vault := filepath.Join(f.root, "vault")
	tools := filepath.Join(vault, "tools")
	if err := os.MkdirAll(tools, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tools, "static-tool"), elf64("", 2), 0o755); err != nil {
		t.Fatal(err)
	}
	c := f.load("version: 0\nname: a\ncommand: [python]\ntier: landlock\nfs:\n  deny_read: [\"" + vault + "\"]\nexec:\n  allow: [\"" + tools + "/\"]\n")
	rt, ds := f.compile(c)
	var msg string
	for _, d := range ds {
		if d.Code == CodeUnenforced && strings.Contains(d.Message, tools) {
			msg = d.Message
		}
	}
	if msg == "" {
		t.Fatalf("no unenforced warning naming %s:\n%s", tools, render(ds))
	}
	if !strings.Contains(msg, vault) {
		t.Errorf("warning never names the deny_read %s: %s", vault, msg)
	}
	if r := rt.Evaluate(Action{Kind: ActionFSRead, Path: filepath.Join(tools, "notes.txt")}, backend.TierLandlock); r.Verdict != VerdictAllow {
		t.Errorf("tier 1 read beneath the exec directory = %+v, want allow", r)
	}
	if r := rt.Evaluate(Action{Kind: ActionFSRead, Path: filepath.Join(vault, "key")}, backend.TierLandlock); r.Verdict != VerdictRefused {
		t.Errorf("tier 1 read beside the exec directory = %+v, want refused", r)
	}
	// A deny_read no exec grant lies inside draws no such warning.
	_, ds = f.compile(f.load("version: 0\nname: a\ncommand: [python]\ntier: landlock\nfs:\n  deny_read: [\"" + vault + "\"]\n"))
	for _, d := range ds {
		if d.Code == CodeUnenforced && strings.Contains(d.Message, "exec grant") {
			t.Errorf("unexpected warning: %s", d.Message)
		}
	}
}
