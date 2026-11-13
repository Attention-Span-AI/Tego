// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRound3CompileOptionSpellingWarnings(t *testing.T) {
	f := commandFixture(t)
	for _, entry := range []string{"git push ---force", "git push -force"} {
		for _, list := range []string{"allow", "deny", "ask"} {
			source := "version: 0\nname: p\ncommand: [static-tool]\nexec:\n  " + list + ": [" + entry + "]\n"
			path := filepath.Join(f.project, "agent.yaml")
			f.file(path, source, 0o644)
			c, ds, err := Load(path, f.profiles())
			if err != nil && list != "allow" {
				t.Fatalf("load: %v\n%s", err, render(ds))
			}
			if err == nil {
				_, compiled := f.compile(c)
				ds = append(ds, compiled...)
			}
			found := false
			for _, d := range ds {
				if d.Severity == SeverityWarning && d.Code == CodeExecRule && strings.Contains(d.Message, entry) && strings.Contains(d.Message+d.Fix, "--force") {
					found = true
				}
			}
			if !found {
				t.Errorf("%s %s: missing spelling warning:\n%s", list, entry, render(ds))
			}
		}
	}
}

func TestRound3NegatedAbbreviationCompiles(t *testing.T) {
	f := commandFixture(t)
	c := f.load("version: 0\nname: p\ncommand: [static-tool]\nexec:\n  allow: [git add --no-f]\n")
	rt, ds, err := Compile(c, f.machine, f.opts()...)
	if err != nil || hasFinding(ds, CodeExecRule, SeverityError) {
		t.Fatalf("compile: %v\n%s", err, render(ds))
	}
	if rt == nil || rt.ExecCommands == nil {
		t.Fatal("no compiled commands")
	}
}

func TestRound4CompileOrdinaryOptionSpellings(t *testing.T) {
	for _, entry := range []string{
		"go build -race", "go test -run Test", "go test -run=Test",
		"npm install -workspace app", "npx -package tool tool",
		"find -name file", "java -jar app.jar",
	} {
		for _, list := range []string{"allow", "deny", "ask"} {
			t.Run(list+"/"+entry, func(t *testing.T) {
				f := commandFixture(t)
				tool := strings.Fields(entry)[0]
				f.file(filepath.Join(f.bin, tool), string(elf64("", 2)), 0o755)
				path := filepath.Join(f.project, "agent.yaml")
				f.file(path, "version: 0\nname: p\ncommand: [static-tool]\nexec:\n  "+list+": ["+entry+"]\n", 0o644)
				c, ds, err := Load(path, f.profiles())
				if err != nil {
					t.Fatalf("load: %v\n%s", err, render(ds))
				}
				_, compiled := f.compile(c)
				for _, d := range append(ds, compiled...) {
					if strings.Contains(d.Message, "unusual leading dashes") {
						t.Errorf("ordinary tool spelling: %s", d.Message)
					}
				}
			})
		}
	}
}
