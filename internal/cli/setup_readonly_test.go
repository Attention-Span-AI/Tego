// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func TestReadOnlyGuideCompiledWriteSet(t *testing.T) {
	for _, which := range []int{0, 1, 2} {
		t.Run(guideAgents[which].label, func(t *testing.T) {
			f := onFixture(t, "fresh")
			a := guideAgents[which]
			command := a.command
			if command == "" {
				command = "/bin/sh"
			} else {
				fakeProgram(t, command)
			}
			for _, name := range []string{"package.json", "Cargo.toml", "pyproject.toml", "go.mod"} {
				if err := os.WriteFile(filepath.Join(f.Project, name), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			m, _, err := loadMachine(config.TrustWarn)
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			g := newWalk(strings.NewReader("2\n"), &out, false)
			rc, err := g.rules(context.Background(), m, a.label, a, f.Project)
			if err != nil {
				t.Fatal(err)
			}
			var errs bytes.Buffer
			file, code := guideSaveRules(context.Background(), m, a, command, "review", f.Project, rc, false, false, &errs)
			if code != identity.ExitOK {
				t.Fatalf("save %d: %s", code, &errs)
			}
			c, ds, err := agent.Load(file, profileSources(m))
			if err != nil {
				t.Fatalf("load: %v %v", err, ds)
			}
			rt, ds, err := agent.Compile(c, m, agent.Offline(), agent.WithHome(f.Home), agent.WithPATH(os.Getenv("PATH")))
			if err != nil {
				t.Fatalf("compile: %v %v", err, ds)
			}
			sub := "review"
			if which == 0 {
				sub = "claude"
			}
			if which == 1 {
				sub = "codex"
			}
			state := filepath.Join(f.Project, ".tego", sub)
			writes := 0
			for _, rule := range rt.FS {
				if rule.Kind != agent.FSWrite {
					continue
				}
				p := strings.TrimSuffix(rule.Resolved, "/")
				switch p {
				case "/dev/null", "/dev/tty", "/dev/ptmx", "/dev/pts", "/dev/pts/ptmx":
					continue
				}
				if p != state && !strings.HasPrefix(p, state+"/") {
					t.Errorf("review grants ordinary filesystem write outside state: %s", p)
				}
				if p == f.Project || strings.HasPrefix(p, f.Project+"/") {
					writes++
					if p != state && !strings.HasPrefix(p, state+"/") {
						t.Errorf("review grants project write outside agent state: %s", p)
					}
				}
			}
			if writes == 0 {
				t.Error("agent state is not writable")
			}
		})
	}
}
