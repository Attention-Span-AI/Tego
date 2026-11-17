// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"fmt"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadOnlyRefusesLinkedState(t *testing.T) {
	for _, choice := range []struct{ agent, state string }{{"claude-code", "claude"}, {"codex", "codex"}, {"", "review"}} {
		for _, at := range []string{".tego", filepath.Join(".tego", choice.state), filepath.Join(".tego", choice.state, "tmp")} {
			t.Run(choice.state+"/"+at, func(t *testing.T) {
				dir := project(t, "src/tmp/", "src/"+choice.state+"/tmp/")
				planted := filepath.Join(dir, at)
				if err := os.MkdirAll(filepath.Dir(planted), 0700); err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(dir, "src")
				if err := os.Symlink(target, planted); err != nil {
					t.Fatal(err)
				}
				o := Options{Dir: dir, Name: "review", Presets: []string{"no-secrets,no-prod,repo-only-writes"}, Agent: choice.agent, ReadOnlyProject: true}
				if choice.agent == "" {
					o.Command = "/bin/sh"
				}
				_, err := Compose(o)
				if err == nil || !strings.Contains(err.Error(), planted) || !strings.Contains(err.Error(), "remove") || !strings.Contains(err.Error(), "other rules") {
					t.Fatalf("planted state accepted or unclear: %v", err)
				}
			})
		}
	}
}

func TestReviewChecksResolvedWriteTargets(t *testing.T) {
	dir := project(t, "src/")
	home := t.TempDir()
	r := compose(t, Options{Dir: dir, Home: home, Name: "review", Command: "/bin/sh", ReadOnlyProject: true, Presets: []string{"no-secrets,no-prod,repo-only-writes"}})
	if err := os.Symlink(filepath.Join(dir, "src"), filepath.Join(dir, ".tego/review/content")); err != nil {
		t.Fatal(err)
	}
	contract := []byte(strings.Replace(string(r.Contract), "  write:\n", "  write:\n    - \"./.tego/review/content/\"\n", 1))
	env := CheckEnv{Options: []agent.CompileOption{agent.WithHome(home), agent.WithPATH("/usr/bin:/bin")}}
	ds, ok := CheckReviewFile(contract, filepath.Join(dir, "agent.yaml"), dir, env, ".tego/review/")
	if ok {
		t.Fatal("compiled write grant resolves through a nested state link into project content")
	}
	if !strings.Contains(fmt.Sprint(ds), "resolves outside") {
		t.Fatalf("unexpected refusal: %v", ds)
	}
}
