// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os/user"
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// env.set names new to the environment are appended in name order, so the agent's environ is the same on every run.
func TestBuildEnvAppendsSetInNameOrder(t *testing.T) {
	rt := &agent.RuleTable{Set: map[string]string{"D": "4", "B": "2", "A": "1", "C": "3", "E": "5"}}
	want := []string{"X=0", "A=1", "B=2", "C=3", "D=4", "E=5"}
	for i := 0; i < 20; i++ {
		if got := buildEnv(rt, []string{"X=0"}); !slices.Equal(got, want) {
			t.Fatalf("environ %v, want %v", got, want)
		}
	}
}

// A variable the launcher's environment holds twice takes env.set's value once, so a reader of the last entry
// sees it too.
func TestBuildEnvSetReplacesEveryDuplicate(t *testing.T) {
	rt := &agent.RuleTable{Set: map[string]string{"FOO": "b"}}
	got := buildEnv(rt, []string{"FOO=a", "Z=1", "FOO=a"})
	if want := []string{"FOO=b", "Z=1"}; !slices.Equal(got, want) {
		t.Fatalf("environ %v, want %v", got, want)
	}
}

// A root launcher's environment names root, and the agent runs as the invoking user: what names root becomes that
// user's (identity-config.md R3a), and nothing else changes.
func TestRootAccountEnv(t *testing.T) {
	root := &user.User{Username: "root", HomeDir: "/root"}
	target := &user.User{Username: "dana", HomeDir: "/home/dana"}
	for _, tc := range []struct {
		name         string
		target       *user.User
		environ, out []string
	}{
		{"sudo's reset", target, []string{"HOME=/root", "USER=root", "LOGNAME=root", "PATH=/bin"}, []string{"HOME=/home/dana", "USER=dana", "LOGNAME=dana", "PATH=/bin"}},
		{"a HOME the caller chose stays", target, []string{"HOME=/srv/agent", "USER=root"}, []string{"HOME=/srv/agent", "USER=dana"}},
		{"a name the launcher does not have stays absent", target, []string{"PATH=/bin"}, []string{"PATH=/bin"}},
		{"another variable holding root's value stays", target, []string{"OWNER=root", "BASE=/root"}, []string{"OWNER=root", "BASE=/root"}},
		{"an entry with no = stays", target, []string{"HOME"}, []string{"HOME"}},
		{"an account with no home keeps the launcher's", &user.User{Username: "dana"}, []string{"HOME=/root", "USER=root"}, []string{"HOME=/root", "USER=dana"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := slices.Clone(tc.environ)
			if got := rootAccountEnv(in, root, tc.target); !slices.Equal(got, tc.out) {
				t.Fatalf("environ %v, want %v", got, tc.out)
			}
			if !slices.Equal(in, tc.environ) {
				t.Fatalf("the launcher's own environment changed: %v", in)
			}
		})
	}
}

// The contract applies after the rewrite: a name env.pass leaves out does not come back, and env.set still wins.
func TestRootAccountEnvIsBelowTheContract(t *testing.T) {
	environ := rootAccountEnv([]string{"HOME=/root", "USER=root", "PATH=/bin"}, &user.User{Username: "root", HomeDir: "/root"},
		&user.User{Username: "dana", HomeDir: "/home/dana"})
	rt := &agent.RuleTable{Env: []string{"PATH", "HOME"}, Set: map[string]string{"HOME": "/work"}}
	if got, want := buildEnv(rt, environ), []string{"HOME=/work", "PATH=/bin"}; !slices.Equal(got, want) {
		t.Fatalf("environ %v, want %v", got, want)
	}
}
