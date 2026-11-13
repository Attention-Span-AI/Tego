// SPDX-License-Identifier: Apache-2.0

package execmatch_test

import (
	"strings"
	"testing"
)

func TestDefaultOptionsBeforeExplicitCommand(t *testing.T) {
	ix := index(t, "deny: git notes get-ref")
	if got := decide(ix, "git", "notes", "--ref", "refs/notes/commits", "get-ref"); got != "refused exec.deny[git notes get-ref]" {
		t.Fatalf("explicit command after a default level's option: %s", got)
	}
}

func TestCommandSearchBeforeFlagParsing(t *testing.T) {
	for _, c := range []struct {
		entry string
		argv  []string
	}{
		// Cobra command.go stripFlags skips the whole bundle without taking a
		// separate value. Find can therefore select delete before pflag parses n.
		{"kubectl delete", []string{"kubectl", "-An", "delete", "pods"}},
		{"oc delete", []string{"oc", "-An", "delete", "pods"}},
		// Cobra stripFlags drops empty words and lone dashes. gh 2.103.3 harmless
		// version probes confirm both spellings select version.
		{"gh version", []string{"gh", "", "version"}},
		{"gh version", []string{"gh", "-", "version"}},
	} {
		if got := decide(index(t, "deny: "+c.entry), c.argv...); got != "refused exec.deny["+c.entry+"]" {
			t.Errorf("%q: %s", c.argv, got)
		}
	}
}

func TestDefaultOptionsKeepDefaultAndAsk(t *testing.T) {
	for _, list := range []string{"deny", "ask"} {
		for _, c := range []struct{ entry, line string }{
			{"git stash push", "git stash -m note"},
			{"git notes list", "git notes --ref=refs/notes/commits"},
			{"git notes get-ref", "git notes --ref=refs/notes/commits get-ref"},
			{"git notes get-ref", "git notes --future value get-ref"},
			{"git submodule update", "git submodule --quiet update"},
		} {
			if got := decide(index(t, list+": "+c.entry), strings.Fields(c.line)...); got != "refused exec."+list+"["+c.entry+"]" {
				t.Errorf("%s: %s: %s", list, c.line, got)
			}
		}
	}
}
