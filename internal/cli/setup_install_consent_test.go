// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func TestAgentInstallerConsentAndRoot(t *testing.T) {
	oldLook, oldInstall, oldUID := guideLookPath, guideInstall, learnEUID
	t.Cleanup(func() { guideLookPath, guideInstall, learnEUID = oldLook, oldInstall, oldUID })
	guideLookPath = func(string) (string, error) { return "", errors.New("missing") }
	for _, a := range guideAgents[:2] {
		for _, answer := range []string{"1\n", "2\n"} {
			var out bytes.Buffer
			calls := 0
			learnEUID = func() int { return 1000 }
			guideInstall = func(_ context.Context, line string, _ io.Writer) error {
				calls++
				prompt := strings.Index(out.String(), "Install "+a.label+" now?")
				command := strings.Index(out.String(), a.install)
				if line != a.install || command < 0 || command > prompt {
					t.Errorf("installer not disclosed before yes: %s", &out)
				}
				return errors.New("stand-in stops here")
			}
			g := newWalk(strings.NewReader(answer), &out, false)
			_, _ = g.installed(context.Background(), a, a.label, a.command, t.TempDir())
			if answer == "2\n" && calls != 0 {
				t.Error("installer ran without yes")
			}
			if answer == "1\n" && calls != 1 {
				t.Errorf("yes made %d install calls", calls)
			}
		}
	}
	learnEUID = func() int { return 0 }
	calls := 0
	guideInstall = func(context.Context, string, io.Writer) error { calls++; return nil }
	var out bytes.Buffer
	g := newWalk(strings.NewReader("1\n"), &out, false)
	code, _ := g.installed(context.Background(), guideAgents[0], "Claude Code", "claude", t.TempDir())
	if code != identity.ExitFinding || calls != 0 || !strings.Contains(out.String(), "root") || !strings.Contains(out.String(), guideAgents[0].install) {
		t.Fatalf("root installer allowed: %d %d %s", code, calls, &out)
	}
}

func TestGuideWorksAsRoot(t *testing.T) {
	f := onFixture(t, "fresh")
	noLogins(t)
	fakeProgram(t, "claude")
	old := learnEUID
	learnEUID = func() int { return 0 }
	t.Cleanup(func() { learnEUID = old })
	t.Chdir(f.Home)
	code, out, errs := runGuide(t, "1\n2\nsk-test-root\n1\n1\n1\n")
	if code != identity.ExitOK || !strings.Contains(out, "Ready") {
		t.Fatalf("root guide: %d\n%s\n%s", code, out, errs)
	}
}
