// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func TestStartKeptRulesRecap(t *testing.T) {
	f := onFixture(t, "fresh")
	noLogins(t)
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "x")
	fakeProgram(t, "claude")
	t.Chdir(f.Home)
	if code, out, errs := runGuide(t, "1\n1\n1\n"); code != identity.ExitOK {
		t.Fatalf("initial: %d %s %s", code, out, errs)
	}
	before := savedRules(t, guideSample)
	code, out, errs := runGuide(t, "1\n1\n2\n1\n")
	if code != identity.ExitOK {
		t.Fatalf("keep: %d %s %s", code, out, errs)
	}
	_, recap, _ := strings.Cut(out, "Ready")
	if strings.Contains(recap, "Rules       Read-only review") {
		t.Fatalf("recap claims unsaved rules: %s", recap)
	}
	m, _, _ := loadMachine(config.TrustWarn)
	path, _ := agentFile(m, guideSample)
	if !strings.Contains(recap, "Rules       Kept file: "+tildeHome(path, f.Home)) {
		t.Fatalf("kept path missing: %s", recap)
	}
	if got := savedRules(t, guideSample); got != before {
		t.Fatal("kept file changed")
	}
}
