// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestForwarderVarNamesIsTheOneList: the forwarder's variables were three lists that disagreed (Compile's
// reserved names held the Anthropic and OpenAI ones, the listeners set the Google ones too, R7 named the Google
// ones and CODEX_HOME but not the OpenAI ones). Every provider's base-URL variable is in ForwarderVarNames, and
// R7 and RUN-IDENTITY.md's forwarder row name exactly that list.
// identity-config.md R7: the forwarder base-URL variables.
func TestForwarderVarNamesIsTheOneList(t *testing.T) {
	for _, p := range []string{"anthropic", "openai", "google", "gemini", "google-gemini", " OpenAI "} {
		vars := ProviderBaseURLVars(p)
		if len(vars) == 0 {
			t.Errorf("provider %q has no variables", p)
		}
		for _, v := range vars {
			if !ForwarderVar(v) {
				t.Errorf("provider %q sets %s, which ForwarderVarNames leaves out", p, v)
			}
		}
	}
	if ProviderBaseURLVars("mistral") != nil {
		t.Error("an unknown provider has variables")
	}
	if ForwarderVar("PATH") {
		t.Error("PATH is a forwarder variable")
	}
	want := slices.Sorted(slices.Values(ForwarderVarNames[:]))
	name := regexp.MustCompile("`([A-Z_]+)`")
	for _, doc := range []struct{ file, start, end string }{
		{filepath.Join("..", "..", "..", "docs", "p0", "identity-config.md"), "- **R7** Forwarder base-URL vars (", ")"},
		{filepath.Join("..", "..", "..", "spec", "identity", "RUN-IDENTITY.md"), "| `ANTHROPIC_BASE_URL`", "| the forwarder"},
	} {
		b, err := os.ReadFile(doc.file)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		i := strings.Index(s, doc.start)
		if i < 0 {
			t.Fatalf("%s: no %q", doc.file, doc.start)
		}
		s = s[i:]
		if j := strings.Index(s[len(doc.start):], doc.end); j >= 0 {
			s = s[:len(doc.start)+j]
		}
		var got []string
		for _, m := range name.FindAllStringSubmatch(s, -1) {
			got = append(got, m[1])
		}
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("%s names %v, want identity.ForwarderVarNames %v", doc.file, got, want)
		}
	}
}
