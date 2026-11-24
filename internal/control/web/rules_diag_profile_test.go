// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A compile diagnostic that lies in a profile the contract extends names the profile, its file and its line, where the
// page used to show the bare compiler text with no line and no link: the person could not tell which file to open.
func TestRawEditorNamesTheProfileFileAndLineOfADiagnostic(t *testing.T) {
	f := newChangeFix(t)
	profiles := filepath.Join(t.TempDir(), "profiles")
	if err := os.MkdirAll(profiles, 0o700); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(profiles, "base.yaml")
	if err := os.WriteFile(profile, []byte("version: 0\nname: base\nfs:\n  write: []\nbogus_key: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.svc.Machine.Profiles.Value = profiles
	ref := f.ref(t, f.other)
	v := url.Values{"mode": {"raw"}, "c": {ref.Ref}, "base": {ref.Base}, "step": {"check"},
		"text": {"version: 0\nname: other-agent\ncommand: [sh]\nextends: base\n"}}
	code, body := f.post(t, "/rules/change", v)
	if code != http.StatusOK || !strings.Contains(body, "This text cannot be saved") {
		t.Fatalf("%d: %s", code, body)
	}
	list := regexp.MustCompile(`(?s)<ul class="rc-diags">.*?</ul>`).FindString(body)
	for _, want := range []string{"Profile base", profile, "line 5"} {
		if !strings.Contains(list, want) {
			t.Fatalf("the diagnostic lacks %q:\n%s", want, list)
		}
	}
	if strings.Contains(list, `href="#yl-`) {
		t.Errorf("a profile's line is linked to this text's lines:\n%s", list)
	}
}
