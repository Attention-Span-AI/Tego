// SPDX-License-Identifier: Apache-2.0

package agent

import "testing"

// TestBuiltInDenyReadFamilies: every row of the built-in deny_read list has exactly one family, and the family table
// names no path that is not a row, so a page that groups the list never files a row by how its path is spelled. The
// spot checks are rows a spelling would file wrongly: ~/.config/op is 1Password's, not Opera's.
func TestBuiltInDenyReadFamilies(t *testing.T) {
	in := map[string]SecretFamily{}
	for f, rows := range builtInDenyReadFamilies {
		for _, rel := range rows {
			if prev, twice := in[rel]; twice {
				t.Errorf("builtInDenyReadFamilies gives %s two families, %s and %s", rel, prev, f)
			}
			in[rel] = f
		}
	}
	for _, rel := range builtInDenyRead {
		if BuiltInDenyReadFamily(rel) == "" {
			t.Errorf("built-in deny_read row %s has no family: add it to builtInDenyReadFamilies", rel)
		}
		delete(in, rel)
	}
	for rel := range in {
		t.Errorf("builtInDenyReadFamilies names %s, which is not a built-in deny_read row", rel)
	}
	for rel, want := range map[string]SecretFamily{
		".ssh": SecretSSHKeys, ".config/op": SecretLogins, ".local/share/kwalletd": SecretLogins,
		".config/opera": SecretBrowsers, ".var/app/com.microsoft.Edge": SecretBrowsers, "snap/chromium/common/chromium": SecretBrowsers,
	} {
		if got := BuiltInDenyReadFamily(rel); got != want {
			t.Errorf("BuiltInDenyReadFamily(%s) = %q, want %q", rel, got, want)
		}
	}
	if got := BuiltInDenyReadFamily(".config/not-a-row"); got != "" {
		t.Errorf("a path that is not a row has family %q", got)
	}
}
