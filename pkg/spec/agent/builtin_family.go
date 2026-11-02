// SPDX-License-Identifier: Apache-2.0

package agent

// SecretFamily is the kind of secret a row of the built-in deny_read list holds (BuiltInDenyRead), in words a person
// recognizes, for a page that groups the list: the dashboard's new policy preview says one Never reads sentence per
// family. Every row has exactly one, written in builtInDenyReadFamilies beside the list (TestBuiltInDenyReadFamilies),
// so a new row is grouped by what it holds, never by how its path is spelled.
type SecretFamily string

const (
	// SecretSSHKeys is ~/.ssh, the person's SSH keys.
	SecretSSHKeys SecretFamily = "ssh-keys"
	// SecretLogins is every other credential store: cloud, registry, git, database and agent logins, keys, keyrings
	// and password stores.
	SecretLogins SecretFamily = "logins"
	// SecretBrowsers is the browser profiles, each channel and packaging (snap, flatpak) of each browser.
	SecretBrowsers SecretFamily = "browsers"
)

// BuiltInDenyReadFamily is the family of rel, a row of BuiltInDenyRead as it returns it; "" for a path that is not a
// row.
func BuiltInDenyReadFamily(rel string) SecretFamily { return builtInDenyReadFamily[rel] }

// builtInDenyReadFamilies gives every builtInDenyRead row its family, each family's rows in the list's order. A row
// added to the list is added here too: TestBuiltInDenyReadFamilies fails until it is.
var builtInDenyReadFamilies = map[SecretFamily][]string{
	SecretSSHKeys: {".ssh"},
	SecretLogins: {
		".aws", ".netrc", ".gnupg",
		".npmrc", ".git-credentials", ".config/gh", ".docker/config.json", ".kube/config", ".config/gcloud",
		".claude/.credentials.json", ".claude.json", ".claude/backups", ".codex/auth.json",
		".gemini/oauth_creds.json", ".gemini/.env", ".gemini/mcp-oauth-tokens.json",
		".copilot/config.json", ".copilot/mcp-oauth-config", ".copilot/mcp-secrets",
		".azure", ".config/op", ".password-store", ".pypirc", ".cargo/credentials", ".cargo/credentials.toml",
		".terraform.d/credentials.tfrc.json", ".vault-token", ".pgpass",
		".local/share/keyrings", ".local/share/kwalletd", ".my.cnf", ".mylogin.cnf",
		".s3cfg", ".boto", ".config/rclone/rclone.conf", ".rclone.conf",
		".gem/credentials", ".local/share/gem/credentials", ".config/composer/auth.json", ".composer/auth.json",
		".m2/settings-security.xml", ".config/doctl/config.yaml", ".config/hub", ".config/glab-cli/config.yml",
		".fly/config.yml", ".supabase/access-token", ".oci",
	},
	SecretBrowsers: {
		".mozilla/firefox", ".config/google-chrome", ".config/chromium",
		".config/BraveSoftware", ".config/microsoft-edge", ".config/vivaldi", ".config/opera",
		".config/google-chrome-beta", ".config/google-chrome-unstable", ".config/microsoft-edge-beta", ".config/microsoft-edge-dev",
		"snap/firefox/common/.mozilla", "snap/chromium/common/chromium",
		".var/app/org.mozilla.firefox", ".var/app/org.chromium.Chromium", ".var/app/com.google.Chrome",
		".var/app/com.brave.Browser", ".var/app/com.microsoft.Edge", ".var/app/com.vivaldi.Vivaldi",
	},
}

// builtInDenyReadFamily is builtInDenyReadFamilies by row.
var builtInDenyReadFamily = func() map[string]SecretFamily {
	m := make(map[string]SecretFamily, len(builtInDenyRead))
	for f, rows := range builtInDenyReadFamilies {
		for _, rel := range rows {
			m[rel] = f
		}
	}
	return m
}()
