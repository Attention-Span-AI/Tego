// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// PersonalFile is where the personal scope lives, relative to the home directory.
const PersonalFile = ".maze/personal.yaml"

// builtInHome mirrors builtInDenyRead in pkg/spec/agent/compile_fs.go: the credential paths, relative
// to the home directory, that the engine refuses to let an agent read with no rule written. Keep the
// two in step; this copy exists only to tell the user, before anything runs, which of them are on
// this machine. TestBuiltInHomeMirrorsTheEngine reads the engine's list from its source and fails when they differ.
var builtInHome = []string{
	".ssh", ".aws", ".netrc", ".gnupg",
	".npmrc", ".git-credentials", ".config/gh", ".docker/config.json", ".kube/config", ".config/gcloud",
	".claude/.credentials.json", ".claude.json", ".claude/backups", ".codex/auth.json",
	".gemini/oauth_creds.json", ".gemini/.env", ".gemini/mcp-oauth-tokens.json",
	".copilot/config.json", ".copilot/mcp-oauth-config", ".copilot/mcp-secrets",
	".azure", ".config/op", ".password-store", ".pypirc", ".cargo/credentials", ".cargo/credentials.toml",
	".terraform.d/credentials.tfrc.json", ".vault-token", ".pgpass",
	".mozilla/firefox", ".config/google-chrome", ".config/chromium",
	".config/BraveSoftware", ".config/microsoft-edge", ".config/vivaldi", ".config/opera",
	".config/google-chrome-beta", ".config/google-chrome-unstable", ".config/microsoft-edge-beta", ".config/microsoft-edge-dev",
	"snap/firefox/common/.mozilla", "snap/chromium/common/chromium",
	".var/app/org.mozilla.firefox", ".var/app/org.chromium.Chromium", ".var/app/com.google.Chrome",
	".var/app/com.brave.Browser", ".var/app/com.microsoft.Edge", ".var/app/com.vivaldi.Vivaldi",
}

// extraHome are credential files, relative to the home directory, that the engine's built-in list doesn't
// cover: Maze suggests blocking them.
var extraHome = []string{".config/hub", ".terraformrc"}

// Finding is one file or folder a scan reports, with the reason it was reported.
type Finding struct {
	// Path is how the user sees it: ~/rel under the home directory, relative inside a workspace.
	Path string `json:"path"`
	// Why says in plain words why it was reported.
	Why string `json:"why"`
	// BuiltIn reports whether the engine already blocks reading it with no rule written.
	BuiltIn bool `json:"built_in"`
}

// EnvName is one environment variable the personal scan reports, by name only.
type EnvName struct {
	// Name is the variable's name. Its value is never read.
	Name string `json:"name"`
	// Why says which part of the name made it look like a secret.
	Why string `json:"why"`
	// NeededBy names the agent that authenticates with it, when one does; such a variable is passed
	// to that agent, not stripped.
	NeededBy string `json:"needed_by,omitempty"`
}

// Personal is what an agent running as this user could reach from anywhere: the proposal for the
// personal scope.
type Personal struct {
	// SetUp reports whether ~/.maze/personal.yaml already exists.
	SetUp bool `json:"set_up"`
	// Files are the credential files and folders present under the home directory.
	Files []Finding `json:"files"`
	// Env are the variables whose names look like secrets.
	Env []EnvName `json:"env"`
	// Startup are the shell startup files present, with the secret-looking variables each one sets.
	Startup []StartupFile `json:"startup"`
}

// StartupFile is a shell startup file: code in it runs each time the person opens a terminal, outside any
// agent run, so an agent that could change it could act later with the person's full access. Under Maze an
// agent writes only inside its project, so these stay unchanged; what init reports is whether the file also
// holds secrets an agent could read (reads are allowed by default, and the engine's built-in list doesn't
// name these files).
type StartupFile struct {
	// Path is ~/rel.
	Path string `json:"path"`
	// Secrets are the secret-looking variable names the file sets. Values are never kept.
	Secrets []string `json:"secrets,omitempty"`
}

// startupFiles are the shell startup files, relative to the home directory, of bash, zsh, sh and fish.
var startupFiles = []string{
	".bashrc", ".bash_profile", ".bash_login", ".profile",
	".zshrc", ".zprofile", ".zshenv", ".zlogin",
	".config/fish/config.fish",
}

// PersonalSetUp reports whether ~/.maze/personal.yaml exists: the one thing init checks in the home folder
// before the person allows it to look around.
func PersonalSetUp(e Env) (bool, error) {
	ok, err := exists(filepath.Join(e.Home, PersonalFile))
	if err != nil {
		return false, fmt.Errorf("look for ~/%s: %w", PersonalFile, err)
	}
	return ok, nil
}

// scanStartup reports the startup files present under home and the secret-looking names each one sets.
func scanStartup(home string) ([]StartupFile, error) {
	var out []StartupFile
	for _, rel := range startupFiles {
		abs := filepath.Join(home, filepath.FromSlash(rel))
		ok, err := exists(abs)
		if err != nil {
			return nil, fmt.Errorf("look for ~/%s: %w", rel, err)
		}
		if !ok {
			continue
		}
		names, err := exportedSecretNames(abs)
		if err != nil {
			return nil, fmt.Errorf("read the names in ~/%s: %w", rel, err)
		}
		out = append(out, StartupFile{Path: homeRel(home, abs), Secrets: names})
	}
	return out, nil
}

// exportedSecretNames returns the secret-looking variable names a shell startup file sets: NAME=…,
// export NAME=…, and fish's set -x / set -gx / set -Ux NAME. Each line is cut at the name; no value is kept.
// A link or anything but a regular file is skipped.
func exportedSecretNames(path string) ([]string, error) {
	data, err := readRegular(path)
	if errors.Is(err, errNotRegular) || errors.Is(err, fs.ErrNotExist) || errors.Is(err, ErrOnlyInCloud) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var name string
		if f := strings.Fields(line); len(f) >= 3 && f[0] == "set" && strings.HasPrefix(f[1], "-") && strings.ContainsAny(f[1], "x") {
			name = f[2]
		} else {
			line = strings.TrimPrefix(line, "export ")
			n, _, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			name = strings.TrimSpace(n)
		}
		if !validEnvName(name) {
			continue
		}
		if _, ok := secretName(name); ok {
			seen[name] = true
		}
	}
	var names []string
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// ScanPersonal reports which built-in credential paths exist under e.Home and which variables in
// e.Environ have secret-looking names. agents are the agents found, so their own keys are marked
// as needed.
func ScanPersonal(e Env, agents []Agent) (Personal, error) {
	var p Personal
	setUp, err := exists(filepath.Join(e.Home, PersonalFile))
	if err != nil {
		return Personal{}, fmt.Errorf("look for ~/%s: %w", PersonalFile, err)
	}
	p.SetUp = setUp
	for _, rel := range builtInHome {
		abs := filepath.Join(e.Home, filepath.FromSlash(rel))
		ok, err := exists(abs)
		if err != nil {
			return Personal{}, fmt.Errorf("look for %s: %w", homeRel(e.Home, abs), err)
		}
		if ok {
			p.Files = append(p.Files, Finding{
				Path:    homeRel(e.Home, abs),
				Why:     "credential location the engine always protects",
				BuiltIn: true,
			})
		}
	}
	// Credential files the engine doesn't block on its own: suggested as rules the person can switch.
	for _, rel := range extraHome {
		abs := filepath.Join(e.Home, filepath.FromSlash(rel))
		if ok, err := exists(abs); err == nil && ok {
			p.Files = append(p.Files, Finding{Path: homeRel(e.Home, abs), Why: "may hold a publish token"})
		}
	}
	needed := map[string]string{}
	for _, a := range agents {
		for _, k := range agentKeys[a.Name] {
			needed[k] = a.Name
		}
	}
	for _, name := range e.names() {
		why, ok := secretName(name)
		if !ok {
			continue
		}
		p.Env = append(p.Env, EnvName{Name: name, Why: why, NeededBy: needed[name]})
	}
	sort.Slice(p.Env, func(i, j int) bool { return p.Env[i].Name < p.Env[j].Name })
	startup, err := scanStartup(e.Home)
	if err != nil {
		return Personal{}, err
	}
	p.Startup = startup
	return p, nil
}

// secretWords are name parts that mark a variable as holding a secret. Matching is on whole parts
// split at '_', so TOKENIZERS_PARALLELISM is not a token and PASSWORD_FILE is.
var secretWords = map[string]bool{
	"SECRET": true, "SECRETS": true, "TOKEN": true, "TOKENS": true, "PASSWORD": true, "PASSWD": true,
	"CREDENTIAL": true, "CREDENTIALS": true, "DSN": true, "APIKEY": true,
}

// secretURLs are whole names of connection strings that usually carry a password.
var secretURLs = map[string]bool{
	"DATABASE_URL": true, "DB_URL": true, "REDIS_URL": true, "MONGODB_URI": true, "MONGO_URL": true,
	"AMQP_URL": true, "RABBITMQ_URL": true, "POSTGRES_URL": true, "MYSQL_URL": true,
}

// secretName reports whether a variable's name looks like a secret, and why. It sees only the name.
func secretName(name string) (string, bool) {
	upper := strings.ToUpper(name)
	if secretURLs[upper] {
		return "connection string, usually holds a password", true
	}
	parts := strings.Split(upper, "_")
	for _, part := range parts {
		if secretWords[part] {
			return "name contains " + part, true
		}
	}
	if len(parts) > 1 && parts[len(parts)-1] == "KEY" {
		return "name ends in _KEY", true
	}
	for _, pair := range []string{"API_KEY", "ACCESS_KEY", "PRIVATE_KEY", "SIGNING_KEY"} {
		if strings.Contains(upper, pair) {
			return "name contains " + pair, true
		}
	}
	return "", false
}

// KeyFolder returns the built-in credential path (as ~/rel) that abs is, or lies inside, and ok; the engine
// blocks reading all of it with no rule written.
func KeyFolder(home, abs string) (string, bool) {
	if home == "" {
		return "", false
	}
	// Compared without letter case: macOS's file system ignores it, so ~/.SSH is ~/.ssh.
	abs = strings.ToLower(filepath.Clean(abs))
	for _, rel := range builtInHome {
		p := strings.ToLower(filepath.Join(home, filepath.FromSlash(rel)))
		if abs == p || strings.HasPrefix(abs, p+string(filepath.Separator)) {
			return "~/" + rel, true
		}
	}
	return "", false
}

// IsEnvFile reports whether a file name is one the engine always blocks as an environment file (.env,
// .env.local, …, but not .env.example and its kind).
func IsEnvFile(name string) bool { return isEnvFile(name) }
