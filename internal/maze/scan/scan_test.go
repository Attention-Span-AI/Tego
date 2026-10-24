// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// write creates path under root with mode, making its folders.
func write(t *testing.T, root, rel string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x\n"), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSecretName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"AWS_SECRET_ACCESS_KEY", true},
		{"AWS_ACCESS_KEY_ID", true},
		{"GITHUB_TOKEN", true},
		{"DATABASE_URL", true},
		{"SENTRY_DSN", true},
		{"POSTGRES_PASSWORD", true},
		{"STRIPE_API_KEY", true},
		{"ANTHROPIC_API_KEY", true},
		{"MY_SIGNING_KEY", true},
		{"PATH", false},
		{"HOME", false},
		{"TOKENIZERS_PARALLELISM", false},
		{"SSH_AUTH_SOCK", false},
		{"KEYCHAIN_PATH", false},
		{"VITE_APP_API_BASE_URL", false},
		{"PWD", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, got := secretName(tt.name); got != tt.want {
				t.Errorf("secretName(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestIsEnvFile(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{".env", true},
		{".env.local", true},
		{".env.development", true},
		{".env.example", false},
		{".env.sample", false},
		{".env.template", false},
		{".env.dist", false},
		{"env", false},
		{".envrc", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isEnvFile(tt.name); got != tt.want {
				t.Errorf("isEnvFile(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestLookPath(t *testing.T) {
	bin := t.TempDir()
	exe := write(t, bin, "tool", 0o755)
	write(t, bin, "plain", 0o644)
	other := t.TempDir()
	tests := []struct {
		name, path, look, want string
	}{
		{"found", bin, "tool", exe},
		{"not executable", bin, "plain", ""},
		{"missing", bin, "nope", ""},
		{"later entry", other + string(os.PathListSeparator) + bin, "tool", exe},
		{"empty entry is not the current folder", "" + string(os.PathListSeparator) + other, "tool", ""},
		{"relative entry skipped", "relative/dir", "tool", ""},
		{"name with a separator", bin, "a/tool", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (Env{Path: tt.path}).LookPath(tt.look); got != tt.want {
				t.Errorf("LookPath(%q) = %q, want %q", tt.look, got, tt.want)
			}
		})
	}
}

// tempDir is t.TempDir with its links resolved (macOS's /var is one), as FindWorkspace answers.
func tempDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestFindWorkspaceThroughALink: a project reached through a link is its real folder, read in full: the walk does
// not enter a link at its root, so the link's path read nothing and found no secret.
func TestFindWorkspaceThroughALink(t *testing.T) {
	real := filepath.Join(tempDir(t), "app")
	write(t, real, ".env", 0o600)
	write(t, real, "sub/id_rsa", 0o600)
	if err := os.Mkdir(filepath.Join(real, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tempDir(t), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	ws, err := FindWorkspace(link)
	if err != nil {
		t.Fatal(err)
	}
	if ws.Root != real || ws.Started != real {
		t.Errorf("root %s, started %s, want %s", ws.Root, ws.Started, real)
	}
	got, err := ScanRepo(context.Background(), ws, Env{})
	if err != nil {
		t.Fatal(err)
	}
	var secrets []string
	for _, f := range got.Secrets {
		secrets = append(secrets, f.Path)
	}
	if len(secrets) < 2 {
		t.Errorf("secrets through a link: %v, want .env and sub/id_rsa", secrets)
	}
}

// TestFindWorkspaceRefusesAControlCharacter: a root whose path holds a newline would end a line of the contract.
func TestFindWorkspaceRefusesAControlCharacter(t *testing.T) {
	bad := filepath.Join(tempDir(t), "app\nfs:")
	if err := os.MkdirAll(filepath.Join(bad, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := FindWorkspace(bad); err == nil {
		t.Error("a root with a newline in its path was accepted")
	}
}

func TestFindWorkspace(t *testing.T) {
	repo := filepath.Join(tempDir(t), "My Repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(repo, "backend", "app")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	plain := tempDir(t)
	setUp := tempDir(t)
	write(t, setUp, WorkspaceFile, 0o644)
	// A project set up without git, run from a folder inside it.
	setUpSub := filepath.Join(setUp, "src")
	if err := os.MkdirAll(setUpSub, 0o755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		dir  string
		want Workspace
	}{
		{"repo root", repo, Workspace{Root: repo, Name: "My Repo", ID: "my-repo", Git: true}},
		{"from a subfolder", sub, Workspace{Root: repo, Name: "My Repo", ID: "my-repo", Git: true}},
		{"no git", plain, Workspace{Root: plain, Name: filepath.Base(plain), ID: workspaceName(plain)}},
		{"already set up", setUp, Workspace{Root: setUp, Name: filepath.Base(setUp), ID: workspaceName(setUp), SetUp: true}},
		{"set up, from a subfolder", setUpSub, Workspace{Root: setUp, Name: filepath.Base(setUp), ID: workspaceName(setUp), SetUp: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FindWorkspace(tt.dir)
			if err != nil {
				t.Fatal(err)
			}
			got.Started = ""
			if got != tt.want {
				t.Errorf("FindWorkspace(%s) = %+v, want %+v", tt.dir, got, tt.want)
			}
		})
	}
	if _, err := FindWorkspace(filepath.Join(plain, "missing")); err == nil {
		t.Error("FindWorkspace on a missing folder: no error")
	}
}

func TestScanPersonal(t *testing.T) {
	home := t.TempDir()
	write(t, home, ".aws/credentials", 0o600)
	write(t, home, ".config/gh/hosts.yml", 0o600)
	env := Env{
		Home:    home,
		Environ: []string{"PATH=/bin", "GITHUB_TOKEN=ghp_value_never_read", "ANTHROPIC_API_KEY=sk-x", "EMPTY_SECRET="},
	}
	got, err := ScanPersonal(env, []Agent{{Name: "claude", Path: "/x/claude"}})
	if err != nil {
		t.Fatal(err)
	}
	if got.SetUp {
		t.Error("SetUp = true with no personal file")
	}
	wantFiles := []string{"~/.aws", "~/.config/gh"}
	var files []string
	for _, f := range got.Files {
		if !f.BuiltIn {
			t.Errorf("%s: BuiltIn = false, want true", f.Path)
		}
		files = append(files, f.Path)
	}
	if !reflect.DeepEqual(files, wantFiles) {
		t.Errorf("files = %v, want %v", files, wantFiles)
	}
	wantEnv := []EnvName{
		{Name: "ANTHROPIC_API_KEY", Why: "name ends in _KEY", NeededBy: "claude"},
		{Name: "EMPTY_SECRET", Why: "name contains SECRET"},
		{Name: "GITHUB_TOKEN", Why: "name contains TOKEN"},
	}
	if !reflect.DeepEqual(got.Env, wantEnv) {
		t.Errorf("env = %+v, want %+v", got.Env, wantEnv)
	}

	write(t, home, PersonalFile, 0o644)
	again, err := ScanPersonal(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !again.SetUp {
		t.Error("SetUp = false with ~/.maze/personal.yaml present")
	}
	if again.Env[0].NeededBy != "" {
		t.Error("ANTHROPIC_API_KEY marked needed with no agent found")
	}
}

func TestScanRepo(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{
		".env", ".env.development", ".env.example",
		"frontend/package.json", "frontend/.env",
		"backend/pyproject.toml", "backend/app/certs/server.pem", "backend/app/certs/server.pub",
		"config/secrets/prod.json",
		"node_modules/pkg/.env", "node_modules/pkg/package.json",
		"deep/a/b/package.json",
		"go.mod",
	} {
		write(t, root, rel, 0o644)
	}
	bin := t.TempDir()
	for _, tool := range []string{"node", "npm", "git"} {
		write(t, bin, tool, 0o755)
	}
	ws := Workspace{Root: root, Git: true}
	got, err := ScanRepo(context.Background(), ws, Env{Path: bin})
	if err != nil {
		t.Fatal(err)
	}

	secrets := map[string]bool{}
	for _, f := range got.Secrets {
		secrets[f.Path] = f.BuiltIn
	}
	wantSecrets := map[string]bool{
		".env": true, ".env.development": true, "frontend/.env": true,
		"backend/app/certs/server.pem": false, "config/secrets/": false,
	}
	if !reflect.DeepEqual(secrets, wantSecrets) {
		t.Errorf("secrets = %v, want %v", secrets, wantSecrets)
	}

	tools := map[string]bool{}
	for _, tool := range got.Tools {
		tools[tool.Name] = tool.Path != ""
	}
	wantTools := map[string]bool{"git": true, "node": true, "npm": true, "python3": false, "pip": false, "go": false}
	if !reflect.DeepEqual(tools, wantTools) {
		t.Errorf("tools (installed?) = %v, want %v", tools, wantTools)
	}

	var hosts []string
	for _, h := range got.Hosts {
		hosts = append(hosts, h.Name)
	}
	if want := []string{"registry.npmjs.org"}; !reflect.DeepEqual(hosts, want) {
		t.Errorf("hosts = %v, want %v (only installed tools get hosts)", hosts, want)
	}
}

func TestScanRepoCancelled(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a/b.txt", 0o644)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ScanRepo(ctx, Workspace{Root: root}, Env{}); !errors.Is(err, context.Canceled) {
		t.Errorf("ScanRepo with a cancelled context: err = %v, want context.Canceled", err)
	}
}

func TestScanStartup(t *testing.T) {
	home := t.TempDir()
	writeText(t, home, ".zshrc", "# my shell\nexport OPENAI_API_KEY=sk-never-kept\nexport PATH=$PATH:/x\nalias ll='ls -l'\nGITHUB_TOKEN=ghp_x\n")
	writeText(t, home, ".bashrc", "export EDITOR=vim\n")
	writeText(t, home, ".config/fish/config.fish", "set -gx STRIPE_SECRET_KEY sk_live\nset fish_greeting\n")
	got, err := scanStartup(home)
	if err != nil {
		t.Fatal(err)
	}
	want := []StartupFile{
		{Path: "~/.bashrc"},
		{Path: "~/.zshrc", Secrets: []string{"GITHUB_TOKEN", "OPENAI_API_KEY"}},
		{Path: "~/.config/fish/config.fish", Secrets: []string{"STRIPE_SECRET_KEY"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("scanStartup =\n%+v\nwant\n%+v", got, want)
	}
}
