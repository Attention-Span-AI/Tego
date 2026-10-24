// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeText(t *testing.T, root, rel, text string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAdviseEnvFiles(t *testing.T) {
	root := t.TempDir()
	// A Vite app whose .env holds only public settings: keep readable.
	writeText(t, root, "package.json", `{"devDependencies":{"vite":"^7.3.5"}}`)
	writeText(t, root, ".env", "# api\nVITE_APP_API_BASE_URL=http://localhost:5000\nexport VITE_APP_DEBUG=true\n\nnot a line\n")
	// A Vite frontend whose .env mixes in a non-public name: keep blocked.
	writeText(t, root, "frontend/package.json", `{"dependencies":{"vite":"^8"}}`)
	writeText(t, root, "frontend/.env", "VITE_API_URL=http://x\nMAILPIT_HOST=http://y\n")
	// A backend .env with no frontend tool beside it: keep blocked.
	writeText(t, root, "backend/.env", "SECRET_KEY=changethis\nPOSTGRES_PASSWORD=changethis\n")
	// A .env that is a link to somewhere else: never followed.
	writeText(t, root, "outside/creds", "VITE_X=1\n")
	if err := os.Symlink(filepath.Join(root, "outside/creds"), filepath.Join(root, "linked.env")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, "linked.env"), filepath.Join(root, "frontend", ".env.local")); err != nil {
		t.Fatal(err)
	}

	secrets := []Finding{
		{Path: ".env", BuiltIn: true},
		{Path: "frontend/.env", BuiltIn: true},
		{Path: "frontend/.env.local", BuiltIn: true},
		{Path: "backend/.env", BuiltIn: true},
		{Path: "keys/deploy.pem"},
		{Path: "config/secrets/"},
	}
	got, err := AdviseEnvFiles(root, secrets)
	if err != nil {
		t.Fatal(err)
	}
	want := []EnvAdvice{
		{Path: ".env", Keys: []string{"VITE_APP_API_BASE_URL", "VITE_APP_DEBUG"}, LoadedBy: "Vite", Prefix: "VITE_", Readable: true},
		{Path: "frontend/.env", Keys: []string{"MAILPIT_HOST", "VITE_API_URL"}, LoadedBy: "Vite", Prefix: "VITE_", NotPublic: []string{"MAILPIT_HOST"}},
		{Path: "frontend/.env.local", Keys: nil, LoadedBy: "Vite", Prefix: "VITE_"},
		{Path: "backend/.env", Keys: []string{"POSTGRES_PASSWORD", "SECRET_KEY"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AdviseEnvFiles =\n%+v\nwant\n%+v", got, want)
	}
}

func TestEnvKeyNamesNeverKeepsValues(t *testing.T) {
	root := t.TempDir()
	writeText(t, root, ".env", "A=secret-value\nB = other-secret\n1BAD=x\nC-D=y\n")
	got, err := envKeyNames(filepath.Join(root, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"A", "B"}; !reflect.DeepEqual(got, want) {
		t.Errorf("envKeyNames = %v, want %v", got, want)
	}
}

func TestFrameworkInBadJSON(t *testing.T) {
	root := t.TempDir()
	writeText(t, root, "package.json", "{not json")
	fw, err := frameworkIn(root)
	if err != nil || fw != nil {
		t.Errorf("frameworkIn on bad JSON = %v, %v; want nil, nil", fw, err)
	}
}
