// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/presets"
)

// presetProject makes a project directory with a src/ folder, changes into it and returns it with its symlinks
// resolved, as init composes for it (a TMPDIR may run through a link).
func presetProject(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	if err := os.Mkdir("src", 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestInitPresetCombinationsCompileClean: tego init --preset writes an agent.yaml for each of the seven non-empty
// preset combinations that compiles with no error and no warning, and a second init changes nothing.
func TestInitPresetCombinationsCompileClean(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	fixedEnviron(t) // a no-warning compile must not see the caller's secret-looking variables (secret-env)
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup)
	all := presets.List()
	for mask := 1; mask < 1<<len(all); mask++ {
		var names []string
		for i, p := range all {
			if mask&(1<<i) != 0 {
				names = append(names, p.Name)
			}
		}
		list := strings.Join(names, ",")
		t.Run(list, func(t *testing.T) {
			dir := presetProject(t)
			code, out, errs := run(t, "init", "--preset", list, "--write", "src", "--allow-host", "127.0.0.1:8080", dir)
			if code != identity.ExitOK || errs != "" {
				t.Fatalf("init: exit %d\n%s\n%s", code, out, errs)
			}
			if !strings.Contains(out, "created agent.yaml (name: ") || !strings.Contains(out, "presets: "+list) {
				t.Errorf("init printed:\n%s", out)
			}
			code, _, errs = run(t, "compile", "agent.yaml", "--offline")
			if code != identity.ExitOK || errs != "" {
				t.Fatalf("compile: exit %d\n%s", code, errs)
			}
			code, out, _ = run(t, "init", "--preset", list, "--write", "src", dir)
			if code != identity.ExitOK || !strings.Contains(out, "already initialized") || !strings.Contains(out, "--preset flags were not applied") {
				t.Errorf("second init: exit %d\n%s", code, out)
			}
		})
	}
}

// TestInitPresetRefusesWhatItPromises: the agent.yaml init writes for the three presets refuses a write outside the
// named folders and a host it does not name, allows the named ones, and holds the project's .env out of reach of a
// read (compile --test against the compiled table, every tier a run can get).
func TestInitPresetRefusesWhatItPromises(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	fixedEnviron(t) // a no-warning compile must not see the caller's secret-looking variables (secret-env)
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup)
	dir := presetProject(t)
	if err := os.WriteFile(".env", []byte("TOKEN=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "init", "--preset", "no-secrets,no-prod,repo-only-writes", "--write", "src/", "--allow-host", "127.0.0.1:8080", "--command", "true", dir)
	if code != identity.ExitOK {
		t.Fatalf("init: exit %d\n%s\n%s", code, out, errs)
	}
	table := `version: 0
tests:
  - name: a write inside the named folder
    action: fs.write
    path: src/main.go
    expect: allow
  - name: a write outside the named folders
    action: fs.write
    path: README.md
    expect: refused
    rule: unmatched
  - name: a write in another folder of the project
    action: fs.write
    path: docs/notes.md
    expect: refused
  - name: the named host
    action: net.connect
    host_port: 127.0.0.1:8080
    expect: allow
  - name: a host not named
    action: net.connect
    host_port: 10.20.30.40:443
    expect: refused
  - name: the named host on another port
    action: net.connect
    host_port: 127.0.0.1:5432
    expect: refused
  - name: the local docker daemon socket, always refused
    action: net.connect
    path: unix:/run/docker.sock
    expect: refused
`
	if err := os.WriteFile(filepath.Join(dir, "rows.yaml"), []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errs = run(t, "compile", "agent.yaml", "--offline", "--test", "rows.yaml")
	if code != identity.ExitOK {
		t.Fatalf("compile --test: exit %d\n%s\n%s", code, out, errs)
	}
	code, js, _ := run(t, "compile", "agent.yaml", "--offline", "--json")
	if code != identity.ExitOK || !strings.Contains(js, filepath.Join(dir, ".env")) || !strings.Contains(js, `"deny_read"`) {
		t.Errorf("the project's .env is not in deny_read:\n%s", js)
	}
}

// TestInitPresetUsageErrors: an unknown preset lists the known ones; repo-only-writes with no folder names --write;
// --write without --preset is refused; nothing is written by any of them.
func TestInitPresetUsageErrors(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--preset", "no-secret"}, "the presets are no-secrets, no-prod, repo-only-writes"},
		{[]string{"--preset", "repo-only-writes"}, "--write"},
		{[]string{"--write", "src"}, "add --preset"},
		{[]string{"--preset", "no-prod", "--allow-host", "@nope"}, "the groups are"},
	} {
		dir := presetProject(t)
		code, _, errs := run(t, append(append([]string{"init"}, tc.args...), dir)...)
		if code != identity.ExitUsage || !strings.Contains(errs, tc.want) {
			t.Errorf("%v: exit %d\n%s", tc.args, code, errs)
		}
		if _, err := os.Stat(filepath.Join(dir, "agent.yaml")); err == nil {
			t.Errorf("%v: agent.yaml was written", tc.args)
		}
	}
}

// TestInitPresetForceAndList: --force replaces a starter with a preset contract; --list prints every preset with
// its revision and the host groups.
func TestInitPresetForceAndList(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	dir := presetProject(t)
	if code, _, errs := run(t, "init", dir); code != identity.ExitOK {
		t.Fatalf("plain init: %d %s", code, errs)
	}
	plain, _ := os.ReadFile(filepath.Join(dir, "agent.yaml"))
	if strings.Contains(string(plain), "extends:") {
		t.Fatalf("plain init wrote presets:\n%s", plain)
	}
	if code, out, errs := run(t, "init", "--force", "--preset", "no-prod", "--allow-host", "@npm", dir); code != identity.ExitOK {
		t.Fatalf("--force: %d %s %s", code, out, errs)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "agent.yaml"))
	if !strings.Contains(string(got), "extends: [tego/no-prod]") || !strings.Contains(string(got), `"registry.npmjs.org:443"`) || !strings.Contains(string(got), `# --allow-host @npm`) {
		t.Errorf("--force wrote:\n%s", got)
	}
	code, out, _ := run(t, "init", "--list")
	for _, want := range []string{"no-secrets", "tego/no-prod@1", "repo-only-writes", "@github", "@maven-central", "always on"} {
		if code != identity.ExitOK || !strings.Contains(out, want) {
			t.Errorf("--list lacks %q:\n%s", want, out)
		}
	}
}

// TestInitPresetInAProjectReachedThroughALink: a project directory named through a symbolic link (a cd through a
// linked folder) is set up in the folder the link leads to: init resolves it before making the contract's folders,
// which are made beneath it with no link followed.
func TestInitPresetInAProjectReachedThroughALink(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	real := presetProject(t)
	link := filepath.Join(t.TempDir(), "linked-project")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "init", "--preset", "repo-only-writes", "--write", "src/new", link)
	if code != identity.ExitOK {
		t.Fatalf("init: exit %d\n%s\n%s", code, out, errs)
	}
	for _, d := range []string{"src/new", ".tego/tmp"} {
		if fi, err := os.Lstat(filepath.Join(real, filepath.FromSlash(d))); err != nil || !fi.IsDir() || !strings.Contains(out, "created "+d+"/") {
			t.Errorf("%s/ not made in %s: %v\n%s", d, real, err, out)
		}
	}
	if _, err := os.Stat(filepath.Join(real, "agent.yaml")); err != nil {
		t.Errorf("agent.yaml not written: %v", err)
	}
}

// TestInitPresetWriteSpelledThroughTheProjectsLink: in a project reached through a link, a --write spelled through
// that link (absolute, as a shell's $PWD spells it) is inside the project, as typed relative: a missing one is made
// there and written ./newdir/. Composed for the resolved folder, init refused it as a missing folder outside the
// project (exit 2).
func TestInitPresetWriteSpelledThroughTheProjectsLink(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	real := presetProject(t)
	link := filepath.Join(t.TempDir(), "linked-project")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "init", "--preset", "repo-only-writes", "--write", filepath.Join(link, "newdir"), link)
	if code != identity.ExitOK || !strings.Contains(out, "created newdir/") {
		t.Fatalf("init: exit %d\n%s\n%s", code, out, errs)
	}
	if fi, err := os.Lstat(filepath.Join(real, "newdir")); err != nil || !fi.IsDir() {
		t.Errorf("newdir/ not made in %s: %v", real, err)
	}
	if b, err := os.ReadFile(filepath.Join(real, "agent.yaml")); err != nil || !strings.Contains(string(b), `- "./newdir/"`) {
		t.Errorf("agent.yaml does not write ./newdir/ (%v):\n%s", err, b)
	}
}

// TestInitPresetRefusesALinkWhereItMakesAFolder: a symbolic link in the project where init must make a folder (a
// .tego linked out of the project, as an agent that may write the project could leave it) is refused with a message
// naming it: no folder is made where it leads and no agent.yaml is written.
func TestInitPresetRefusesALinkWhereItMakesAFolder(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	dir := presetProject(t)
	outside := t.TempDir()
	link := filepath.Join(dir, ".tego")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "init", "--preset", "repo-only-writes", "--write", "src", dir)
	if code != identity.ExitError || !strings.Contains(errs, link+" is a symbolic link") || !strings.Contains(errs, "remove the link") {
		t.Fatalf("init: exit %d\n%s\n%s", code, out, errs)
	}
	if es, _ := os.ReadDir(outside); len(es) > 0 {
		t.Errorf("init made a folder where the link leads: %v", es)
	}
	if _, err := os.Lstat(filepath.Join(dir, "agent.yaml")); err == nil {
		t.Error("agent.yaml was written")
	}
}

// TestInitPresetThatDoesNotCompileWritesNothing: a --command not on PATH makes a contract that does not compile;
// init prints compile's diagnostic at agent.yaml, exits 1 as compile would, and writes no agent.yaml.
func TestInitPresetThatDoesNotCompileWritesNothing(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	dir := presetProject(t)
	code, _, errs := run(t, "init", "--preset", "repo-only-writes", "--write", "src", "--command", "tego-no-such-agent-binary", dir)
	if code != identity.ExitFinding || !strings.Contains(errs, "[exec-not-on-path]") || !strings.Contains(errs, filepath.Join(dir, "agent.yaml")) || strings.Contains(errs, ".agent.yaml.") {
		t.Errorf("exit %d\n%s", code, errs)
	}
	if _, err := os.Stat(filepath.Join(dir, "agent.yaml")); err == nil {
		t.Error("agent.yaml was written")
	}
	if _, err := os.Stat(filepath.Join(dir, ".tego", "tmp")); err == nil {
		t.Error(".tego/tmp/ was created for a contract that was not written")
	}
	if _, err := os.Stat(filepath.Join(dir, ".tego")); err == nil {
		t.Error(".tego/ was created despite the promise that nothing was written")
	}
}
