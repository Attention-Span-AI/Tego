// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIntegrationHeldReadIdentityAtLandlock(t *testing.T) {
	f := newFixture(t, contractFor("iheldidentity", []string{"/bin/sh"}, []string{"/bin/sh"}))
	bin := tegoBinary(t)
	heldIdentityScene(t, f, "landlock", func() *exec.Cmd {
		cmd := exec.Command(bin, "run", filepath.Join(f.dir, "agent.yaml"))
		cmd.Dir, cmd.Env = f.dir, isolatedEnv(t, f)
		return cmd
	})
}

// Python stays in-process across the outside replacement, so a refusal of its
// loader cannot accidentally make the replacement test pass.
func heldIdentityScene(t *testing.T, f *fixture, tier string, command func() *exec.Cmd) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	for _, how := range []string{"rename", "hardlink", "replace-rename", "replace-hardlink"} {
		t.Run(how, func(t *testing.T) {
			out := filepath.Join(f.out, tier+"-"+how)
			if err := os.MkdirAll(out, 0o755); err != nil {
				t.Fatal(err)
			}
			secret := filepath.Join(out, "secret")
			if err := os.WriteFile(secret, []byte(heldReadsSecret), 0o644); err != nil {
				t.Fatal(err)
			}
			program := fmt.Sprintf(`import errno, os, time
p = %q

def put(name, value):
    fd = os.open(p + '/' + name, os.O_WRONLY | os.O_CREAT, 0o644)
    os.write(fd, value.encode())
    os.close(fd)

put('ready', 'ready')
while not os.path.exists(p + '/go'):
    time.sleep(.01)
try:
    if %q.endswith('hardlink'):
        os.link(p + '/secret', p + '/alias')
    else:
        os.rename(p + '/secret', p + '/alias')
except OSError as e:
    if e.errno not in (errno.EACCES, errno.EPERM, errno.EXDEV):
        raise
    put('result', 'mutation-refused')
else:
    try:
        data = open(p + '/alias').read()
    except OSError as e:
        if e.errno != errno.EACCES:
            raise
        put('result', 'read-refused')
    else:
        put('result', data)
`, out, how)
			py := filepath.Join(f.dir, "identity.py")
			if err := os.WriteFile(py, []byte(program), 0o644); err != nil {
				t.Fatal(err)
			}
			contract := strings.Replace(contractFor("iheldidentity", []string{python, py}, []string{python}), "tier: landlock\n", "tier: "+tier+"\n", 1)
			contract = strings.Replace(contract, "  write: [\"./out/\"]\n", "  write: [\"./out/\"]\n  reads: held\n  deny_read: [\""+secret+"\"]\n", 1)
			if err := os.WriteFile(filepath.Join(f.dir, "agent.yaml"), []byte(contract), 0o644); err != nil {
				t.Fatal(err)
			}
			agentOwnsTree(t, out)
			agentOwns(t, py)
			cmd := command()
			log, err := os.Create(filepath.Join(t.TempDir(), "launcher.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()
			cmd.Stdout, cmd.Stderr = log, log
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			t.Cleanup(func() { _ = cmd.Process.Kill() })
			for deadline := time.Now().Add(45 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				if _, err := os.Stat(filepath.Join(out, "ready")); err == nil {
					break
				}
				select {
				case err := <-done:
					t.Fatalf("agent ended before ready: %v\n%s", err, output(cmd))
				default:
				}
				if time.Now().After(deadline) {
					t.Fatalf("agent did not start\n%s", output(cmd))
				}
			}
			if strings.HasPrefix(how, "replace-") {
				fresh := filepath.Join(out, "fresh")
				if err := os.WriteFile(fresh, []byte(heldReadsSecret), 0o644); err != nil {
					t.Fatal(err)
				}
				agentOwns(t, fresh)
				if err := os.Rename(fresh, secret); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(out, "go"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("agent failed: %v\n%s", err, output(cmd))
				}
			case <-time.After(45 * time.Second):
				t.Fatalf("agent did not finish\n%s", output(cmd))
			}
			result, err := os.ReadFile(filepath.Join(out, "result"))
			if err != nil || (string(result) != "mutation-refused" && string(result) != "read-refused") {
				t.Fatalf("identity bypass: result %q, error %v\n%s", result, err, output(cmd))
			}
		})
	}
}
