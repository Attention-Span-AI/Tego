// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestCompileTestUnixLandsAsTheRunGolden: a net.connect or net.send row to a unix pathname is decided as the run decides
// the connect or the datagram (supervisor.md R11, R11a; SEMANTICS §5 as amended 2026-10-16): on the name it passes,
// then on the socket that name reaches through the kernel's walk, with the walk compile --test lands every row's path
// with, refused when either refuses and named by the second. compile answered the name alone, so a datagram and a
// connect through a symlink in the write entry to a socket outside every entry (rows 01, 02, 06), and a name whose
// ".." after a symlink climbs out of it (07), read allow while the run refused them, EACCES with rule unmatched; a
// relative name, which the run joins to the agent's cwd, read
// refused (05).
//
// Spec: docs/p0/limits-check-doctor-cli.md R28.
func TestCompileTestUnixLandsAsTheRunGolden(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("the contract names sh, not on PATH")
	}
	golden, err := filepath.Abs(filepath.Join("testdata", "compile-test-unix-landed.golden"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(golden)
	if err != nil && !*updateGolden {
		t.Fatal(err)
	}
	dir := sunPathDir(t, "ul", len("/run/d.sock")) // the declared entry's socket name must fit sun_path
	contract := fmt.Sprintf(`version: 0
name: unix-landed
command: ["sh", "agent.sh"]
fs:
  write: ["./out/"]
net:
  allow: ["127.0.0.1:8080", "unix:%[1]s/run/d.sock"]
record: summary
`, dir)
	table := fmt.Sprintf(`version: 0
tests:
  - {name: "01 a datagram through a symlink in the write entry to a socket outside every entry", action: net.send, path: "unix:%[1]s/out/lk/s.sock", expect: refused, rule: unmatched}
  - {name: "02 a connect through it", action: net.connect, path: "unix:%[1]s/out/lk/s.sock", expect: refused, rule: unmatched}
  - {name: "03 a datagram through a symlink outside every entry into the write entry", action: net.send, path: "unix:%[1]s/elsewhere/back/s.sock", expect: refused, rule: unmatched}
  - {name: "04 a connect through a symlink in the write entry to the declared socket", action: net.connect, path: "unix:%[1]s/out/to-run/d.sock", expect: allow, rule: "net[unix:%[1]s/run/d.sock]"}
  - {name: "05 a datagram to a relative name in the write entry", action: net.send, path: "unix:out/own.sock", expect: allow, rule: "fs.write[./out/]"}
  - {name: "06 a relative connect through the symlink", action: net.connect, path: "unix:out/lk/s.sock", expect: refused, rule: unmatched}
  - {name: "07 a datagram whose .. after a symlink climbs out of the write entry", action: net.send, path: "unix:%[1]s/out/lk/../s2.sock", expect: refused, rule: unmatched}
  - {name: "08 control, a datagram to a socket in the write entry", action: net.send, path: "unix:%[1]s/out/s.sock", expect: allow, rule: "fs.write[./out/]"}
  - {name: "09 control, a connect to the socket outside every entry", action: net.connect, path: "unix:%[1]s/elsewhere/s.sock", expect: refused, rule: unmatched}
  - {name: "10 control, a connect to the declared socket", action: net.connect, path: "unix:%[1]s/run/d.sock", expect: allow, rule: "net[unix:%[1]s/run/d.sock]"}
`, dir)
	for name, body := range map[string]string{"agent.yaml": contract, "verdicts.yaml": table, "out/keep": "x", "elsewhere/keep": "x",
		"run/keep": "x"} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"out/lk": "../elsewhere", "elsewhere/back": "../out", "out/to-run": "../run"} {
		if err := os.Symlink(target, filepath.Join(dir, filepath.FromSlash(link))); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM)
	code, out, errs := run(t, "compile", "--offline", "agent.yaml", "--test", "verdicts.yaml", "--tier", "landlock,cgroup,bpflsm")
	if code != identity.ExitOK {
		t.Fatalf("exit %d, want %d\nstdout %s\nstderr %s", code, identity.ExitOK, out, errs)
	}
	out = strings.ReplaceAll(out, dir+"/", "<dir>/")
	if *updateGolden {
		if err := os.WriteFile(golden, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if out != string(want) {
		t.Errorf("output drifted from the golden file:\ngot:\n%s\nwant:\n%s", out, want)
	}
}
