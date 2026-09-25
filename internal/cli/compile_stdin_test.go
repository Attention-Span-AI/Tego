// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// stdinFrom makes `compile -` read data, through a pipe as a shell would hand it over.
func stdinFrom(t *testing.T, data string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = w.WriteString(data)
		_ = w.Close()
	}()
	t.Cleanup(func() { _ = r.Close() })
	prev := contractStdin
	contractStdin = func() *os.File { return r }
	t.Cleanup(func() { contractStdin = prev })
}

// TestCompileReadsStdin: `tego compile -` reads the contract from standard input, as
// agent.LoadBytes's comment promised; it compiled a file named "-". The contract compiles to the table its file
// does, a relative entry resolves against the working directory, and a diagnostic is labelled <stdin>.
func TestCompileReadsStdin(t *testing.T) {
	minimal, err := os.ReadFile(filepath.Join("testdata", "minimal.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	code, fromFile, errs := run(t, "compile", filepath.Join("testdata", "minimal.yaml"), "--json", "--offline")
	if code != identity.ExitOK {
		t.Fatalf("file: exit %d stderr %q", code, errs)
	}
	stdinFrom(t, string(minimal))
	code, fromStdin, errs := run(t, "compile", "-", "--json", "--offline")
	if code != identity.ExitOK {
		t.Fatalf("stdin: exit %d stderr %q", code, errs)
	}
	var a, b Table
	if err := json.Unmarshal([]byte(fromFile), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(fromStdin), &b); err != nil {
		t.Fatal(err)
	}
	if a.Name != b.Name || a.ContractHash != b.ContractHash {
		t.Errorf("stdin compiled %s %s, the file %s %s", b.Name, b.ContractHash, a.Name, a.ContractHash)
	}

	t.Run("relative entries resolve against the working directory", func(t *testing.T) {
		cwd := t.TempDir()
		t.Chdir(cwd)
		stdinFrom(t, "version: 0\nname: stdin\ncommand: [\"true\"]\nfs:\n  write: [\"out/\"]\n")
		code, out, errs := run(t, "compile", "-", "--json", "--offline")
		if code != identity.ExitOK {
			t.Fatalf("exit %d stderr %q", code, errs)
		}
		var tbl Table
		if err := json.Unmarshal([]byte(out), &tbl); err != nil {
			t.Fatal(err)
		}
		want, _ := filepath.EvalSymlinks(cwd)
		found := false
		for _, e := range tbl.FS {
			if e.Kind == "write" && (e.Path == filepath.Join(cwd, "out") || e.Path == filepath.Join(want, "out")) {
				found = true
			}
		}
		if !found {
			t.Errorf("no write entry at %s: %+v", filepath.Join(cwd, "out"), tbl.FS)
		}
	})

	t.Run("a diagnostic names stdin", func(t *testing.T) {
		stdinFrom(t, "version: 0\nname: stdin\ncommand: [\"true\"]\nbogus: 1\n")
		code, _, errs := run(t, "compile", "-")
		if code != identity.ExitFinding || !strings.Contains(errs, "<stdin>:4:1: unknown field \"bogus\"") {
			t.Errorf("exit %d stderr %q", code, errs)
		}
	})

	t.Run("a terminal or device is refused, not waited on", func(t *testing.T) {
		dev, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = dev.Close() }()
		prev := contractStdin
		contractStdin = func() *os.File { return dev }
		defer func() { contractStdin = prev }()
		code, _, errs := run(t, "compile", "-")
		if code == identity.ExitOK || !strings.HasPrefix(errs, stdinLabel+":") {
			t.Errorf("exit %d stderr %q, want a message naming %s", code, errs, stdinLabel)
		}
	})

	// Node's child_process stdio 'pipe' hands the child a socketpair, not a pipe: it is read as a pipe is.
	t.Run("a socket is read", func(t *testing.T) {
		fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Skipf("socketpair: %v", err)
		}
		r, w := os.NewFile(uintptr(fds[0]), "stdin"), os.NewFile(uintptr(fds[1]), "writer")
		defer func() { _ = r.Close() }()
		go func() {
			_, _ = w.Write(minimal)
			_ = w.Close()
		}()
		prev := contractStdin
		contractStdin = func() *os.File { return r }
		defer func() { contractStdin = prev }()
		code, out, errs := run(t, "compile", "-", "--json", "--offline")
		if code != identity.ExitOK {
			t.Fatalf("exit %d stderr %q", code, errs)
		}
		var tbl Table
		if err := json.Unmarshal([]byte(out), &tbl); err != nil || tbl.ContractHash != a.ContractHash {
			t.Errorf("a socket compiled %s (%v), the file %s", tbl.ContractHash, err, a.ContractHash)
		}
	})
}
