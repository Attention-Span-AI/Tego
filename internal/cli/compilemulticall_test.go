// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// staticELF is an ELF64 header and one PT_LOAD program header, with no PT_INTERP: a static binary as compile reads
// one (pkg/spec/agent's elf64 with no loader).
func staticELF() []byte {
	le := binary.LittleEndian
	h := make([]byte, 64+56)
	copy(h, "\x7fELF")
	h[4], h[5], h[6] = 2, 1, 1 // ELFCLASS64, little-endian, EV_CURRENT
	le.PutUint16(h[16:], 2)    // ET_EXEC
	le.PutUint16(h[18:], 0x3e) // x86-64
	le.PutUint32(h[20:], 1)
	le.PutUint64(h[32:], 64) // e_phoff
	le.PutUint16(h[52:], 64)
	le.PutUint16(h[54:], 56)
	le.PutUint16(h[56:], 1) // e_phnum
	le.PutUint32(h[64:], 1) // PT_LOAD
	return h
}

// TestCompileExecMulticallKeepsExitAndJSON: `tego compile` of a contract whose two exec.allow entries are hard links of
// one file prints one [exec-multicall] warning on stderr and exits 0, and its --json table is byte for byte the table
// of the same contract where the two entries are separate files: the warning is the only thing that moves. A run's
// quiet start leaves the note out, and -v prints it. The files are made here, so the test holds on a GNU host too.
func TestCompileExecMulticallKeepsExitAndJSON(t *testing.T) {
	dir := t.TempDir()
	ls, cat := filepath.Join(dir, "ls"), filepath.Join(dir, "cat")
	for _, p := range []string{ls, cat} {
		if err := os.WriteFile(p, staticELF(), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	contract := "version: 0\nname: mc\ncommand: [" + ls + "]\nexec:\n  allow:\n    - " + ls + "\n    - " + cat + "\n"
	if err := os.WriteFile(filepath.Join(dir, "agent.yaml"), []byte(contract), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	t.Setenv("TEGO_CONFIG", "")
	compile := func(args ...string) (string, string) {
		t.Helper()
		code, out, errs := run(t, append([]string{"compile", "agent.yaml", "--offline"}, args...)...)
		if code != identity.ExitOK {
			t.Fatalf("exit %d, want %d\nstderr %s", code, identity.ExitOK, errs)
		}
		return out, errs
	}
	twoJSON, twoErrs := compile("--json")
	if strings.Contains(twoErrs, "[exec-multicall]") {
		t.Fatalf("two files of one link each warned:\n%s", twoErrs)
	}
	if err := os.Remove(cat); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(ls, cat); err != nil {
		t.Fatal(err)
	}
	oneJSON, oneErrs := compile("--json")
	if n := strings.Count(oneErrs, "[exec-multicall]"); n != 1 {
		t.Fatalf("one file of two links: %d [exec-multicall] lines, want 1:\n%s", n, oneErrs)
	}
	if !strings.Contains(oneErrs, `the exec entries "`+ls+`" and "`+cat+`" lead to one program file, `) {
		t.Errorf("the warning does not name both entries:\n%s", oneErrs)
	}
	if oneJSON != twoJSON {
		t.Errorf("--json moved with the warning:\ntwo files %s\none file  %s", twoJSON, oneJSON)
	}
	if strings.Replace(oneErrs, multicallLines(oneErrs), "", 1) != twoErrs {
		t.Errorf("stderr moved beyond the warning:\ntwo files\n%s\none file\n%s", twoErrs, oneErrs)
	}
	if _, text := compile(); !strings.Contains(text, "[exec-multicall]") {
		t.Errorf("tego compile's text form lacks the warning:\n%s", text)
	}

	// The run's start: the same contract's findings through the filter `tego run` prints them with.
	c, _, err := agent.LoadBytes("agent.yaml", []byte(contract), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, ds, err := agent.Compile(c, config.Builtin(), agent.Offline(), agent.WithPATH(dir))
	if err != nil {
		t.Fatalf("compile: %v %v", err, ds)
	}
	var notes int
	for _, d := range ds {
		if d.Code == agent.CodeExecMulticall {
			notes++
			if !d.Informational() {
				t.Errorf("%q is not a note", d.Message)
			}
		}
	}
	if notes != 1 {
		t.Fatalf("compile gave %d exec-multicall findings, want 1: %v", notes, ds)
	}
	for _, d := range runNotices(ds, false) {
		if d.Code == agent.CodeExecMulticall {
			t.Errorf("a quiet run start printed %q", d.Message)
		}
	}
	var kept bool
	for _, d := range runNotices(ds, true) {
		kept = kept || d.Code == agent.CodeExecMulticall
	}
	if !kept {
		t.Error("tego run -v left out the exec-multicall note")
	}
}

// multicallLines is the [exec-multicall] warning's lines in a diagnostics text: its line and its fix line.
func multicallLines(text string) string {
	lines := strings.SplitAfter(text, "\n")
	for i, l := range lines {
		if strings.HasSuffix(l, "[exec-multicall]\n") {
			out := l
			if i+1 < len(lines) && strings.HasPrefix(lines[i+1], "  fix: ") {
				out += lines[i+1]
			}
			return out
		}
	}
	return ""
}
