// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseScript(t *testing.T) {
	good := `{"prompt":"p","turns":[{"calls":[{"write":"a.txt","content":"x"}]},{"parallel":true,"calls":[{"read":"a.txt"},{"run":["echo","hi"]},{"bash":"true"},{"connect":"127.0.0.1:80"}]}]}`
	s, err := ParseScript([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Turns) != 2 || !s.Turns[1].Parallel || s.Turns[1].Calls[3].ToolName() != "Connect" || s.Turns[1].Calls[1].ToolName() != "Bash" {
		t.Errorf("%+v", s)
	}
	for name, tc := range map[string]struct{ in, want string }{
		"unknown key":   {`{"turns":[],"extra":1}`, "unknown field"},
		"no verb":       {`{"turns":[{"calls":[{"content":"x"}]}]}`, "exactly one"},
		"two verbs":     {`{"turns":[{"calls":[{"read":"a","bash":"b"}]}]}`, "exactly one"},
		"empty turn":    {`{"turns":[{"calls":[]}]}`, "no calls"},
		"bad connect":   {`{"turns":[{"calls":[{"connect":"nohost"}]}]}`, "host:port"},
		"port range":    {`{"turns":[{"calls":[{"connect":"h:70000"}]}]}`, "1-65535"},
		"content stray": {`{"turns":[{"calls":[{"read":"a","content":"x"}]}]}`, "belong to write"},
		"trailing data": {`{} {}`, "after the top-level"},
	} {
		if _, err := ParseScript([]byte(tc.in)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestWriteIsATemporaryFileRenamedOverTheTarget(t *testing.T) {
	dir := t.TempDir()
	r := Call{Write: "sub/note.txt", Content: "hello\n"}.Execute(dir, os.Environ())
	if r.Err != "" || r.Name != "Write" {
		t.Fatalf("%+v", r)
	}
	target := filepath.Join(dir, "sub", "note.txt")
	if b, _ := os.ReadFile(target); string(b) != "hello\n" {
		t.Errorf("content %q", b)
	}
	if ents, _ := os.ReadDir(filepath.Join(dir, "sub")); len(ents) != 1 {
		t.Errorf("a temporary file was left: %v", ents)
	}
	if got := r.Input["file_path"]; got != target {
		t.Errorf("file_path %v is not the absolute path %s", got, target)
	}
	if resp := r.Response.(map[string]any); resp["type"] != "create" || resp["filePath"] != target {
		t.Errorf("response %v", resp)
	}
	r = Call{Write: target, Content: "again", Inplace: true}.Execute(dir, os.Environ())
	if r.Err != "" || r.Response.(map[string]any)["type"] != "update" {
		t.Errorf("second write: %+v", r)
	}
}

func TestFailuresAreReportedLikeNode(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "plain")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	notExec := filepath.Join(dir, "notexec")
	if err := os.WriteFile(notExec, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	ln.Close()
	for name, tc := range map[string]struct {
		call Call
		want string
	}{
		"write under a file": {Call{Write: filepath.Join(file, "x"), Content: "y"}, "ENOTDIR: not a directory, mkdir"},
		"read missing":       {Call{Read: filepath.Join(dir, "none")}, "ENOENT: no such file or directory, open '" + filepath.Join(dir, "none") + "'"},
		"exit status":        {Call{Run: []string{"sh", "-c", "echo out; echo err >&2; exit 3"}}, "Exit code 3\nout\nerr"},
		"not found":          {Call{Run: []string{"fakeclaude-no-such-command"}}, "Exit code 127"},
		"not executable":     {Call{Run: []string{notExec}}, "Exit code 126"},
		"bash failure":       {Call{Bash: "echo hi; false"}, "Exit code 1\nhi"},
		"connect refused":    {Call{Connect: closed}, "ECONNREFUSED: connection refused, connect '" + closed + "'"},
		"timeout":            {Call{Bash: "sleep 30", TimeoutMS: 200}, "timed out"},
	} {
		r := tc.call.Execute(dir, os.Environ())
		if !strings.Contains(r.Err, tc.want) {
			t.Errorf("%s: error %q, want %q", name, r.Err, tc.want)
		}
	}
}

func TestSuccessfulToolsReport(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("one\ntwo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := Call{Read: "f.txt"}.Execute(dir, os.Environ())
	file := r.Response.(map[string]any)["file"].(map[string]any)
	if r.Text != "1\tone\n2\ttwo\n" || file["numLines"] != 2 || file["content"] != "one\ntwo\n" {
		t.Errorf("read: %+v", r)
	}
	r = Call{Run: []string{"printf", "%s", "a b"}, Description: "d"}.Execute(dir, os.Environ())
	if r.Err != "" || r.Input["command"] != "printf %s 'a b'" || r.Response.(map[string]any)["stdout"] != "a b" || r.Input["description"] != "d" {
		t.Errorf("run: %+v", r)
	}
	r = Call{Bash: "pwd"}.Execute(dir, os.Environ())
	if got, _ := filepath.EvalSymlinks(strings.TrimSpace(r.Text)); got != mustEval(t, dir) {
		t.Errorf("bash cwd %q", r.Text)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	r = Call{Connect: ln.Addr().String()}.Execute(dir, os.Environ())
	if r.Err != "" || r.Name != "Connect" || r.Response.(map[string]any)["connected"] != true {
		t.Errorf("connect: %+v", r)
	}
}

// A command that exits 0 and leaves a background child holding its output is a success, with the output it wrote.
func TestCommandThatLeavesAChildHoldingItsOutputSucceeds(t *testing.T) {
	old := toolWaitDelay
	toolWaitDelay = 150 * time.Millisecond
	defer func() { toolWaitDelay = old }()
	r := Call{Bash: "echo hi; sleep 2 &"}.Execute(t.TempDir(), os.Environ())
	if r.Err != "" || r.Text != "hi\n" {
		t.Errorf("%+v", r)
	}
}

// Claude Code 2.1.310's Write, as measured (RESULTS.md R3): the temporary file is <name>.tmp.<pid>.<12 hex digits>,
// made through an O_PATH descriptor of the directory, and a failed one is removed at once; the error names the real
// directory, and the success text is the real binary's.
func TestWriteIsClaudeCodes2_1_310(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	dir := t.TempDir()
	r := Call{Write: "note.txt", Content: "x"}.Execute(dir, os.Environ())
	want := "File created successfully at: " + filepath.Join(dir, "note.txt") + " (file state is current in your context — no need to Read it back)"
	if r.Err != "" || r.Text != want {
		t.Errorf("write: %+v, want text %q", r, want)
	}
	ro := filepath.Join(dir, "ro")
	if err := os.Mkdir(ro, 0o555); err != nil {
		t.Fatal(err)
	}
	r = Call{Write: filepath.Join(ro, "leak.txt"), Content: "x"}.Execute(dir, os.Environ())
	tmp := regexp.MustCompile(`^EACCES: permission denied, open '` + regexp.QuoteMeta(ro) + `/leak\.txt\.tmp\.` + strconv.Itoa(os.Getpid()) + `\.[0-9a-f]{12}'$`)
	if !tmp.MatchString(r.Err) {
		t.Fatalf("a refused write: error %q, want %s", r.Err, tmp)
	}
	if ents, _ := os.ReadDir(ro); len(ents) != 0 {
		t.Errorf("the read-only directory holds %v", ents)
	}
}

// Claude Code's Bash runs the command with /bin/bash and shows its output and error in the order they were written.
func TestBashIsBinBashWithOneStream(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("no /bin/bash")
	}
	r := Call{Bash: `echo "$0"; echo err >&2; sleep 0.05; echo out`}.Execute(t.TempDir(), os.Environ())
	if r.Err != "" || r.Text != "/bin/bash\nerr\nout\n" {
		t.Errorf("bash: %+v", r)
	}
	if resp := r.Response.(map[string]any); resp["stdout"] != r.Text || resp["stderr"] != "" {
		t.Errorf("bash response %v", resp)
	}
}

func mustEval(t *testing.T, p string) string {
	t.Helper()
	q, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return q
}
