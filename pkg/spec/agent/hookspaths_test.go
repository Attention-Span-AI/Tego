// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// hooksPathsCases are git config files and the core.hooksPath values git reads from them. gitRefuses marks a
// file git will not parse at all: hooksPaths still reads a value from it, which only adds a directory to
// protect.
var hooksPathsCases = []struct {
	name, config string
	want         []string
	gitRefuses   bool
}{
	{"plain", "[core]\n\thooksPath = /x/h\n", []string{"/x/h"}, false},
	// A continued value kept only its first line, "/x/ev".
	{"continued", "[core]\n\thooksPath = /x/ev\\\nil\n", []string{"/x/evil"}, false},
	{"continued inside quotes", "[core]\n\thooksPath = \"/x/a \\\nb\"\n", []string{"/x/a b"}, false},
	{"continued at the end of the file", "[core]\n\thooksPath = /x/h\\\n", []string{"/x/h"}, false},
	{"continued at the end of the file, no newline", "[core]\n\thooksPath = /x/h\\", []string{"/x/h"}, false},
	// A line continued from another key's value is that value's, never an assignment of its own.
	{"continued from another key", "[core]\n\teditor = vi\\\nhooksPath = /x/evil\n", nil, false},
	{"continued from another section", "[user]\n\tname = a\\\n[core] hooksPath = /x/evil\n", nil, false},
	// A backslash in a comment continues nothing.
	{"backslash in a comment", "[core]\n\thooksPath = /x/h ; c\\\n\thooksPath = /y/h\n", []string{"/x/h", "/y/h"}, false},
	{"quoted", "[core]\n\thooksPath = \"/x/a b\"\n", []string{"/x/a b"}, false},
	{"quoted trailing space", "[core]\n\thooksPath = \"/x/h \"\n", []string{"/x/h "}, false},
	{"inner whitespace", "[core]\n\thooksPath = /x/a  b\n", []string{"/x/a  b"}, false},
	{"trailing whitespace", "[core]\n\thooksPath = /x/h \t \n", []string{"/x/h"}, false},
	// An escaped trailing tab was trimmed as if it were written whitespace.
	{"escaped trailing tab", "[core]\n\thooksPath = /x/h\\t\n", []string{"/x/h\t"}, false},
	{"escaped trailing tab then space", "[core]\n\thooksPath = /x/h\\t \n", []string{"/x/h\t"}, false},
	{"hash comment", "[core]\n\thooksPath=/x/h # c\n", []string{"/x/h"}, false},
	{"semicolon comment", "[core]\n\thooksPath = /x/h ; c\n", []string{"/x/h"}, false},
	{"quoted comment characters", "[core]\n\thooksPath = \"e;f#g\"\n", []string{"e;f#g"}, false},
	{"case", "[CoRe]\n\tHOOKSPATH = /x/h\n", []string{"/x/h"}, false},
	{"subsection", "[core \"sub\"]\n\thooksPath = /x/h\n", nil, false},
	{"dotted subsection", "[core.sub]\n\thooksPath = /x/h\n", nil, false},
	{"key on the header line", "[core]hooksPath=/x/h\n", []string{"/x/h"}, false},
	{"crlf", "[core]\r\n\thooksPath = /x/h\r\n", []string{"/x/h"}, false},
	{"crlf continued", "[core]\r\n\thooksPath = /x/ev\\\r\nil\r\n", []string{"/x/evil"}, false},
	{"quotes inside", "[core]\n\thooksPath = /x/\"h\"\n", []string{"/x/h"}, false},
	{"tilde", "[core]\n  hooksPath = ~/h\n", []string{"~/h"}, false},
	{"no value", "[core]\n\thooksPath\n", nil, false},
	{"two sections", "[core]\n\thooksPath = /x/h\n[core]\n\thooksPath = /y/h\n", []string{"/x/h", "/y/h"}, false},
	{"comment after the header", "[core] ; x\n\thooksPath = /x/h\n", []string{"/x/h"}, false},
	{"header text in a value", "[section] a = [core]\n\thooksPath = /x/h\n", nil, false},
	{"hyphenated key", "[core]\n\thooks-path = /x/h\n", nil, false},
	// A byte order mark hid the first section header.
	{"byte order mark", "\xef\xbb\xbf[core]\n\thooksPath = /x/h\n", []string{"/x/h"}, false},
	{"no expansion", "[core]\n\thooksPath = %(prefix)/x/h\n", []string{"%(prefix)/x/h"}, false},
	{"NUL", "[core]\n\thooksPath = /x/h\x00tail\n", []string{"/x/h"}, false},
	{"escapes", "[core]\n\thooksPath = g\\\\h\\\"i\n", []string{"g\\h\"i"}, false},
	{"unclosed quote", "[core]\n\thooksPath = \"/x/h\n", []string{"/x/h"}, true},
	{"spaced header", "[ core ]\n\thooksPath = /x/h\n", []string{"/x/h"}, true},
	{"unknown escape", "[core]\n\thooksPath = /x/\\q\n", []string{"/x/q"}, true},
	{"second header on the line", "[a][core]hooksPath=/evil\n", []string{"/evil"}, false},
	{"core then another header", "[core][a]hooksPath=/x/h\n", nil, false},
	{"three headers", "[core] [a \"b\"]\t[CORE]hooksPath = /x/h\n", []string{"/x/h"}, false},
}

// TestHooksPathsMatchGit pins hooksPaths against the values above and, where git is installed, against what
// `git config -f FILE --get-all core.hooksPath` reads from the same bytes.
func TestHooksPathsMatchGit(t *testing.T) {
	gitBin, gitErr := exec.LookPath("git")
	dir := t.TempDir()
	for _, tc := range hooksPathsCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hooksPaths([]byte(tc.config)); !slices.Equal(got, tc.want) {
				t.Errorf("hooksPaths(%q) = %q, want %q", tc.config, got, tc.want)
			}
			if gitErr != nil {
				t.Skip("git not installed: the comparison with git is skipped")
			}
			path := filepath.Join(dir, "config")
			if err := os.WriteFile(path, []byte(tc.config), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(gitBin, "config", "-z", "-f", path, "--get-all", "core.hooksPath")
			cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "HOME="+dir)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			var exit *exec.ExitError
			switch {
			case err == nil:
			case errors.As(err, &exit) && exit.ExitCode() == 1 && stderr.Len() == 0:
				out = nil // the key is not set
			case errors.As(err, &exit):
				if !tc.gitRefuses {
					t.Fatalf("git refused %q: %s", tc.config, stderr.String())
				}
				return
			default:
				t.Fatal(err)
			}
			if tc.gitRefuses {
				t.Fatalf("git read %q, which the table says it refuses: %q", tc.config, out)
			}
			var git []string
			for v := range strings.SplitSeq(string(out), "\x00") {
				if v != "" {
					git = append(git, v)
				}
			}
			if !slices.Equal(tc.want, git) {
				t.Errorf("git reads %q from %q; the table says %q", git, tc.config, tc.want)
			}
		})
	}
}

// FuzzHooksPaths holds hooksPaths to what compile relies on: every value is a non-empty string shorter than
// pathMax with no NUL, lastValues keeps at most maxHooksValues of them, and a byte order mark or "\r\n" line
// ends change nothing.
func FuzzHooksPaths(f *testing.F) {
	for _, tc := range hooksPathsCases {
		f.Add([]byte(tc.config))
	}
	f.Add([]byte("[core]hooksPath=\"a\\\"b\" ; c\n"))
	f.Add([]byte("[a][core]hooksPath=/evil\n"))
	f.Add([]byte("[a][b][core]\n\thooksPath=~bob/h\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		vs := hooksPaths(data)
		for _, v := range vs {
			if v == "" || len(v) >= pathMax || strings.IndexByte(v, 0) >= 0 {
				t.Fatalf("bad value %q", v)
			}
		}
		if n := len(lastValues(vs)); n > maxHooksValues {
			t.Fatalf("lastValues kept %d", n)
		}
		if !bytes.HasPrefix(data, []byte("\xef\xbb\xbf")) {
			if got := hooksPaths(append([]byte("\xef\xbb\xbf"), data...)); !slices.Equal(got, vs) {
				t.Fatalf("a byte order mark changed %q to %q", vs, got)
			}
		}
		if !bytes.Contains(data, []byte("\r")) {
			if got := hooksPaths(bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))); !slices.Equal(got, vs) {
				t.Fatalf("\\r\\n line ends changed %q to %q", vs, got)
			}
		}
	})
}
