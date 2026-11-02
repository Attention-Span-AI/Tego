// SPDX-License-Identifier: Apache-2.0

package shellword

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// quoteCases are words and the one word each is written as: a plain one as it is, any other in single quotes, with each
// ' and \ in it written outside them.
var quoteCases = []struct{ in, want string }{
	{"curl", "curl"},
	{"/usr/bin/curl", "/usr/bin/curl"},
	{"example.com:443", "example.com:443"},
	{"r-aaaaaaaa-0000000000006-askedx", "r-aaaaaaaa-0000000000006-askedx"},
	{"user@host,a+b=c_d.e", "user@host,a+b=c_d.e"},
	{"--for", "--for"},
	{"", "''"},
	{"/tmp/my dir/", "'/tmp/my dir/'"},
	{" fix it ", "' fix it '"}, // nothing is trimmed: a restart line's argument keeps its spaces
	{"it's", `'it'\''s'`},
	{"'", `''\'''`},
	{"''", `''\'''\'''`},
	{`say "hi"`, `'say "hi"'`},
	{"/tmp/$HOME", "'/tmp/$HOME'"},
	{"a`id`b", "'a`id`b'"},
	{"$(id)", "'$(id)'"},
	{"/tmp/a;rm -rf /x", "'/tmp/a;rm -rf /x'"},
	{"a&&b|c>d<e", "'a&&b|c>d<e'"},
	{"line\nbreak", "'line\nbreak'"},
	{"tab\there", "'tab\there'"},
	{`back\slash`, `'back'\\'slash'`},
	{`\`, `''\\''`},
	{`\\`, `''\\''\\''`},
	{`/tmp/x\'; id #`, `'/tmp/x'\\''\''; id #'`}, // in fish, \' and \\ inside single quotes are escapes
	{"~/.ssh", "'~/.ssh'"},
	{"*.txt", "'*.txt'"},
	{"[::1]:80", "'[::1]:80'"},
	{"{a,b}", "'{a,b}'"},
	{"!x", "'!x'"},
	{"#x", "'#x'"},
	{"50%", "'50%'"},
	{"%self", "'%self'"}, // fish expands %self to its pid
	{"=curl", "'=curl'"}, // zsh expands =curl to curl's path
	{"=", "'='"},
	{"a=b", "a=b"},
	{"café", "'café'"},
	{"a\u202eb", "'a\u202eb'"},
	{"\xff", "'\xff'"},
}

func TestQuote(t *testing.T) {
	for _, c := range quoteCases {
		if got := Quote(c.in); got != c.want {
			t.Errorf("Quote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// shells are the shells a pasted line may meet, each with the flags that keep the startup files of the person running
// the test out of it.
var shells = []struct {
	name string
	args []string
}{
	{"sh", nil},
	{"dash", nil},
	{"bash", []string{"--norc", "--noprofile"}},
	{"zsh", []string{"-f"}},
	{"fish", []string{"--no-config"}},
	{"busybox", []string{"sh"}},
}

// TestQuoteInShells: every quoted word, on one command line given to sh and to each of dash, bash, zsh, fish and
// busybox sh the machine has, reaches the program as the word it was, byte for byte. Each runs with a home of its own.
func TestQuoteInShells(t *testing.T) {
	words := make([]string, len(quoteCases))
	for i, c := range quoteCases {
		words[i] = Quote(c.in)
	}
	script := `printf '%s\0' ` + strings.Join(words, " ")
	home := t.TempDir()
	env := append(os.Environ(), "HOME="+home, "ZDOTDIR="+home, "XDG_CONFIG_HOME="+home, "XDG_DATA_HOME="+home, "XDG_CACHE_HOME="+home,
		"BASH_ENV=", "ENV=")
	var ran []string
	for _, sh := range shells {
		path, err := exec.LookPath(sh.name)
		if err != nil {
			if sh.name == "sh" {
				t.Fatalf("no sh: %v", err)
			}
			continue
		}
		cmd := exec.Command(path, append(sh.args, "-c", script)...)
		cmd.Env = env
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: %v", sh.name, err)
		}
		got := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
		if len(got) != len(quoteCases) {
			t.Fatalf("%s read %d words, want %d: %q", sh.name, len(got), len(quoteCases), got)
		}
		for i, c := range quoteCases {
			if got[i] != c.in {
				t.Errorf("%s read %s as %q, want %q", sh.name, words[i], got[i], c.in)
			}
		}
		ran = append(ran, sh.name)
	}
	t.Logf("read by %s", strings.Join(ran, ", "))
}
