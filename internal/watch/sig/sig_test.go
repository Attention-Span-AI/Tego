// SPDX-License-Identifier: Apache-2.0

package sig

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestDefaultNamesTheFourAgents(t *testing.T) {
	names := map[string]bool{}
	for _, r := range Default() {
		if err := r.Validate(); err != nil {
			t.Errorf("shipped rule %s does not validate: %v", r, err)
		}
		names[r.Name] = true
	}
	for _, want := range []string{"claude", "codex", "opencode", "gemini"} {
		if !names[want] {
			t.Errorf("the shipped list has no rule named %s", want)
		}
		delete(names, want)
	}
	if len(names) != 0 {
		t.Errorf("the shipped list names more than claude, codex, opencode and gemini: %v", names)
	}
}

// The shipped list against what each agent's real install looks like from /proc.
func TestDefaultMatches(t *testing.T) {
	for _, tc := range []struct {
		name  string
		facts Facts
		want  string // rule name, "" for no match
	}{
		{"claude native, run by its link", Facts{Exe: "/home/u/.local/share/claude/versions/2.1.290", Argv: []string{"claude"}, Comm: "claude"}, "claude"},
		{"claude native, run by the version file", Facts{Exe: "/home/u/.local/share/claude/versions/2.1.290", Argv: []string{"/home/u/.local/share/claude/versions/2.1.290"}, Comm: "2.1.290"}, ""},
		{"claude on node", Facts{Exe: "/usr/bin/node", Argv: []string{"node", "--no-warnings", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js", "--resume"}, Comm: "node"}, "claude"},
		{"codex native", Facts{Exe: "/opt/codex/vendor/codex", Argv: []string{"/opt/codex/vendor/codex", "exec"}, Comm: "codex"}, "codex"},
		{"codex on node", Facts{Exe: "/usr/bin/node", Argv: []string{"node", "/usr/lib/node_modules/@openai/codex/bin/codex.js"}, Comm: "node"}, "codex"},
		{"opencode", Facts{Exe: "/home/u/.opencode/bin/opencode", Argv: []string{"opencode"}, Comm: "opencode"}, "opencode"},
		{"gemini on node, by its bin link", Facts{Exe: "/usr/bin/node", Argv: []string{"node", "/usr/bin/gemini"}, Comm: "node"}, "gemini"},
		{"gemini on node, by its package", Facts{Exe: "/usr/bin/node", Argv: []string{"node", "/usr/lib/node_modules/@google/gemini-cli/dist/index.js"}, Comm: "node"}, "gemini"},
		{"node running something else", Facts{Exe: "/usr/bin/node", Argv: []string{"node", "/srv/app/server.js"}, Comm: "node"}, ""},
		{"a shell", Facts{Exe: "/usr/bin/bash", Argv: []string{"-bash"}, Comm: "bash"}, ""},
		{"grep for the name", Facts{Exe: "/usr/bin/grep", Argv: []string{"grep", "claude", "notes.txt"}, Comm: "grep"}, ""},
		{"an editor with the name as a file", Facts{Exe: "/usr/bin/vim", Argv: []string{"vim", "claude"}, Comm: "vim"}, ""},
		{"a name that only contains one", Facts{Exe: "/usr/bin/claude-flow", Argv: []string{"claude-flow"}, Comm: "claude-flow"}, ""},
		{"nothing read", Facts{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, ok := Default().Match(tc.facts)
			if ok != (tc.want != "") || r.Name != tc.want {
				t.Fatalf("Match = (%q, %v), want %q", r.Name, ok, tc.want)
			}
		})
	}
}

func TestRuleMatch(t *testing.T) {
	node := func(args ...string) Facts {
		return Facts{Exe: "/usr/bin/node", Argv: append([]string{"node"}, args...), Comm: "node"}
	}
	for _, tc := range []struct {
		name  string
		rule  Rule
		facts Facts
		want  bool
	}{
		{"basename is the exe", Rule{Name: "a", Basename: "agent"}, Facts{Exe: "/x/agent"}, true},
		{"basename is argv0", Rule{Name: "a", Basename: "agent"}, Facts{Exe: "/x/1.2.3", Argv: []string{"agent", "-x"}}, true},
		{"basename is argv0 by path", Rule{Name: "a", Basename: "agent"}, Facts{Exe: "/x/1.2.3", Argv: []string{"/opt/agent"}}, true},
		{"basename is comm", Rule{Name: "a", Basename: "agent"}, Facts{Exe: "/x/1.2.3", Argv: []string{"x"}, Comm: "agent"}, true},
		{"a long basename is never a comm", Rule{Name: "a", Basename: "averyverylongagentname"}, Facts{Exe: "/x/y", Argv: []string{"y"}, Comm: "averyverylongage"}, false},
		{"basename is exact, not a prefix", Rule{Name: "a", Basename: "agent"}, Facts{Exe: "/x/agent2", Argv: []string{"agent2"}, Comm: "agent2"}, false},
		{"basename is case-sensitive", Rule{Name: "a", Basename: "agent"}, Facts{Exe: "/x/Agent"}, false},
		{"basename on an argument is not a match", Rule{Name: "a", Basename: "agent"}, Facts{Exe: "/bin/sh", Argv: []string{"sh", "agent"}, Comm: "sh"}, false},
		{"path exact", Rule{Name: "a", Path: "/opt/a/agent"}, Facts{Exe: "/opt/a/agent"}, true},
		{"path in another directory", Rule{Name: "a", Path: "/opt/a/agent"}, Facts{Exe: "/opt/b/agent"}, false},
		{"path with no exe read", Rule{Name: "a", Path: "/opt/a/agent"}, Facts{Argv: []string{"/opt/a/agent"}}, false},
		{"file identity", Rule{Name: "a", File: FileID{Dev: 259, Ino: 77}}, Facts{Exe: "/anything", File: FileID{Dev: 259, Ino: 77}}, true},
		{"file identity on another device", Rule{Name: "a", File: FileID{Dev: 259, Ino: 77}}, Facts{File: FileID{Dev: 8, Ino: 77}}, false},
		{"file identity unknown", Rule{Name: "a", File: FileID{Dev: 259, Ino: 77}}, Facts{Exe: "/anything"}, false},
		{"argv: program and script", Rule{Name: "a", Argv: []string{"node", ".../cli.js"}}, node("/a/b/cli.js"), true},
		{"argv: flags between are skipped", Rule{Name: "a", Argv: []string{"node", ".../cli.js"}}, node("--max-old-space-size=4096", "/a/b/cli.js", "--flag"), true},
		{"argv: a relative script", Rule{Name: "a", Argv: []string{"node", ".../cli.js"}}, node("cli.js"), true},
		{"argv: the directory part is matched by component", Rule{Name: "a", Argv: []string{"node", ".../x/cli.js"}}, node("/a/ax/cli.js"), false},
		{"argv: two components", Rule{Name: "a", Argv: []string{"node", ".../x/cli.js"}}, node("/a/x/cli.js"), true},
		{"argv: shorter than the tail", Rule{Name: "a", Argv: []string{"node", ".../x/cli.js"}}, node("cli.js"), false},
		{"argv: another script", Rule{Name: "a", Argv: []string{"node", ".../cli.js"}}, node("/a/b/server.js"), false},
		{"argv: no script", Rule{Name: "a", Argv: []string{"node", ".../cli.js"}}, node(), false},
		{"argv: wrong program", Rule{Name: "a", Argv: []string{"node", ".../cli.js"}}, Facts{Exe: "/usr/bin/python3", Argv: []string{"python3", "/a/cli.js"}}, false},
		{"argv: the program may be argv0 alone", Rule{Name: "a", Argv: []string{"node", ".../cli.js"}}, Facts{Exe: "/opt/n/bin/node20", Argv: []string{"node", "/a/cli.js"}}, true},
		{"argv: the program may be the exe alone", Rule{Name: "a", Argv: []string{"node", ".../cli.js"}}, Facts{Exe: "/usr/bin/node", Argv: []string{"nodejs", "/a/cli.js"}}, true},
		{"argv: the script is not argv0", Rule{Name: "a", Argv: []string{"node", ".../cli.js"}}, Facts{Exe: "/usr/bin/node", Argv: []string{"/a/cli.js"}}, false},
		{"argv: program glob", Rule{Name: "a", Argv: []string{"node*", ".../cli.js"}}, Facts{Exe: "/usr/bin/nodejs", Argv: []string{"nodejs", "/a/cli.js"}}, true},
		{"argv: program by path", Rule{Name: "a", Argv: []string{"/usr/bin/node", ".../cli.js"}}, node("/a/cli.js"), true},
		{"argv: program by another path", Rule{Name: "a", Argv: []string{"/opt/bin/node", ".../cli.js"}}, node("/a/cli.js"), false},
		{"argv: three tokens in order", Rule{Name: "a", Argv: []string{"node", ".../cli.js", "serve"}}, node("/a/cli.js", "--x", "serve"), true},
		{"argv: three tokens out of order", Rule{Name: "a", Argv: []string{"node", ".../cli.js", "serve"}}, node("serve", "/a/cli.js"), false},
		{"argv: no argv read", Rule{Name: "a", Argv: []string{"node", ".../cli.js"}}, Facts{Exe: "/usr/bin/node"}, false},
		{"argv: a single token is the program alone", Rule{Name: "a", Argv: []string{"agent-*"}}, Facts{Exe: "/x/agent-7", Argv: []string{"agent-7"}}, true},
		{"the zero rule matches nothing", Rule{}, Facts{Exe: "/x/y", Argv: []string{"y"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rule.Match(tc.facts); got != tc.want {
				t.Fatalf("Match = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		spec string
		want Rule
		err  string
	}{
		{"claude", Rule{Name: "claude", Basename: "claude"}, ""},
		{"  claude  ", Rule{Name: "claude", Basename: "claude"}, ""},
		{"cc=claude", Rule{Name: "cc", Basename: "claude"}, ""},
		{"/opt/agents/bin/My_Agent", Rule{Name: "my_agent", Path: "/opt/agents/bin/My_Agent"}, ""},
		{"web=node .../web/cli.js", Rule{Name: "web", Argv: []string{"node", ".../web/cli.js"}}, ""},
		{"pin=file:259:1048577", Rule{Name: "pin", File: FileID{Dev: 259, Ino: 1048577}}, ""},
		{"nodes=node*", Rule{Name: "nodes", Argv: []string{"node*"}}, ""},
		{"Claude.Code", Rule{Name: "claude-code", Basename: "Claude.Code"}, ""},
		{"", Rule{}, "empty"},
		{"   ", Rule{}, "empty"},
		{"node .../cli.js", Rule{}, "needs a name"},
		{"file:259:12", Rule{}, "needs a name"},
		{"x=file:259", Rule{}, "file:<device>:<inode>"},
		{"x=file:a:b", Rule{}, "file:<device>:<inode>"},
		{"x=file:1:0", Rule{}, "inode"},
		{"node*", Rule{}, "needs a name"},
		{"bin/claude", Rule{}, "absolute"},
		{"/opt/../bin/claude", Rule{}, "clean"},
		{"/opt//bin/claude", Rule{}, "clean"},
		{"web=node .../[", Rule{}, "syntax error"},
		{"9lives=claude", Rule{}, ""}, // not a name, so the whole text is a basename that holds an '='
	} {
		t.Run(tc.spec, func(t *testing.T) {
			got, err := Parse(tc.spec)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("Parse(%q) error = %v, want one containing %q", tc.spec, err, tc.err)
				}
				return
			}
			if tc.spec == "9lives=claude" {
				if err != nil || got.Basename != "9lives=claude" {
					t.Fatalf("Parse(%q) = %+v, %v", tc.spec, got, err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Parse(%q) = %+v, %v; want %+v", tc.spec, got, err, tc.want)
			}
		})
	}
}

func TestParseRemoval(t *testing.T) {
	r, err := Parse("gemini=")
	if !errors.Is(err, ErrRemove) || r.Name != "gemini" {
		t.Fatalf("Parse(\"gemini=\") = %+v, %v; want ErrRemove for gemini", r, err)
	}
}

// What String writes, Parse reads back.
func TestStringRoundTrips(t *testing.T) {
	rules := append(Default(),
		Rule{Name: "p", Path: "/opt/a/agent"},
		Rule{Name: "f", File: FileID{Dev: 1, Ino: 2}},
	)
	for _, r := range rules {
		got, err := Parse(r.String())
		if err != nil || !reflect.DeepEqual(got, r) {
			t.Errorf("Parse(%q) = %+v, %v; want %+v", r.String(), got, err, r)
		}
	}
}

func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule Rule
		ok   bool
	}{
		{"basename", Rule{Name: "a", Basename: "x"}, true},
		{"no matcher", Rule{Name: "a"}, false},
		{"two matchers", Rule{Name: "a", Basename: "x", Path: "/x"}, false},
		{"bad name", Rule{Name: "A", Basename: "x"}, false},
		{"no name", Rule{Basename: "x"}, false},
		{"basename with a slash", Rule{Name: "a", Basename: "x/y"}, false},
		{"empty argv token", Rule{Name: "a", Argv: []string{"node", ""}}, false},
		{"bad glob", Rule{Name: "a", Argv: []string{"node", "["}}, false},
	} {
		if err := tc.rule.Validate(); (err == nil) != tc.ok {
			t.Errorf("%s: Validate = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

func TestMerge(t *testing.T) {
	names := func(l List) []string {
		var out []string
		for _, r := range l {
			out = append(out, r.String())
		}
		return out
	}
	base := List{
		{Name: "claude", Basename: "claude"},
		{Name: "claude", Argv: []string{"node", ".../cli.js"}},
		{Name: "gemini", Basename: "gemini"},
	}
	orig := names(base)
	for _, tc := range []struct {
		name  string
		specs []string
		want  []string
	}{
		{"none", nil, []string{"claude=claude", "claude=node .../cli.js", "gemini=gemini"}},
		{"add", []string{"mine"}, []string{"claude=claude", "claude=node .../cli.js", "gemini=gemini", "mine=mine"}},
		{"replace every rule of a name", []string{"claude=/opt/claude"}, []string{"gemini=gemini", "claude=/opt/claude"}},
		{"two of one name replace once", []string{"claude=/opt/a", "claude=/opt/b"}, []string{"gemini=gemini", "claude=/opt/a", "claude=/opt/b"}},
		{"remove", []string{"claude="}, []string{"gemini=gemini"}},
		{"remove then add", []string{"gemini=", "gemini=/opt/g"}, []string{"claude=claude", "claude=node .../cli.js", "gemini=/opt/g"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Merge(base, tc.specs)
			if err != nil || !reflect.DeepEqual(names(got), tc.want) {
				t.Fatalf("Merge = %v, %v; want %v", names(got), err, tc.want)
			}
			if !reflect.DeepEqual(names(base), orig) {
				t.Fatalf("Merge changed its base list: %v", names(base))
			}
		})
	}
	if _, err := Merge(base, []string{"fine", "node .../x"}); err == nil {
		t.Fatal("Merge accepted an argv pattern with no name")
	}
}

func FuzzParseAndMatch(f *testing.F) {
	for _, s := range []string{"claude", "a=node .../x", "file:1:2", "x=", "/p/q"} {
		f.Add(s, "/usr/bin/node", "node\x00x")
	}
	f.Fuzz(func(t *testing.T, spec, exe, argv string) {
		r, err := Parse(spec)
		if err != nil {
			return
		}
		_ = r.Match(Facts{Exe: exe, Argv: strings.Split(argv, "\x00")})
		if _, err := Parse(r.String()); err != nil {
			t.Fatalf("Parse(%q).String() = %q does not parse: %v", spec, r.String(), err)
		}
	})
}
