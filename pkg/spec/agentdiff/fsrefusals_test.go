// SPDX-License-Identifier: Apache-2.0

package agentdiff

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func deny(path string, ask bool) agent.FSRule {
	return agent.FSRule{Kind: agent.FSDenyRead, Path: path, Resolved: path, AskRead: ask}
}

func tableWith(fs ...agent.FSRule) *agent.RuleTable {
	t := table()
	t.FS = fs
	return t
}

func writeGrant(path string) agent.FSRule {
	return agent.FSRule{Kind: agent.FSWrite, Path: path, Resolved: path, Access: agent.AccessWriteSet}
}

func TestReadRefusalsAreOrderedByStrictness(t *testing.T) {
	for _, tc := range []struct {
		name    string
		a, b    []agent.FSRule
		want    Direction
		allowed string
	}{
		{"a refusal added", nil, []agent.FSRule{deny("/p/secret", false)}, Narrowed, ""},
		{"a question added", nil, []agent.FSRule{deny("/p/docs", true)}, Narrowed, ""},
		{"a question made a refusal", []agent.FSRule{deny("/p/docs", true)}, []agent.FSRule{deny("/p/docs", false)}, Narrowed, ""},
		{"a refusal made a question", []agent.FSRule{deny("/p/docs", false)}, []agent.FSRule{deny("/p/docs", true)}, Widened, "Read /p/docs after asking (it was refused)"},
		{"a refusal removed", []agent.FSRule{deny("/p/secret", false)}, nil, Widened, "Read /p/secret (it was refused)"},
		{"a question removed", []agent.FSRule{deny("/p/docs", true)}, nil, Widened, "Read /p/docs without asking"},
		{"one added and one removed", []agent.FSRule{deny("/p/a", false)}, []agent.FSRule{deny("/p/b", false)}, Widened, "Read /p/a (it was refused)"},
		{"unchanged", []agent.FSRule{deny("/p/a", false)}, []agent.FSRule{deny("/p/a", false)}, Unchanged, ""},
		// A question that goes beneath a folder that is now refused loses nothing: the refusal covers it.
		{"a nested question under a new refusal", []agent.FSRule{deny("/p/b", true), deny("/p/b/x", true)}, []agent.FSRule{deny("/p/b", false)}, Narrowed, ""},
		{"a nested question under a new question", []agent.FSRule{deny("/p/b", true), deny("/p/b/x", true)}, []agent.FSRule{deny("/p/b", true)}, Unchanged, ""},
		{"a nested refusal under a new question", []agent.FSRule{deny("/p/b", true), deny("/p/b/x", false)}, []agent.FSRule{deny("/p/b", true)}, Widened, "Read /p/b/x (it was refused)"},
		{"a nested question under a refusal that stays", []agent.FSRule{deny("/p/b", false), deny("/p/b/x", true)}, []agent.FSRule{deny("/p/b", false)}, Unchanged, ""},
		// A grant between the refusal and the question: the question was what held the folder, and it goes.
		{"a question that goes under a nearer grant", []agent.FSRule{deny("/p/b", false), writeGrant("/p/b/w"), deny("/p/b/w/x", true)}, []agent.FSRule{deny("/p/b", false), writeGrant("/p/b/w")}, Widened, "Read /p/b/w/x without asking"},
		// A question beneath a refusal would reopen it: not ordered.
		{"a question under a refusal", []agent.FSRule{deny("/p", false)}, []agent.FSRule{deny("/p", false), deny("/p/docs", true)}, CannotClassify, ""},
		// A grant at the same place: which entry decides is not ordered here.
		{"a refusal at a grant", []agent.FSRule{writeGrant("/p/out")}, []agent.FSRule{writeGrant("/p/out"), deny("/p/out", false)}, CannotClassify, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := rowResult(t, "filesystem", tableWith(tc.a...), tableWith(tc.b...))
			if r.Direction != tc.want {
				t.Fatalf("got %+v, want %s", r, tc.want)
			}
			if tc.allowed != "" && !strings.Contains(strings.Join(r.NewlyAllowed, "|"), tc.allowed) {
				t.Fatalf("missing %q in %+v", tc.allowed, r)
			}
		})
	}
}

func TestRefusalAttributeChangeCannotBeOrdered(t *testing.T) {
	a, b := tableWith(deny("/p/a", false)), tableWith(deny("/p/a", false))
	b.FS[0].Device = 7
	if r := rowResult(t, "filesystem", a, b); r.Direction != CannotClassify {
		t.Fatalf("a changed refusal row: %+v", r)
	}
}

func TestProtectionRowsAreOrdered(t *testing.T) {
	row := func(p string) agent.FSRule {
		return agent.FSRule{Kind: agent.FSDenyWrite, Path: p, Resolved: p, Unenforced: true}
	}
	for _, tc := range []struct {
		name string
		set  func(t *agent.RuleTable, on bool)
	}{
		{"deny_write", func(t *agent.RuleTable, on bool) {
			if on {
				t.DenyWrite = []agent.FSRule{row("/p/out/sub")}
			}
		}},
		{"approval scope protection", func(t *agent.RuleTable, on bool) {
			if on {
				t.AskDenyWrite = []agent.FSRule{row("/p/ask/.git")}
			}
		}},
		{"refusal inside a write entry", func(t *agent.RuleTable, on bool) {
			if on {
				t.Reads.Nested = []agent.NestedRead{{Rule: "fs.deny_read[./out/key]", Path: "/p/out/key", Resolved: "/p/out/key"}}
			}
		}},
		{"deny_read pattern", func(t *agent.RuleTable, on bool) {
			if on {
				t.DenyReadPatterns = []agent.DenyReadPattern{{Pattern: "/p/*.pem", Rule: "fs.deny_read[./*.pem]"}}
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := table(), table()
			tc.set(a, false)
			tc.set(b, true)
			if r := rowResult(t, "filesystem protection", a, b); r.Direction != Narrowed {
				t.Fatalf("added: %+v", r)
			}
			r := rowResult(t, "filesystem protection", b, a)
			if r.Direction != Widened || len(r.NewlyAllowed) != 1 || !strings.Contains(r.NewlyAllowed[0], "it was refused") && !strings.Contains(r.NewlyAllowed[0], "they were refused") {
				t.Fatalf("removed: %+v", r)
			}
			if r := rowResult(t, "filesystem protection", b, b); r.Direction != Unchanged {
				t.Fatalf("equal: %+v", r)
			}
		})
	}
}

// The protection fields no ordering reads stay visible when they change.
func TestProtectionFieldsWithoutAnOrderingNeedReview(t *testing.T) {
	for _, field := range []string{"DenyWriteLinked", "NameDeny", "NameExempt", "NameLeftOut", "OwnState", "OwnReadable", "AbsentDenyRead", "AskReadRelaxes"} {
		t.Run(field, func(t *testing.T) {
			a, b := table(), table()
			changeValue(t, fieldValue(b, field))
			if r := rowResult(t, "filesystem protection", a, b); r.Direction != CannotClassify {
				t.Fatalf("silent changed field %s: %+v", field, r)
			}
		})
	}
}

// The held-read record's other parts (mode, name rules, aliases) have no ordering: a change shows.
func TestHeldReadsOtherPartsNeedReview(t *testing.T) {
	a, b := table(), table()
	b.Reads.Mode = "direct"
	if r := rowResult(t, "filesystem protection", a, b); r.Direction != CannotClassify {
		t.Fatalf("held-read mode: %+v", r)
	}
	b = table()
	b.Reads.Aliases = []agent.NameAlias{{Alias: "/x", Original: "/y"}}
	if r := rowResult(t, "filesystem protection", a, b); r.Direction != CannotClassify {
		t.Fatalf("held-read aliases: %+v", r)
	}
}
