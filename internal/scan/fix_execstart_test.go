// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/scan/result"
)

func TestUnitSystemdDifferential(t *testing.T) {
	var oracle struct {
		SystemdVersion string `json:"systemd_version"`
		Cases          []struct {
			Name            string   `json:"name"`
			Input           string   `json:"input"`
			SystemdCommands []string `json:"systemd_commands"`
			Exec            []struct {
				Program   string `json:"program"`
				Arguments int    `json:"arguments"`
			} `json:"exec"`
		} `json:"cases"`
	}
	if e := json.Unmarshal(fixtureContent(t, "systemd-execstart.json"), &oracle); e != nil {
		t.Fatal(e)
	}
	if oracle.SystemdVersion == "" || len(oracle.Cases) == 0 {
		t.Fatal("missing systemd oracle provenance")
	}
	for _, tc := range oracle.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			if len(tc.SystemdCommands) != len(tc.Exec) {
				t.Fatal("systemd command count differs from expected observations")
			}
			doc, e := parseUnit(t.Context(), strings.NewReader(tc.Input))
			if e != nil || len(doc.Exec) != len(tc.Exec) {
				t.Fatalf("%s reported %q; scan returned %+v (%v)", oracle.SystemdVersion, tc.SystemdCommands, doc, e)
			}
			for i, want := range tc.Exec {
				got := doc.Exec[i]
				if got.Program != want.Program || got.Arguments != want.Arguments {
					t.Fatalf("%s reported %q; scan returned %+v, want %+v", oracle.SystemdVersion, tc.SystemdCommands[i], got, want)
				}
			}
			assertNoCanary(t, doc)
		})
	}
}

// Port of TestRvEscapedBackslashIsNotContinuation from the independent review.
func TestUnitEscapedBackslashIsNotContinuation(t *testing.T) {
	doc, e := parseUnit(t.Context(), strings.NewReader("[Service]\nEnvironment=A=b\\\\\nExecStart=/usr/bin/codex\n"))
	if e != nil || len(doc.Exec) != 1 || doc.Exec[0].Program != "codex-native" {
		t.Fatalf("escaped backslash hid the following start: %+v (%v)", doc, e)
	}
}

// Port of TestRvNodeWrapperExpansion, including values deliberately discarded
// while scanning. Expansion uncertainty must not become a clean no-match.
func TestExecStartExpansionIsUnresolved(t *testing.T) {
	for _, raw := range []string{
		`/usr/bin/node $CODEX_JS`,
		`/usr/bin/node ${HOME}/.npm/lib/node_modules/@openai/codex/bin/codex.js`,
		`/usr/bin/node %h/script.js`,
		`/usr/bin/node ${SCRIPT}`,
		`/usr/bin/node --token $CODEX_JS`,
		`/usr/bin/node --token ${CODEX_JS}`,
		`/usr/bin/node --token %h/script.js`,
		`/usr/bin/node --require=%h/script.js`,
		`/usr/bin/node /opt/@openai/codex/bin/codex.js --token $SECRET`,
		`/usr/bin/true $CMD`,
		`/usr/bin/true --password ${SECRET}`,
		`/usr/bin/codex --token $SECRET`,
		`@/usr/bin/node $ARGV0 /opt/@openai/codex/bin/codex.js`,
		`/usr/bin/node "\x24CODEX_JS"`,
		`/$ROOT/codex`,
		`%h/codex`,
	} {
		t.Run(raw, func(t *testing.T) {
			got, e := parseExecStart([]byte(raw + " --key " + mcpCanary))
			if e == nil || fixedReason(e) != "unresolved" {
				t.Fatalf("expansion passed without uncertainty: %+v (%v)", got, e)
			}
			if got != (unitExec{}) {
				t.Fatalf("partial expansion evidence retained: %+v", got)
			}
			assertNoCanary(t, got)
			assertNoCanary(t, e)
		})
	}
}

func TestExecStartMeasuredWordBound(t *testing.T) {
	const maxArguments = 256
	for _, prefix := range []string{"codex ", "@codex argv0 "} {
		t.Run(prefix, func(t *testing.T) {
			got, e := parseExecStart([]byte(prefix + strings.Repeat("arg ", maxArguments)))
			if e != nil || got.Arguments != maxArguments || got.Program != "codex-native" {
				t.Fatalf("within measured argument cap: %+v (%v)", got, e)
			}
			got, e = parseExecStart([]byte(prefix + strings.Repeat("arg ", maxArguments+1)))
			if e != errLimit || got != (unitExec{}) {
				t.Fatalf("argument cap not enforced: %+v (%v)", got, e)
			}
		})
	}
}

func TestExecStartLaunchWrappersAreUnresolved(t *testing.T) {
	for _, base := range []string{"sh", "bash", "dash", "zsh", "env", "tego", "nohup", "timeout", "nice", "setsid", "stdbuf", "npx", "bunx", "uvx", "tmux", "screen"} {
		t.Run(base, func(t *testing.T) {
			got, e := parseExecStart([]byte("/usr/bin/" + base + " /usr/local/bin/codex --key " + mcpCanary))
			if e == nil || fixedReason(e) != "unresolved" || got != (unitExec{}) {
				t.Fatalf("launcher passed without uncertainty: %+v (%v)", got, e)
			}
			assertNoCanary(t, got)
			assertNoCanary(t, e)
		})
	}
}

func TestExecStartLiteralDollarsAndFixedSpecifier(t *testing.T) {
	for _, tc := range []struct{ raw, program string }{
		{`/usr/bin/true $$VALUE`, ""},
		{`:/usr/bin/node ${HOME}/.npm/lib/node_modules/@openai/codex/bin/codex.js`, "codex-node"},
		{`/usr/bin/node %h/.npm/lib/node_modules/@openai/codex/bin/codex.js`, "codex-node"},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			got, e := parseExecStart([]byte(tc.raw))
			if e != nil || got.Program != tc.program {
				t.Fatalf("literal argument or fixed script suffix became unresolved: %+v (%v)", got, e)
			}
		})
	}
}

func TestUnitUnresolvedLaunchIsDisclosed(t *testing.T) {
	for _, raw := range []string{
		`|codex`,
		`| codex`,
		`@|codex login`,
		`-:|codex`,
		`|@-:!codex login`,
		`/usr/bin/node $CODEX_JS`,
		`/usr/bin/node %h/script.js`,
		`/usr/bin/true --password ${SECRET}`,
		`/usr/bin/nohup /usr/local/bin/codex`,
		`/usr/bin/npx -y @openai/codex`,
		`/usr/bin/timeout 1h codex`,
	} {
		t.Run(raw, func(t *testing.T) {
			o := commandOptions(t)
			if e := os.RemoveAll(filepath.Join(o.ProcRoot, "20")); e != nil {
				t.Fatal(e)
			}
			o.Check = true
			writeSettings(t, o.Directory, ".config/systemd/user/unresolved-agent.service", []byte("[Service]\nEnvironment=CODEX_JS="+mcpCanary+"\nExecStart="+raw+"\n"))
			s := Collect(t.Context(), o).Snapshot
			found := false
			for _, src := range s.Sources {
				if src.Kind == "E" && src.Locator != nil && strings.HasSuffix(string(*src.Locator), "/unresolved-agent.service") {
					found = src.State == "not-read" && src.Reason == "unresolved"
				}
			}
			if !found || s.Counts.Units != 0 || s.Check != "none-observed" || s.ExitCode() != 0 || s.Status != "partial" {
				t.Fatalf("unresolved unit was not disclosed: source=%t units=%d check=%s exit=%d status=%s", found, s.Counts.Units, s.Check, s.ExitCode(), s.Status)
			}
			if _, e := result.Encode(s); e != nil {
				t.Fatal(e)
			}
			for _, verbose := range []bool{false, true} {
				var out, errs bytes.Buffer
				if e := result.Render(&out, &errs, s, false, verbose, nil); e != nil {
					t.Fatal(e)
				}
				text := out.String() + errs.String()
				if strings.Contains(text, "No match") || strings.Contains(text, "No agent") {
					t.Fatalf("uncertainty printed negative summary: %s", text)
				}
				if !strings.Contains(text, "unresolved-agent.service") || !strings.Contains(text, "could not be determined") {
					t.Fatalf("missing named uncertainty (verbose %t): %s", verbose, text)
				}
			}
			assertNoCanary(t, s)
		})
	}
}
