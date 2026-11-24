// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"github.com/attention-span-ai/tego/internal/watch/sig"
	"strconv"
	"strings"
)

// Revision identifies this immutable catalog in saved observations.
const Revision = "c3"

// Row is one observation rule. Paths are relative to the selected home, never input from a file.
type Row struct {
	ID       string
	Rule     sig.Rule
	Programs []string
	Install  []string
	Settings []string
}

// Rows returns fresh copies, so user overrides cannot change the catalog or the guard's defaults.
func Rows() []Row {
	return []Row{
		{ID: "claude-native", Rule: sig.Rule{Name: "claude", Basename: "claude"}, Programs: []string{"claude"}, Install: []string{".local/bin/claude", ".claude/local/claude", ".local/share/claude/versions/*"}, Settings: []string{".claude"}},
		{ID: "claude-node", Rule: sig.Rule{Name: "claude", Argv: []string{"node", ".../@anthropic-ai/claude-code/cli.js"}}},
		{ID: "codex-native", Rule: sig.Rule{Name: "codex", Basename: "codex"}, Programs: []string{"codex"}, Install: []string{".local/bin/codex"}, Settings: []string{".codex"}},
		{ID: "codex-node", Rule: sig.Rule{Name: "codex", Argv: []string{"node", ".../@openai/codex/bin/codex.js"}}},
		{ID: "opencode-native", Rule: sig.Rule{Name: "opencode", Basename: "opencode"}, Programs: []string{"opencode"}, Install: []string{".opencode/bin/opencode", ".local/bin/opencode", ".bun/bin/opencode"}, Settings: []string{".config/opencode", ".local/share/opencode"}},
		{ID: "opencode-node", Rule: sig.Rule{Name: "opencode", Argv: []string{"node", ".../opencode-ai/bin/opencode"}}},
		{ID: "gemini-native", Rule: sig.Rule{Name: "gemini", Basename: "gemini"}, Programs: []string{"gemini"}, Install: []string{".local/bin/gemini"}, Settings: []string{".gemini"}},
		{ID: "gemini-node-bin", Rule: sig.Rule{Name: "gemini", Argv: []string{"node", ".../bin/gemini"}}},
		{ID: "gemini-node-dist", Rule: sig.Rule{Name: "gemini", Argv: []string{"node", ".../@google/gemini-cli/dist/index.js"}}},
	}
}

// ObservedName resolves an observation id to fixed display words. A custom signature's
// chosen alias and tokens are match input; numbered ids prevent either becoming output.
func ObservedName(id string) (string, bool) {
	for _, row := range Rows() {
		if row.ID == id {
			return row.Rule.Name, true
		}
	}
	if rest, ok := strings.CutPrefix(id, "user-"); ok {
		n, err := strconv.ParseUint(rest, 10, 8)
		if err == nil && n >= 1 && n <= 64 && strconv.FormatUint(n, 10) == rest {
			return id, true
		}
	}
	return "", false
}
