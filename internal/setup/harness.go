// SPDX-License-Identifier: Apache-2.0

package setup

// Harness describes a supported init --agent command and the model it uses.
// The command is separate from the YAML so --prompt never becomes shell code.
type Harness struct {
	Name, Summary, Command string
	Argv, Notes            []string
	Contract               string
}

// Harnesses lists the supported agents. Keys and login stores are never read by setup.
func Harnesses() []Harness {
	return []Harness{
		{Name: "claude-code", Summary: "Claude Code print mode, with an API key or setup-token", Command: "claude",
			Argv:     []string{"claude", "-p", "--permission-mode", "acceptEdits"},
			Contract: "\nharness: claude-code\ncapture: forwarder\nrecord: full\nmodels:\n  - {provider: anthropic, host: api.anthropic.com, port: 443}\n",
			Notes:    []string{"  claude-code starts one task in print mode; use --prompt <text> to choose the task", "  claude-code uses ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN; for a subscription, run claude setup-token outside Tego, then export CLAUDE_CODE_OAUTH_TOKEN with that token", "  for the full-screen interface, use examples/agents/claude-code-interactive.yaml; its direct model connection is not captured", "  only ./out/ and the generated state folders are writable by default; add --write src/ for a coding task"}},
		{Name: "codex", Summary: "Codex exec, with CODEX_API_KEY (ChatGPT sign-in uses examples/agents/codex-chatgpt.yaml)", Command: "codex",
			Argv:     []string{"codex", "--no-daemon", "--sandbox", "danger-full-access", "--ask-for-approval", "never", "exec"},
			Contract: "\nharness: codex\ncapture: forwarder\nrecord: full\nmodels:\n  - {provider: openai, host: api.openai.com, port: 443}\n",
			Notes:    []string{"  codex needs CODEX_API_KEY; export it before tego run agent.yaml", "  codex starts with a read-only task by default; use --prompt <text> to choose another task", "  only ./out/ and the generated state folders are writable by default; add --write src/ for a coding task"}},
	}
}

func harnessFor(name string) (*Harness, error) {
	if name == "" {
		return nil, nil
	}
	if name == "claude" {
		name = "claude-code"
	}
	for _, h := range Harnesses() {
		if h.Name == name {
			return &h, nil
		}
	}
	return nil, usagef("unknown agent %q; use tego init --list to see claude-code and codex", name)
}
