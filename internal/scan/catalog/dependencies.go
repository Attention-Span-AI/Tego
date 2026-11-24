// SPDX-License-Identifier: Apache-2.0

package catalog

// Dependency is a closed declaration rule, never an installed or running claim.
type Dependency struct{ ID, Name, Format, Package string }

// Dependencies returns fixed ids; parsers return these values rather than input text.
func Dependencies() []Dependency {
	return []Dependency{
		{"dep-claude", "claude", "npm", "@anthropic-ai/claude-code"},
		{"dep-codex", "codex", "npm", "@openai/codex"},
		{"dep-opencode", "opencode", "npm", "opencode-ai"},
		{"dep-gemini", "gemini", "npm", "@google/gemini-cli"},
		{"dep-langgraph-js", "langgraph", "npm", "@langchain/langgraph"},
		{"dep-langgraph", "langgraph", "python", "langgraph"},
		{"dep-crewai", "crewai", "python", "crewai"},
	}
}

// DependencyNamed matches an exact package spelling after format normalization.
func DependencyNamed(format, name string) (Dependency, bool) {
	for _, d := range Dependencies() {
		if d.Format == format && d.Package == name {
			return d, true
		}
	}
	return Dependency{}, false
}
