// SPDX-License-Identifier: Apache-2.0

package catalog

// SettingsFile names a fixed MCP source, relative to the selected home or project.
// Evidence: ADR 0145 source table and its linked vendor documentation.
// Real-install checks at the pinned versions remain owed in a guest.
type SettingsFile struct{ ID, Client, Scope, Path, Format string }

// SettingsFiles never expands a path read from settings or the environment.
func SettingsFiles() []SettingsFile {
	return []SettingsFile{
		{"mcp-claude", "claude", "user", ".claude.json", "json"},
		{"mcp-claude", "claude", "project", ".mcp.json", "json"},
		{"mcp-codex", "codex", "user", ".codex/config.toml", "toml"},
		{"mcp-codex", "codex", "project", ".codex/config.toml", "toml"},
		{"mcp-gemini", "gemini", "user", ".gemini/settings.json", "json"},
		{"mcp-gemini", "gemini", "project", ".gemini/settings.json", "json"},
	}
}
