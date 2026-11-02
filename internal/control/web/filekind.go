// SPDX-License-Identifier: Apache-2.0

package web

import (
	"path"
	"strings"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// fileKinds name well-known files by what they hold, so a path reads as something a person recognises. Matched on
// the path's ending; the first match wins. Never their contents: the page says what a file is, not what is in it.
var fileKinds = []struct{ suffix, kind string }{
	{"/.claude/.credentials.json", "Claude Code's login"},
	{"/.claude-state/.credentials.json", "Claude Code's login"},
	{"/.codex/auth.json", "Codex's login"},
	{"/.netrc", "Saved logins (git, curl)"},
	{"/.git-credentials", "Saved git logins"},
	{"/.ssh/config", "SSH settings"},
	{"/.ssh/known_hosts", "SSH known hosts"},
	{"/.ssh/authorized_keys", "Who may SSH in"},
	{"/.aws/credentials", "AWS keys"},
	{"/.aws/config", "AWS settings"},
	{"/.kube/config", "Kubernetes access"},
	{"/.docker/config.json", "Docker registry logins"},
	{"/.npmrc", "npm token"},
	{"/.pypirc", "PyPI login"},
	{"/.config/gh/hosts.yml", "GitHub CLI login"},
	{"/.env", "Project secrets"},
	{"/.bashrc", "Runs when a terminal opens"},
	{"/.bash_profile", "Runs at login"},
	{"/.profile", "Runs at login"},
	{"/.zshrc", "Runs when a terminal opens"},
	{"/.zprofile", "Runs at login"},
	{"/etc/shadow", "System passwords"},
	{"/etc/passwd", "System users"},
	{"/etc/hosts", "Local host names"},
}

// fileKind says what the file at p is, "" when it is not a well-known one.
func fileKind(p string) string {
	for _, k := range fileKinds {
		if strings.HasSuffix(p, k.suffix) {
			return k.kind
		}
	}
	switch base := path.Base(p); {
	case strings.Contains(p, "/.ssh/") && strings.HasPrefix(base, "id_") && !strings.HasSuffix(base, ".pub"):
		return "SSH private key"
	case strings.Contains(p, "/.gnupg/"):
		return "GPG keys"
	case strings.Contains(p, "/.git/hooks/"):
		return "Runs on git commands"
	case strings.HasPrefix(base, ".env."):
		return "Project secrets"
	case ledgerview.RunsLater(p):
		return "Runs code later"
	}
	return ""
}
