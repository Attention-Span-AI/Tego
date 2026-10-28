// SPDX-License-Identifier: Apache-2.0

package secretpath

import "testing"

func TestIs(t *testing.T) {
	for p, want := range map[string]bool{
		"/home/u/.ssh":                              true,
		"/home/u/.ssh/id_rsa":                       true,
		"/home/u/.ssh/id_rsa.pub":                   false,
		"/home/u/.aws/credentials":                  true,
		"/home/u/proj/.env":                         true,
		"/home/u/proj/.env.local":                   true,
		"/home/u/proj/.envrc":                       false,
		"/home/u/proj/confidential/plan.md":         true,
		"/home/u/.config/gcloud/creds.db":           true,
		"/home/u/.config/gh/token":                  true,
		"/home/u/.config/token":                     false,
		"/home/u/.config/other":                     false,
		"/home/u/server.key":                        true,
		"/home/u/.codex/auth.json":                  true,
		"/etc/ssl/certs/Some_Root_CA.pem":           false,
		"/usr/lib/ssl/cert.pem":                     false,
		"/opt/python/certifi/cacert.pem":            false,
		"/home/u/proj/src/main.go":                  false,
		"/home/u/proj/docs/identity-and-secrets.md": false,
		"": false,
	} {
		if got := Is(p); got != want {
			t.Errorf("Is(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestGuardRule(t *testing.T) {
	for rule, want := range map[string]bool{
		"fs.deny_read[/home/u/.ssh/]":         true,
		"fs.ask_read[/home/u/.config/telem/]": true,
		"fs.ask[./src/]":                      false,
		"fs.write[./src/]":                    false,
		"unmatched":                           false,
		"":                                    false,
	} {
		if got := GuardRule(rule); got != want {
			t.Errorf("GuardRule(%q) = %v, want %v", rule, got, want)
		}
	}
}

// TestReadOpen is what counts as a read: the receipt, the dashboard's verdict and tego learn ask the same question.
func TestReadOpen(t *testing.T) {
	const wronly, rdwr, creat = 0o1, 0o2, 0o100
	for _, c := range []struct {
		name         string
		op           string
		flags, errno int
		created      bool
		want         bool
	}{
		{"read-only", "open", 0, 0, false, true},
		{"read-write", "open", rdwr, 0, false, true},
		{"read-only with O_CLOEXEC", "open", 0o2000000, 0, false, true},
		{"create-or-open for reading and writing, not created", "open", rdwr | creat, 0, false, true},
		{"write-only", "open", wronly, 0, false, false},
		{"write-only create", "open", wronly | creat, 0, true, false},
		{"it made the file", "open", rdwr | creat, 0, true, false},
		{"failed", "open", 0, 2, false, false},
		{"unlink", "unlink", 0, 0, false, false},
		{"rename", "rename", 0, 0, false, false},
	} {
		if got := ReadOpen(c.op, c.flags, c.errno, c.created); got != c.want {
			t.Errorf("%s: ReadOpen = %v, want %v", c.name, got, c.want)
		}
	}
}
