// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// passwdOf is a passwd lookup over a fixed table, as LauncherOf's caller passes config.LookupPasswd.
func passwdOf(names map[uint32]string) func(uint32) (string, error) {
	return func(uid uint32) (string, error) {
		if n, ok := names[uid]; ok {
			return n, nil
		}
		return "", fmt.Errorf("no passwd entry for uid %d", uid)
	}
}

func hostnameOf(name string, err error) func() (string, error) {
	return func() (string, error) { return name, err }
}

func u32(v uint32) *uint32 { return &v }

// TestLauncherOf is ADR 0073's identity table: who launched the run, the account sudo says invoked it (only when the
// launcher is root and SUDO_UID is a uid), and the host, each from the inputs given and nothing else.
func TestLauncherOf(t *testing.T) {
	names := passwdOf(map[uint32]string{0: "root", 1000: "dev", 1001: "ops"})
	host := hostnameOf("box", nil)
	cases := []struct {
		name      string
		uid, euid uint32
		env       []string
		passwd    func(uint32) (string, error)
		hostname  func() (string, error)
		want      Launcher
	}{
		{"ordinary user", 1000, 1000, []string{"HOME=/home/dev"}, names, host,
			Launcher{UID: 1000, User: "dev", Host: "box"}},
		{"root without sudo", 0, 0, nil, names, host, Launcher{UID: 0, User: "root", Host: "box"}},
		{"root with a valid SUDO_UID", 0, 0, []string{"SUDO_UID=1001", "SUDO_USER=mallory"}, names, host,
			Launcher{UID: 0, User: "root", SudoUID: u32(1001), SudoUser: "ops", Host: "box"}},
		{"sudo from root to root", 0, 0, []string{"SUDO_UID=0"}, names, host,
			Launcher{UID: 0, User: "root", SudoUID: u32(0), SudoUser: "root", Host: "box"}},
		{"SUDO_UID with no passwd entry keeps the uid", 0, 0, []string{"SUDO_UID=4242", "SUDO_USER=ghost"}, names, host,
			Launcher{UID: 0, User: "root", SudoUID: u32(4242), Host: "box"}},
		{"SUDO_UID non-numeric", 0, 0, []string{"SUDO_UID=dev"}, names, host, Launcher{UID: 0, User: "root", Host: "box"}},
		{"SUDO_UID negative", 0, 0, []string{"SUDO_UID=-1"}, names, host, Launcher{UID: 0, User: "root", Host: "box"}},
		{"SUDO_UID overflowing", 0, 0, []string{"SUDO_UID=4294967296"}, names, host, Launcher{UID: 0, User: "root", Host: "box"}},
		{"SUDO_UID the no-uid value", 0, 0, []string{"SUDO_UID=4294967295"}, names, host, Launcher{UID: 0, User: "root", Host: "box"}},
		{"SUDO_UID empty", 0, 0, []string{"SUDO_UID="}, names, host, Launcher{UID: 0, User: "root", Host: "box"}},
		{"SUDO_UID with a sign", 0, 0, []string{"SUDO_UID=+1000"}, names, host, Launcher{UID: 0, User: "root", Host: "box"}},
		{"SUDO_UID with leading zeros reads as the drop reads it", 0, 0, []string{"SUDO_UID=01000"}, names, host,
			Launcher{UID: 0, User: "root", SudoUID: u32(1000), SudoUser: "dev", Host: "box"}},
		{"SUDO_UID with blank space", 0, 0, []string{"SUDO_UID= 1000"}, names, host, Launcher{UID: 0, User: "root", Host: "box"}},
		{"SUDO_UID while euid is not 0", 1000, 1000, []string{"SUDO_UID=1001"}, names, host,
			Launcher{UID: 1000, User: "dev", Host: "box"}},
		{"SUDO_UID with uid 0 but euid not 0", 0, 1000, []string{"SUDO_UID=1001"}, names, host,
			Launcher{UID: 0, User: "root", Host: "box"}},
		{"the last SUDO_UID wins, as getenv's", 0, 0, []string{"SUDO_UID=1000", "SUDO_UID=1001"}, names, host,
			Launcher{UID: 0, User: "root", SudoUID: u32(1001), SudoUser: "ops", Host: "box"}},
		{"no passwd entry", 2000, 2000, nil, names, host, Launcher{UID: 2000, Host: "box"}},
		{"a passwd name that is empty is none", 1000, 1000, nil, passwdOf(map[uint32]string{1000: ""}), host,
			Launcher{UID: 1000, Host: "box"}},
		{"nil passwd lookup", 1000, 1000, nil, nil, host, Launcher{UID: 1000, Host: "box"}},
		{"hostname error", 1000, 1000, nil, names, hostnameOf("box", errors.New("uname")),
			Launcher{UID: 1000, User: "dev"}},
		{"empty hostname", 1000, 1000, nil, names, hostnameOf("", nil), Launcher{UID: 1000, User: "dev"}},
		{"hostname over 255 bytes", 1000, 1000, nil, names, hostnameOf(strings.Repeat("h", MaxHostBytes+1), nil),
			Launcher{UID: 1000, User: "dev"}},
		{"hostname of 255 bytes", 1000, 1000, nil, names, hostnameOf(strings.Repeat("h", MaxHostBytes), nil),
			Launcher{UID: 1000, User: "dev", Host: strings.Repeat("h", MaxHostBytes)}},
		{"hostname not UTF-8", 1000, 1000, nil, names, hostnameOf("bo\xffx", nil), Launcher{UID: 1000, User: "dev"}},
		// The nodename is whoever holds the UTS namespace's to set; a host a view prints may neither break its line
		// nor reorder or hide what is beside it, as a label value may not.
		{"hostname with an escape", 1000, 1000, nil, names, hostnameOf("bo\x1bx", nil), Launcher{UID: 1000, User: "dev"}},
		{"hostname with a newline", 1000, 1000, nil, names, hostnameOf("box\nrun ok", nil), Launcher{UID: 1000, User: "dev"}},
		{"hostname with a carriage return", 1000, 1000, nil, names, hostnameOf("box\r", nil), Launcher{UID: 1000, User: "dev"}},
		{"hostname with a NUL", 1000, 1000, nil, names, hostnameOf("bo\x00x", nil), Launcher{UID: 1000, User: "dev"}},
		{"hostname with DEL", 1000, 1000, nil, names, hostnameOf("bo\x7fx", nil), Launcher{UID: 1000, User: "dev"}},
		{"hostname with a C1 control", 1000, 1000, nil, names, hostnameOf("bo\u009bx", nil), Launcher{UID: 1000, User: "dev"}},
		{"hostname with a right-to-left override", 1000, 1000, nil, names, hostnameOf("bo\u202ex", nil),
			Launcher{UID: 1000, User: "dev"}},
		{"hostname with a zero-width joiner", 1000, 1000, nil, names, hostnameOf("bo\u200dx", nil),
			Launcher{UID: 1000, User: "dev"}},
		{"hostname with a line separator", 1000, 1000, nil, names, hostnameOf("bo\u2028x", nil),
			Launcher{UID: 1000, User: "dev"}},
		{"hostname with a paragraph separator", 1000, 1000, nil, names, hostnameOf("bo\u2029x", nil),
			Launcher{UID: 1000, User: "dev"}},
		// A passwd name is read from the mount namespace's /etc/passwd, which a user in its own user and mount
		// namespace can replace: it takes the host's rule, and a name that breaks it is no name.
		{"passwd name with an escape", 1000, 1000, nil, passwdOf(map[uint32]string{1000: "de\x1b[2Jv"}), host,
			Launcher{UID: 1000, Host: "box"}},
		{"sudo account's passwd name with a right-to-left override", 0, 0, []string{"SUDO_UID=1001"},
			passwdOf(map[uint32]string{0: "root", 1001: "op\u202es"}), host,
			Launcher{UID: 0, User: "root", SudoUID: u32(1001), Host: "box"}},
		{"passwd name not UTF-8", 1000, 1000, nil, passwdOf(map[uint32]string{1000: "d\xffv"}), host,
			Launcher{UID: 1000, Host: "box"}},
		{"hostname with a space and other letters", 1000, 1000, nil, names, hostnameOf("büro 7", nil),
			Launcher{UID: 1000, User: "dev", Host: "büro 7"}},
		{"nil hostname reader", 1000, 1000, nil, names, nil, Launcher{UID: 1000, User: "dev"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := LauncherOf(tc.uid, tc.euid, tc.passwd, tc.env, tc.hostname)
			if !launcherEqual(got, tc.want) {
				t.Fatalf("LauncherOf = %s, want %s", launcherString(got), launcherString(tc.want))
			}
		})
	}
}

func launcherEqual(a, b Launcher) bool {
	if (a.SudoUID == nil) != (b.SudoUID == nil) || (a.SudoUID != nil && *a.SudoUID != *b.SudoUID) {
		return false
	}
	return a.UID == b.UID && a.User == b.User && a.SudoUser == b.SudoUser && a.Host == b.Host
}

func launcherString(l Launcher) string {
	sudo := "none"
	if l.SudoUID != nil {
		sudo = fmt.Sprint(*l.SudoUID)
	}
	return fmt.Sprintf("{uid %d user %q sudo %s sudo_user %q host %q}", l.UID, l.User, sudo, l.SudoUser, l.Host)
}

// TestValidLabels is each of ADR 0073's label rules, accepted at its edge and refused one past it.
func TestValidLabels(t *testing.T) {
	long := strings.Repeat("k", 63)
	many := map[string]string{}
	for i := range MaxLabels {
		many[fmt.Sprintf("k%d", i)] = "v"
	}
	ok := []map[string]string{
		nil,
		{},
		{"team": "infra", "ticket": "OPS-12", "0": ""},
		{long: strings.Repeat("v", MaxLabelValueBytes)},
		{"a.b_c-d": "naïve café ✓"},
		{"tegox": "a key that only starts like the reserved prefix"},
		many,
	}
	for i, l := range ok {
		if err := ValidLabels(l); err != nil {
			t.Errorf("ok[%d]: ValidLabels refused %v: %v", i, l, err)
		}
	}
	tooMany := map[string]string{"extra": "v"}
	for k, v := range many {
		tooMany[k] = v
	}
	bad := []struct {
		name   string
		labels map[string]string
		want   string
	}{
		{"empty key", map[string]string{"": "v"}, "key"},
		{"key too long", map[string]string{long + "k": "v"}, "key"},
		{"key with an upper-case letter", map[string]string{"Team": "v"}, "key"},
		{"key starting with a dot", map[string]string{".team": "v"}, "key"},
		{"key starting with a dash", map[string]string{"-team": "v"}, "key"},
		{"key with a slash", map[string]string{"a/b": "v"}, "key"},
		{"key with a space", map[string]string{"a b": "v"}, "key"},
		{"key with a non-ASCII letter", map[string]string{"é": "v"}, "key"},
		{"reserved prefix", map[string]string{"tego.run": "v"}, "reserved"},
		{"reserved prefix alone", map[string]string{"tego.": "v"}, "reserved"},
		{"value too long", map[string]string{"k": strings.Repeat("v", MaxLabelValueBytes+1)}, "bytes"},
		{"value not UTF-8", map[string]string{"k": "a\xffb"}, "UTF-8"},
		{"value with a newline", map[string]string{"k": "a\nb"}, "control"},
		{"value with a NUL", map[string]string{"k": "a\x00b"}, "control"},
		{"value with DEL", map[string]string{"k": "a\x7fb"}, "control"},
		{"value with a C1 control", map[string]string{"k": "a\u0085b"}, "control"},
		{"value with a right-to-left override", map[string]string{"k": "a\u202eb"}, "format"},
		{"value with a zero-width space", map[string]string{"k": "a\u200bb"}, "format"},
		{"value with a line separator", map[string]string{"k": "a\u2028b"}, "line"},
		{"too many labels", tooMany, "at most"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidLabels(tc.labels)
			if err == nil {
				t.Fatalf("ValidLabels accepted %q", tc.labels)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidLabels(%q) = %v, want it to say %q", tc.labels, err, tc.want)
			}
		})
	}
}

// TestRoles: the empty role is the agent's own run, check is a tego check run's, and nothing else is a role.
func TestRoles(t *testing.T) {
	for _, r := range []Role{RoleAgent, RoleCheck} {
		if !r.Valid() {
			t.Errorf("%q is not Valid", r)
		}
	}
	for _, r := range []Role{"Check", "agent", "check ", "judge"} {
		if r.Valid() {
			t.Errorf("%q is Valid", r)
		}
	}
	if RoleAgent != "" || RoleCheck != "check" {
		t.Fatalf("role spellings changed: %q %q (record-ledger.md run_start role)", RoleAgent, RoleCheck)
	}
}
