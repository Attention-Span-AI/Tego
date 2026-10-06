// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Capability numbers the table names (linux/capability.h).
const (
	capNetBindService = 10
	capSysAdmin       = 21
	capPerfmon        = 38
	capBPF            = 39
	capUnknown        = 62 // no kernel defines it: an allowlist refuses it
)

// errClearFailed stands in for a capset the kernel refused.
var errClearFailed = errors.New("capset refused")

func bit(c ...int) uint64 {
	var m uint64
	for _, n := range c {
		m |= 1 << n
	}
	return m
}

// TestPrivilegeActionTable is ADR 0042 (3)(a)'s table: a launcher that gained privilege without being root of the
// initial user namespace is refused, whatever the command but version; one holding only incidental capabilities
// has them cleared and continues; root's launchers, stages and helpers, and a plain user, are left alone.
func TestPrivilegeActionTable(t *testing.T) {
	user := privFacts{userNS: config.UserNamespaceInitial, ruid: 1000, euid: 1000, rgid: 1000, egid: 1000}
	root := privFacts{userNS: config.UserNamespaceInitial}
	with := func(f privFacts, edit func(*privFacts)) privFacts { edit(&f); return f }
	child := privFacts{userNS: config.UserNamespaceChild}
	// A chroot or minimal container with no /proc: the uid map cannot be read, AT_SECURE still can (unix.Auxv).
	unknownUser := with(user, func(f *privFacts) { f.userNS = config.UserNamespaceUnknown })
	unknownRoot := privFacts{userNS: config.UserNamespaceUnknown}
	commands := []string{"run", "doctor", "compile", "status", "events", "__reap", "__child", "__bpf-linger"}
	for _, tc := range []struct {
		name string
		f    privFacts
		want privAction
	}{
		{"a plain user", user, privNone},
		{"root of the initial namespace", root, privNone},
		{"root with every capability", with(root, func(f *privFacts) { f.prm, f.eff = ^uint64(0)>>23, ^uint64(0)>>23 }), privNone},
		{"root, AT_SECURE (a setuid-root copy run by root)", with(root, func(f *privFacts) { f.secure = true }), privNone},
		{"AT_SECURE: a file-capability or setuid copy", with(user, func(f *privFacts) { f.secure = true }), privRefuse},
		{"euid differs from ruid: a setuid copy", with(user, func(f *privFacts) { f.euid = 0 }), privRefuse},
		{"egid differs from rgid: a setgid copy", with(user, func(f *privFacts) { f.egid = 0 }), privRefuse},
		{"cap_net_bind_service ambient only", with(user, func(f *privFacts) {
			f.prm, f.eff, f.inh, f.amb = bit(capNetBindService), bit(capNetBindService), bit(capNetBindService), bit(capNetBindService)
		}), privClear},
		{"cap_net_bind_service permitted and effective", with(user, func(f *privFacts) {
			f.prm, f.eff = bit(capNetBindService), bit(capNetBindService)
		}), privClear},
		// An Ubuntu desktop session hands every process cap_wake_alarm in its inheritable set (measured on the
		// development box, 6.17): an inheritable set alone grants nothing and is left alone.
		{"an inheritable set alone", with(user, func(f *privFacts) { f.inh = bit(capSysAdmin) }), privNone},
		{"a desktop session's inheritable cap_wake_alarm", with(user, func(f *privFacts) { f.inh = bit(35) }), privNone},
		{"cap_bpf only", with(user, func(f *privFacts) { f.prm, f.eff = bit(capBPF), bit(capBPF) }), privRefuse},
		{"the three caps of the withdrawn copy", with(user, func(f *privFacts) {
			f.prm, f.eff = bit(capBPF, capPerfmon, capSysAdmin), bit(capBPF, capPerfmon, capSysAdmin)
		}), privRefuse},
		{"cap_sys_admin ambient", with(user, func(f *privFacts) {
			f.prm, f.inh, f.amb = bit(capSysAdmin), bit(capSysAdmin), bit(capSysAdmin)
		}), privRefuse},
		{"cap_sys_admin permitted, not effective", with(user, func(f *privFacts) { f.prm = bit(capSysAdmin) }), privRefuse},
		{"an incidental and a privileged capability", with(user, func(f *privFacts) {
			f.prm, f.eff = bit(capNetBindService, capSysAdmin), bit(capNetBindService)
		}), privRefuse},
		{"an unknown capability number", with(user, func(f *privFacts) { f.prm = bit(capUnknown) }), privRefuse},
		// Under `unshare -r` or in a rootless container uid 0 holds every capability of its own namespace, none
		// over the host's; only a gain by exec (AT_SECURE) or an id mismatch counts there.
		{"uid 0 of a child namespace with every capability", with(child, func(f *privFacts) { f.prm, f.eff = ^uint64(0)>>23, ^uint64(0)>>23 }), privNone},
		{"a child namespace, AT_SECURE", with(child, func(f *privFacts) { f.secure = true }), privRefuse},
		{"a child namespace, euid differs", with(child, func(f *privFacts) { f.ruid = 1000 }), privRefuse},
		// A uid map that cannot be read is not a child namespace: the sets are read as in the initial one, and its
		// uid 0 is not taken for root (ADR 0042 (3)(a), fail-closed).
		{"uid_map unreadable, cap_sys_admin permitted", with(unknownUser, func(f *privFacts) { f.prm = bit(capSysAdmin) }), privRefuse},
		{"uid_map unreadable, cap_bpf permitted and effective", with(unknownUser, func(f *privFacts) { f.prm, f.eff = bit(capBPF), bit(capBPF) }), privRefuse},
		{"uid_map unreadable, cap_net_bind_service only", with(unknownUser, func(f *privFacts) {
			f.prm, f.eff = bit(capNetBindService), bit(capNetBindService)
		}), privClear},
		{"uid_map unreadable, nothing held", unknownUser, privNone},
		{"uid_map unreadable, AT_SECURE", with(unknownUser, func(f *privFacts) { f.secure = true }), privRefuse},
		{"uid_map unreadable, uid 0 with every capability", with(unknownRoot, func(f *privFacts) { f.prm, f.eff = ^uint64(0)>>23, ^uint64(0)>>23 }), privRefuse},
	} {
		for _, cmd := range commands {
			got, why := privilegeAction(tc.f, cmd)
			if got != tc.want {
				t.Errorf("%s, %s: action %v (%s), want %v", tc.name, cmd, got, why, tc.want)
			}
			if (got == privRefuse) != (why != "") {
				t.Errorf("%s, %s: action %v with reason %q", tc.name, cmd, got, why)
			}
		}
		// version answers whatever the credentials: it reads nothing and acts on nothing.
		if got, why := privilegeAction(tc.f, "version"); got != privNone {
			t.Errorf("%s, version: action %v (%s), want none", tc.name, got, why)
		}
	}
	// The refusal in an unknown namespace says why it was not taken for a child one.
	if _, why := privilegeAction(with(unknownUser, func(f *privFacts) { f.prm = bit(capSysAdmin) }), "run"); !strings.Contains(why, "uid map could not be read") {
		t.Errorf("an unknown namespace's refusal %q does not name the unreadable uid map", why)
	}
}

// TestGuardPrivilegeRefusesWithTheCode: the refusal is one line with the code and the way to the root tiers, and
// exit 125; a clear under run prints one note naming the cleared set.
func TestGuardPrivilegeRefusesWithTheCode(t *testing.T) {
	refused := privFacts{userNS: config.UserNamespaceInitial, ruid: 1000, euid: 1000, rgid: 1000, egid: 1000, secure: true}
	var stderr bytes.Buffer
	code, ok := guardPrivilege([]string{"tego", "doctor"}, &stderr, refused, func() error {
		t.Fatal("a refusal cleared")
		return nil
	})
	if ok || code != identity.ExitLauncher {
		t.Fatalf("guardPrivilege = %d, %v; want 125 and stop", code, ok)
	}
	line := stderr.String()
	for _, want := range []string{"[" + identity.CodePrivilegedPathUnsupported + "]", "sudo tego run", "ADR 0042", "AT_SECURE"} {
		if !strings.Contains(line, want) {
			t.Errorf("refusal %q lacks %q", line, want)
		}
	}
	if strings.Count(line, "\n") != 1 {
		t.Errorf("refusal is not one line: %q", line)
	}

	incidental := privFacts{userNS: config.UserNamespaceInitial, ruid: 1000, euid: 1000, rgid: 1000, egid: 1000,
		prm: bit(capNetBindService), inh: bit(capNetBindService), amb: bit(capNetBindService)}
	for _, cmd := range []string{"run", "status"} {
		stderr.Reset()
		cleared := 0
		code, ok = guardPrivilege([]string{"tego", cmd}, &stderr, incidental, func() error { cleared++; return nil })
		if !ok || cleared != 1 {
			t.Fatalf("%s: guardPrivilege = %d, %v after %d clears; want to continue after one", cmd, code, ok, cleared)
		}
		note := stderr.String()
		if cmd == "run" && (!strings.Contains(note, "tego run: note:") || !strings.Contains(note, "cap_net_bind_service")) {
			t.Errorf("run's note %q does not name the cleared set", note)
		}
		if cmd != "run" && note != "" {
			t.Errorf("%s printed %q; only run notes the clearing", cmd, note)
		}
	}

	stderr.Reset()
	code, ok = guardPrivilege([]string{"tego", "run"}, &stderr, incidental, func() error { return errClearFailed })
	if ok || code != identity.ExitLauncher || !strings.Contains(stderr.String(), "["+identity.CodePrivilegedPathUnsupported+"]") {
		t.Errorf("a failed clear: %d, %v, %q; want a refusal", code, ok, stderr.String())
	}
}

// TestCapabilityNames: the note and the refusal name capabilities as capabilities(7) does.
func TestCapabilityNames(t *testing.T) {
	if got := capNames(bit(capNetBindService, capSysAdmin, capUnknown)); got != "cap_net_bind_service,cap_sys_admin,cap_62" {
		t.Errorf("capNames = %q", got)
	}
}
