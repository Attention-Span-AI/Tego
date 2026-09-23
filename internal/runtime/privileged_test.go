// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"testing"
)

// TestPrivilegedTargetRefusesRoot is the credential-drop half of R4: a root launcher that cannot name
// a real unprivileged account must refuse the run rather than "drop" the agent to uid 0. With a target
// of 0 the child's drop is three no-op syscalls and, because R4 skips no_new_privs, the kernel's
// root-exec rule restores the whole capability bounding set across the agent's execve — the escape the
// refusal exists to prevent (capabilities(7); ARCHITECTURE.md §5 step 2).
//
// Also pins runtime-launch.md E36: a root launcher with no unprivileged account to drop to refuses the run.
func TestPrivilegedTargetRefusesRoot(t *testing.T) {
	noPasswd := func(int) (int, error) { return 0, errors.New("no passwd entry") }
	cases := []struct {
		name    string
		uid     int
		sudo    bool
		sudoGID string
	}{
		// Direct root: a systemd unit, a cron job, `su -c`, a root container entrypoint.
		// config.InvokingUID answers 0/false here, which is the config-trust answer, not a drop target.
		{"root without sudo", 0, false, ""},
		// E8: a corrupted or sentinel SUDO_UID counts as unset, so InvokingUID falls back to the real
		// uid 0 — the same non-target, reached through sudo.
		{"corrupt SUDO_UID falls back to root", 0, false, "1000"},
		// `sudo` run by root itself: SUDO_UID=0 parses, so viaSudo is true and the uid is still 0.
		{"sudo by root", 0, true, "0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			uid, gid, err := privilegedTarget(c.uid, c.sudo, c.sudoGID, noPasswd)
			if !errors.Is(err, ErrPrivilegedTarget) {
				t.Fatalf("privilegedTarget = (%d, %d, %v), want ErrPrivilegedTarget", uid, gid, err)
			}
		})
	}
}

// TestPrivilegedTargetGroupIsNotTheUID covers the second half: the group the agent drops into is the
// invoking user's own, taken from SUDO_GID or from the passwd entry, never the uid reused as a gid.
// uid and primary gid are independent on directory-backed hosts, so aliasing them hands the agent a
// group the caller never belonged to.
func TestPrivilegedTargetGroupIsNotTheUID(t *testing.T) {
	const (
		uid     = 1450000003
		realGID = 1450000500
	)
	passwd := func(u int) (int, error) {
		if u != uid {
			return 0, fmt.Errorf("unexpected uid %d", u)
		}
		return realGID, nil
	}
	t.Run("SUDO_GID wins", func(t *testing.T) {
		gotUID, gotGID, err := privilegedTarget(uid, true, "1450000500", func(int) (int, error) {
			return 0, errors.New("passwd must not be consulted when sudo said the gid")
		})
		if err != nil {
			t.Fatalf("privilegedTarget: %v", err)
		}
		if gotUID != uid || gotGID != realGID {
			t.Fatalf("got (%d, %d), want (%d, %d)", gotUID, gotGID, uid, realGID)
		}
	})
	t.Run("passwd fills in for a missing SUDO_GID", func(t *testing.T) {
		gotUID, gotGID, err := privilegedTarget(uid, true, "", passwd)
		if err != nil {
			t.Fatalf("privilegedTarget: %v", err)
		}
		if gotUID != uid || gotGID != realGID {
			t.Fatalf("got (%d, %d), want (%d, %d)", gotUID, gotGID, uid, realGID)
		}
	})
	t.Run("the (gid_t)-1 sentinel is not a group", func(t *testing.T) {
		_, gotGID, err := privilegedTarget(uid, true, "4294967295", passwd)
		if err != nil {
			t.Fatalf("privilegedTarget: %v", err)
		}
		if gotGID != realGID {
			t.Fatalf("gid %d, want the passwd gid %d", gotGID, realGID)
		}
	})
	t.Run("no gid source at all is refused", func(t *testing.T) {
		_, _, err := privilegedTarget(uid, true, "bogus", func(int) (int, error) {
			return 0, errors.New("no passwd entry")
		})
		if !errors.Is(err, ErrPrivilegedTarget) {
			t.Fatalf("err = %v, want ErrPrivilegedTarget", err)
		}
	})
}

// TestParseID covers the SUDO_* id parse E8 describes: unsigned 32-bit, sentinel and garbage unset.
func TestParseID(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"", 0, false},
		{"0", 0, true},
		{"1000", 1000, true},
		{"4294967294", 4294967294, true},
		{"4294967295", 0, false}, // (uid_t)-1, never a real id
		{"4294967296", 0, false}, // out of uid_t range
		{"-1", 0, false},
		{"1000x", 0, false},
	}
	for _, c := range cases {
		got, ok := parseID(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("parseID(%q) = (%d, %v), want (%d, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}
