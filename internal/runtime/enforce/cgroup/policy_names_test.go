// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"io/fs"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// namePolicy is the listener's policy over nameTable("/p"), with /p/mnt and /p/node_modules mounted beneath the
// scope and /q a mount of its own.
func namePolicy() *policy {
	under := func(dir string) ([]string, error) {
		if dir == "/p" {
			return []string{"/p/mnt", "/p/node_modules"}, nil
		}
		return nil, nil
	}
	mountOf := func(p string) (mountKey, error) { return mountKey{}, errors.New("unnamed") }
	return newPolicyWith(nameTable("/p"), "/run.scope", under, mountOf)
}

// TestListenerPolicyRefusesNameMatchedOpen is ADR 0043 D7's fallback in the listener's policy: an open of a file a
// name entry covers beneath its scope is refused read-denied with the entry's label (D8), also read back with the
// unlinked suffix and on a mount beneath the scope; an exception, a dependency directory and a path outside the
// scope are allowed; and a policy whose only refusals are name entries can refuse an open (canRefuse), so an
// event whose path cannot be read back is refused.
func TestListenerPolicyRefusesNameMatchedOpen(t *testing.T) {
	p := namePolicy()
	for _, tc := range []struct {
		path, rule string
	}{
		{"/p/later/.env.local", "fs.deny_read[/p/**/.env.*]"},
		{"/p/.ENV", "fs.deny_read[/p/**/.env]"},
		{"/p/later/.env (deleted)", "fs.deny_read[/p/**/.env]"},
		{"/p/mnt/x/.env.prod", "fs.deny_read[/p/**/.env.*]"},
		{"/p/x/.env.example", ""},
		{"/p/node_modules/m/.env", ""},
		{"/q/.env", ""},
		{"/p/.envrc", ""},
	} {
		v := p.decideOpen(tc.path)
		if v.allow != (tc.rule == "") || v.rule != tc.rule || (!v.allow && v.reason != record.ReasonReadDenied) {
			t.Errorf("decideOpen(%s) = %+v, want rule %q", tc.path, v, tc.rule)
		}
	}
	if !p.canRefuse(false) {
		t.Error("a policy with name entries reports it cannot refuse an open")
	}
}

// TestListenerMarksMountsBeneathScope: the listener marks each name scope's mount and every mount point beneath the
// scope for FAN_OPEN_PERM (enforce-cgroup-observe R8's rule for deny_read entries), a dependency directory's mount
// included, and a mount table it cannot read refuses the policy (ErrMountTable) rather than leave a submount
// unmarked.
func TestListenerMarksMountsBeneathScope(t *testing.T) {
	p := namePolicy()
	for _, m := range []string{"/p", "/p/mnt", "/p/node_modules"} {
		if p.masks[m]&unix.FAN_OPEN_PERM == 0 {
			t.Errorf("%s is not marked for FAN_OPEN_PERM (marks %v)", m, p.masks)
		}
	}
	if p.mountErr != nil {
		t.Errorf("mountErr %v", p.mountErr)
	}
	broken := newPolicyWith(nameTable("/p"), "/run.scope", func(string) ([]string, error) { return nil, fs.ErrPermission },
		func(string) (mountKey, error) { return mountKey{}, errors.New("unnamed") })
	if !errors.Is(broken.mountErr, ErrMountTable) || !errors.Is(broken.mountErr, fs.ErrPermission) {
		t.Errorf("an unreadable mount table under a name scope gave mountErr %v, want ErrMountTable", broken.mountErr)
	}
	// The root as a scope marks every mount point beneath it.
	root := newPolicyWith(nameTable("/"), "/run.scope", func(dir string) ([]string, error) {
		return sortedUnder([]string{"/", "/a", "/b/c"}, dir), nil
	}, func(string) (mountKey, error) { return mountKey{}, errors.New("unnamed") })
	for _, m := range []string{"/", "/a", "/b/c"} {
		if root.masks[m]&unix.FAN_OPEN_PERM == 0 {
			t.Errorf("scope /: %s is not marked (marks %v)", m, root.masks)
		}
	}
}
