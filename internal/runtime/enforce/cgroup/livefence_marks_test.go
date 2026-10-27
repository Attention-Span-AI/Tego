// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestAReadFenceEntrysMountIsMarkedForExec: compile takes an Adjustable run's read fence entry out of deny_read, so
// nothing marked its mount, nor a mount beneath it, and an exec of a program there was never seen by decideExec.
// Both stay marked, for FAN_OPEN_EXEC_PERM alone, and decideExec refuses a program there. A Locked
// table and one with no exec: section mark nothing for the entry; an entry not yet created marks the mount it would
// be created on; a mount table that cannot be read is carried for Prepare to refuse.
func TestAReadFenceEntrysMountIsMarkedForExec(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tool := filepath.Join(dir, "bin", "tool")      // exec.allow, on the mount of dir
	secret := filepath.Join(dir, "srv", "exports") // the read fence entry, a mount of its own
	sub := filepath.Join(secret, "mnt")            // a mount beneath it
	for _, d := range []string{filepath.Dir(tool), sub} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(tool, nil, 0o700); err != nil {
		t.Fatal(err)
	}
	ids := map[string]uint64{dir: 1, secret: 2, sub: 3}
	mountOf := func(p string) (mountKey, error) { // the longest mount point holding p, as the kernel's walk
		best, id := "", uint64(9)
		for path, pid := range ids {
			if (p == path || strings.HasPrefix(p, path+"/")) && len(path) > len(best) {
				best, id = path, pid
			}
		}
		return mountKey{unique: true, id: id}, nil
	}
	under := func(d string) ([]string, error) {
		if d == secret {
			return []string{sub}, nil
		}
		return nil, nil
	}
	table := func(mode agent.LiveMode, read string) *agent.RuleTable {
		rt := policyTable(nil, []agent.ExecRule{{Path: tool, Raw: "tool", Verdict: agent.VerdictAllow}})
		rt.Live = &agent.LiveTable{Mode: mode, Entries: []agent.LiveEntry{
			{Kind: agent.LiveKindRead, Value: read, Source: agent.LiveSourceDeny},
		}}
		return rt
	}

	p := newPolicyWith(table(agent.LiveAdjustable, secret), "/run.scope", under, mountOf)
	if p.mountErr != nil {
		t.Fatal(p.mountErr)
	}
	for _, m := range []string{secret, sub} {
		if !slices.Contains(p.mounts, m) {
			t.Fatalf("mounts = %v: %s, under the read fence entry, is not marked", p.mounts, m)
		}
		if p.masks[m] != unix.FAN_OPEN_EXEC_PERM {
			t.Errorf("%s is marked %#x, want FAN_OPEN_EXEC_PERM alone", m, p.masks[m])
		}
	}
	for _, prog := range []string{filepath.Join(secret, "run.sh"), filepath.Join(sub, "run.sh")} {
		if v := p.decideExec(prog); v.allow {
			t.Errorf("an exec of %s, under the read fence entry, is allowed", prog)
		}
	}
	if v := p.decideExec(tool); !v.allow {
		t.Errorf("the exec.allow program is refused: %+v", v)
	}

	locked := newPolicyWith(table(agent.LiveLocked, secret), "/run.scope", under, mountOf)
	open := table(agent.LiveAdjustable, secret)
	open.Contract = &agent.Contract{Name: "no-exec-section"}
	for name, q := range map[string]*policy{"Locked": locked, "no exec: section": newPolicyWith(open, "/run.scope", under, mountOf)} {
		if slices.Contains(q.mounts, secret) || slices.Contains(q.mounts, sub) {
			t.Errorf("%s: mounts = %v, want none for the fence entry", name, q.mounts)
		}
	}

	later := filepath.Join(dir, "srv", "later")
	q := newPolicyWith(table(agent.LiveAdjustable, later), "/run.scope", under, mountOf)
	if slices.Contains(q.mounts, later) || q.mountErr != nil {
		t.Errorf("an entry not yet created is marked by its own name (%v, %v), want the mount of %s",
			q.mounts, q.mountErr, filepath.Dir(later))
	}

	failing := func(string) ([]string, error) { return nil, os.ErrPermission }
	if q := newPolicyWith(table(agent.LiveAdjustable, secret), "/run.scope", failing, mountOf); !errors.Is(q.mountErr, ErrMountTable) {
		t.Errorf("an unreadable mount table under the fence entry: mountErr %v, want ErrMountTable", q.mountErr)
	}
}
