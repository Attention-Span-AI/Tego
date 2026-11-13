// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// strictPoints is the mount points of a table as Prepare reads them: agent.ParseMountTableStrict, then Points.
func strictPoints(t *testing.T, table string) []string {
	t.Helper()
	mt, err := agent.ParseMountTableStrict([]byte(table))
	if err != nil {
		t.Fatal(err)
	}
	return mt.Points()
}

// TestMountPointsUnder reads the mount points beneath a directory from a mountinfo table, octal escapes decoded,
// the directory itself and its siblings left out.
func TestMountPointsUnder(t *testing.T) {
	table := strings.Join([]string{
		"22 1 0:21 / / rw - ext4 /dev/sda1 rw",
		"30 22 0:30 / /work/out/secret rw - tmpfs tmpfs rw",
		"31 30 0:31 / /work/out/secret/sub rw - tmpfs tmpfs rw",
		"32 22 0:32 / /work/out/secret\\040copy rw - tmpfs tmpfs rw",
		"33 22 0:33 / /work/out/secretive rw - tmpfs tmpfs rw",
		"34 30 0:34 / /work/out/secret/with\\040space rw - tmpfs tmpfs rw",
	}, "\n")
	under := mountPointsUnderFrom(func() ([]string, error) { return strictPoints(t, table), nil })
	got, _ := under("/work/out/secret")
	want := []string{"/work/out/secret/sub", "/work/out/secret/with space"}
	if !slices.Equal(got, want) {
		t.Errorf("mount points under = %q, want %q", got, want)
	}
}

// TestMountPointsUnderSplitsOnSpacesAlone: the kernel escapes only space, tab, newline and backslash, so a mount
// point or root may hold U+00A0, U+0085, \v or \r unescaped. Splitting a line on any Unicode space cut such a
// mount point short, or shifted the mount point field when the root held one, and left the real submount
// beneath a deny_read tree unmarked.
func TestMountPointsUnderSplitsOnSpacesAlone(t *testing.T) {
	table := strings.Join([]string{
		"22 1 0:21 / / rw - ext4 /dev/sda1 rw",
		"30 22 0:30 / /data/a\u00a0b rw - tmpfs tmpfs rw",
		"31 22 0:31 / /data/v\vt rw - tmpfs tmpfs rw",
		"32 22 0:32 / /data/n\u0085l rw - tmpfs tmpfs rw",
		"33 22 8:1 /src\u00a0dir /data/c rw shared:1 - ext4 /dev/sda1 rw",
		"34 22 8:1 /r\rx /data/d rw - ext4 /dev/sda1 rw",
	}, "\n")
	got, _ := mountPointsUnderFrom(func() ([]string, error) { return strictPoints(t, table), nil })("/data")
	want := []string{"/data/a\u00a0b", "/data/c", "/data/d", "/data/n\u0085l", "/data/v\vt"}
	if !slices.Equal(got, want) {
		t.Errorf("mount points under = %q, want %q", got, want)
	}
}

// TestADeniedTreesSubmountsAreMarked: a mark covers one mount, so opens on a tmpfs mounted beneath a deny_read entry
// raised no event and a file there was read with no refusal. Every mount point beneath the entry is marked for
// FAN_OPEN_PERM, and an open there is decided like any in the tree.
func TestADeniedTreesSubmountsAreMarked(t *testing.T) {
	const secret, sub, other = "/work/out/secret", "/work/out/secret/sub", "/elsewhere/mnt"
	under := func(dir string) ([]string, error) {
		if dir == secret {
			return []string{sub}, nil
		}
		return nil, nil
	}
	ids := map[string]uint64{secret: 1, sub: 2, other: 3}
	mountOf := func(p string) (mountKey, error) { // the longest mount point holding p, as the kernel's walk
		best, id := "", uint64(9)
		for path, pid := range ids {
			if (p == path || strings.HasPrefix(p, path+"/")) && len(path) > len(best) {
				best, id = path, pid
			}
		}
		return mountKey{unique: true, id: id}, nil
	}
	p := newPolicyWith(policyTable([]agent.FSRule{
		fsRule(agent.FSWrite, "/work/out", "", "out"),
		{Kind: agent.FSDenyRead, Path: secret, Raw: "out/secret", Unenforced: true},
	}, nil), "/run.scope", under, mountOf)
	if !slices.Contains(p.mounts, sub) {
		t.Fatalf("mounts = %v: the submount beneath the denied tree is not marked", p.mounts)
	}
	if p.masks[sub]&unix.FAN_OPEN_PERM == 0 {
		t.Errorf("the submount's mask %#x asks for no open event", p.masks[sub])
	}
	if v := p.decideOpen(sub + "/key"); v.rule == "" {
		t.Errorf("an open on the submount is not refused: %+v", v)
	}
}

// TestPolicyReadsTheMountTableOnce: the .env scan can put thousands of deny_read entries in one table, and
// reading and parsing mountinfo again for each entry's every spelling made Prepare cost entries x mount lines.
// The table is read once per policy, and each entry still gets the submounts beneath it, and only those.
func TestPolicyReadsTheMountTableOnce(t *testing.T) {
	t.Parallel()
	table := strings.Join([]string{
		"22 1 0:21 / / rw - ext4 /dev/sda1 rw",
		"30 22 0:30 / /proj/a/.env.d rw - tmpfs tmpfs rw",
		"31 22 0:31 / /proj/b rw - tmpfs tmpfs rw",
		"32 22 0:32 / /proj/a/.env.d rw - tmpfs tmpfs rw",
		"33 22 0:33 / /proj/a/.env.dx rw - tmpfs tmpfs rw",
	}, "\n")
	reads := 0
	under := mountPointsUnderFrom(func() ([]string, error) { reads++; return strictPoints(t, table), nil })
	var asked, got []string
	counting := func(dir string) ([]string, error) {
		asked = append(asked, dir)
		out, err := under(dir)
		got = append(got, out...)
		return out, err
	}
	var rules []agent.FSRule
	for i := range 500 {
		rules = append(rules, agent.FSRule{Kind: agent.FSDenyRead, Path: "/proj/c/" + strings.Repeat("x", i%7+1) + "/.env", Raw: ".env"})
	}
	rules = append(rules, agent.FSRule{Kind: agent.FSDenyRead, Path: "/proj/a", Raw: "a"})
	mountOf := func(string) (mountKey, error) { return mountKey{unique: true, id: 1}, nil }
	newPolicyWith(policyTable(rules, nil), "/run.scope", counting, mountOf)
	if len(asked) < len(rules) {
		t.Fatalf("under was asked %d times for %d entries", len(asked), len(rules))
	}
	if reads != 1 {
		t.Fatalf("the mount table was read %d times for %d lookups, want once", reads, len(asked))
	}
	if want := []string{"/proj/a/.env.d", "/proj/a/.env.dx"}; !slices.Equal(got, want) {
		t.Fatalf("submounts = %q, want %q (a path mounted over twice once, a sibling tree none)", got, want)
	}
}

// TestAnUnreadableMountTableRefusesADenyReadPolicy: an unreadable mountinfo listed no mount point, so a tmpfs
// beneath a deny_read tree was left unmarked and a file there read with no refusal and nothing recorded (R8). The
// read error now reaches the policy as ErrMountTable, which Prepare refuses; a table with no deny_read entry never
// reads the mount table and carries none.
func TestAnUnreadableMountTableRefusesADenyReadPolicy(t *testing.T) {
	t.Parallel()
	reads := 0
	under := mountPointsUnderFrom(func() ([]string, error) { reads++; return nil, fs.ErrPermission })
	if got, err := under("/work"); !errors.Is(err, fs.ErrPermission) || got != nil {
		t.Fatalf("under over an unreadable table = %q, %v; want no mount points and the read error", got, err)
	}
	if _, err := under("/elsewhere"); err == nil || reads != 1 {
		t.Fatalf("second lookup = %v after %d reads; want the error again from the one read", err, reads)
	}
	mountOf := func(string) (mountKey, error) { return mountKey{unique: true, id: 1}, nil }
	p := newPolicyWith(policyTable([]agent.FSRule{
		fsRule(agent.FSWrite, "/work/out", "", "out"),
		{Kind: agent.FSDenyRead, Path: "/work/out/secret", Raw: "out/secret", Unenforced: true},
	}, nil), "/run.scope", under, mountOf)
	if !errors.Is(p.mountErr, ErrMountTable) || !errors.Is(p.mountErr, fs.ErrPermission) {
		t.Fatalf("policy mountErr = %v; want ErrMountTable wrapping the read error", p.mountErr)
	}
	calls := 0
	failing := func(string) ([]string, error) { calls++; return nil, fs.ErrPermission }
	q := newPolicyWith(policyTable([]agent.FSRule{fsRule(agent.FSWrite, "/work/out", "", "out")}, nil), "/run.scope", failing, mountOf)
	if q.mountErr != nil || calls != 0 {
		t.Fatalf("a table with no deny_read entry: mountErr %v after %d lookups; want none", q.mountErr, calls)
	}
}
