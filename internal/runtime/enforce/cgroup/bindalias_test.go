// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// bindTable is a mount table with the deny_read directory /proj/secret bound beside itself (alias), beneath a
// granted sibling (pub/alias), one file of it bound alone (pub/keyfile), its parent bound beneath the sibling
// (pub/up), and a tmpfs mounted beneath it that is mounted beneath the sibling as well (pub/subalias): that one is the
// tmpfs's own place, not the entry's tree (agent.MountTable.TreeAliases), as the decision plane's walk finds it.
var bindTable = strings.Join([]string{
	"22 1 8:1 / / rw - ext4 /dev/sda1 rw",
	"30 22 8:1 /proj/secret /proj/pub/alias rw - ext4 /dev/sda1 rw",
	"31 22 8:1 /proj/secret /proj/alias rw - ext4 /dev/sda1 rw",
	"32 22 8:1 /proj/secret/key /proj/pub/keyfile rw - ext4 /dev/sda1 rw",
	"33 22 8:1 /proj /proj/pub/up rw - ext4 /dev/sda1 rw",
	"34 22 0:40 / /proj/secret/sub rw - tmpfs tmpfs rw",
	"35 22 0:40 / /proj/pub/subalias rw - tmpfs tmpfs rw",
}, "\n")

// bindMountOf is the mount a path is on in bindTable, by its longest mount point, as statx names it.
func bindMountOf(p string) (mountKey, error) {
	best, id := "/", uint64(22)
	for _, line := range strings.Split(bindTable, "\n") {
		f := strings.Fields(line)
		var n uint64
		for _, c := range f[0] {
			n = n*10 + uint64(c-'0')
		}
		if pt := f[4]; (p == pt || strings.HasPrefix(p, pt+"/")) && len(pt) > len(best) {
			best, id = pt, n
		}
	}
	return mountKey{unique: true, id: id}, nil
}

func bindPolicy(table string) *policy {
	return newPolicyAt(policyTable([]agent.FSRule{
		fsRule(agent.FSWrite, "/proj/pub", "", "./pub/"),
		fsRule(agent.FSDenyRead, "/proj/secret", "", "./secret/"),
	}, nil), "/run.scope", mountSnapshotOf(table).view(), bindMountOf)
}

// TestListenerRefusesEveryAliasLayout pins the fail-closed release limit independently
// of what the contract permits modifying or approving.
func TestListenerRefusesEveryAliasLayout(t *testing.T) {
	for _, tc := range []struct {
		name, lines string
		plane       bool
		wantPlane   bool
	}{
		{"whole tree", "30 22 8:1 /proj/secret /proj/view/alias rw - ext4 /dev/sda1 rw", false, false},
		{"detached file", "30 22 8:1 /proj/secret/key /proj/view/key rw - ext4 /dev/sda1 rw", false, false},
		{"ancestor writable through another bind", "30 22 8:1 /proj/view /proj/edit rw - ext4 /dev/sda1 rw\n31 22 8:1 /proj/secret/deep /proj/view/a/alias rw - ext4 /dev/sda1 rw", false, false},
		{"approval scope", "30 22 8:1 /proj/secret/deep /proj/pub/a/alias rw - ext4 /dev/sda1 rw", false, false},
		{"plane whole tree", "30 22 8:1 /proj/secret /proj/view/alias rw - ext4 /dev/sda1 rw", true, true},
		{"plane detached fallback", "30 22 8:1 /proj/secret/key /proj/view/key rw - ext4 /dev/sda1 rw", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var f *fixture
			if tc.plane {
				f, _ = planeFixture(t, ebpfbindings.PlaneFmodRet)
			} else {
				f = newFixture(t)
			}
			f.table.FS = []agent.FSRule{fsRule(agent.FSDenyRead, "/proj/secret", "", "./secret/"), fsRule(agent.FSWrite, "/proj/edit", "", "./edit/")}
			f.table.NameDeny = nil
			if tc.name == "approval scope" {
				f.table.FSAsk = []agent.FSRule{fsRule(agent.FSAsk, "/proj/pub", "", "./pub/")}
			}
			f.run.Mounts = mountSnapshotOf("22 1 8:1 / / rw - ext4 /dev/sda1 rw\n" + tc.lines + "\n")
			h, err := f.backend.Prepare(context.Background(), f.table, f.run)
			if h != nil {
				defer h.Close()
			}
			if tc.wantPlane {
				if err != nil {
					t.Fatalf("Prepare = %v, want plane", err)
				}
				if h.planeMode == "" {
					t.Fatal("whole-tree alias lost plane")
				}
				return
			}
			if !errors.Is(err, ErrListenerAlias) {
				t.Fatalf("Prepare = %v, want ErrListenerAlias", err)
			}
			if strings.Contains(err.Error(), "tier bpflsm") {
				t.Errorf("incorrect remedy: %v", err)
			}
			if len(f.kernel.calls) != 0 {
				t.Errorf("refusal loaded kernel state: %v", f.kernel.calls)
			}
		})
	}
}

func TestListenerAliasDiagnosticOncePerEntry(t *testing.T) {
	p := bindPolicy(bindTable)
	if !errors.Is(p.aliasErr, ErrListenerAlias) {
		t.Fatalf("aliasErr = %v", p.aliasErr)
	}
	if strings.Count(p.aliasErr.Error(), "deny_read /proj/secret is also visible") != 1 {
		t.Fatalf("duplicate diagnostic: %v", p.aliasErr)
	}
	for _, place := range []string{"/proj/pub/alias", "/proj/alias", "/proj/pub/keyfile", "/proj/pub/up/secret"} {
		if !strings.Contains(p.aliasErr.Error(), place) {
			t.Errorf("missing %s: %v", place, p.aliasErr)
		}
	}
	if v := p.decideOpen("/proj/pub/alias/key"); !v.allow {
		t.Errorf("listener retained alias decision: %+v", v)
	}
	for _, m := range p.mounts {
		if strings.HasPrefix(m, "/proj/pub/") || m == "/proj/alias" {
			t.Errorf("listener retained alias mark %s", m)
		}
	}
}

func TestListenerAliasDiagnosticsBoundLargeInventory(t *testing.T) {
	const entries = 30000
	rules := make([]agent.FSRule, entries)
	for i := range rules {
		path := fmt.Sprintf("/proj/.env.%05d", i)
		rules[i] = fsRule(agent.FSDenyRead, path, "", path)
	}
	started := time.Now()
	p := newPolicyAt(policyTable(rules, nil), "/run.scope", mountSnapshotOf(
		"22 1 8:1 / / rw - ext4 /dev/root rw\n30 22 8:1 /proj /view rw - ext4 /dev/root rw\n").view(), bindMountOf)
	if !errors.Is(p.aliasErr, ErrListenerAlias) {
		t.Fatalf("aliasErr = %v", p.aliasErr)
	}
	// Do not render the old recursively joined inventory: copying its growing prefix
	// is the bug, and can exhaust a busy host before an output-size assertion runs.
	if joined, ok := p.aliasErr.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if _, nested := child.(interface{ Unwrap() []error }); nested {
				t.Fatal("large inventory has recursively joined diagnostics")
			}
		}
	}
	message := p.aliasErr.Error()
	if len(message) > 8192 {
		t.Fatalf("diagnostic has %d bytes, want at most 8192", len(message))
	}
	for _, want := range []string{"deny_read /proj/.env.00000", "and 29992 more"} {
		if !strings.Contains(message, want) {
			t.Errorf("diagnostic omits %q: %s", want, message)
		}
	}
	if strings.Contains(message, "deny_read /proj/.env.00008") {
		t.Error("diagnostic printed entries beyond the first eight")
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Errorf("policy build and rendering took %s for %d entries", elapsed, entries)
	}
	t.Logf("%d entries: %d diagnostic bytes in %s", entries, len(message), time.Since(started))
}

func TestListenerAliasDiagnosticsBoundPlaces(t *testing.T) {
	places := make([]string, 100)
	for i := range places {
		places[i] = fmt.Sprintf("/view/%03d", i)
	}
	view := mountView{
		under:   func(string) ([]string, error) { return nil, nil },
		aliases: func(string) ([]string, error) { return slices.Clone(places), nil },
	}
	p := newPolicyAt(policyTable([]agent.FSRule{fsRule(agent.FSDenyRead, "/proj/secret", "", "./secret/")}, nil), "/run.scope", view, bindMountOf)
	if !errors.Is(p.aliasErr, ErrListenerAlias) {
		t.Fatalf("aliasErr = %v", p.aliasErr)
	}
	message := p.aliasErr.Error()
	if !strings.Contains(message, "/view/000") || !strings.Contains(message, "and 96 more places") || strings.Contains(message, "/view/004") {
		t.Fatalf("unbounded or incomplete places diagnostic: %s", message)
	}
}

// TestBindAliasesThatCannotBeListedRefuseTheRun: a table that cannot be read, is not one well-formed snapshot (a
// chroot's, with no root mount), or disagrees with the mounts the system reports cannot say where else the entry's
// tree is mounted, so Prepare refuses the run (mountErr) rather than run a listener that a bind alias reads past.
func TestBindAliasesThatCannotBeListedRefuseTheRun(t *testing.T) {
	t.Parallel()
	rules := policyTable([]agent.FSRule{fsRule(agent.FSDenyRead, "/proj/secret", "", "./secret/")}, nil)
	failing := newMountSnapshot(nil, nil, fs.ErrPermission, nil)
	if p := newPolicyAt(rules, "/run.scope", failing.view(), bindMountOf); !errors.Is(p.mountErr, ErrMountTable) || !errors.Is(p.mountErr, fs.ErrPermission) {
		t.Errorf("an unreadable table: mountErr = %v, want ErrMountTable wrapping the read's error", p.mountErr)
	}
	noRoot := strings.Join(strings.Split(bindTable, "\n")[1:], "\n") // a chroot's table: no mount at /
	if p := bindPolicy(noRoot); !errors.Is(p.mountErr, ErrMountTable) || !errors.Is(p.mountErr, agent.ErrMountSnapshot) {
		t.Errorf("a table with no root mount: mountErr = %v, want ErrMountTable and agent.ErrMountSnapshot", p.mountErr)
	}
	// The table says / is mount 22; the system says another.
	mt, err := agent.ParseMountTableStrict([]byte(bindTable))
	if err != nil {
		t.Fatal(err)
	}
	other := newMountSnapshot(mt, []byte(bindTable), nil, func(string) (int, error) { return 99, nil })
	if p := newPolicyAt(rules, "/run.scope", other.view(), bindMountOf); !errors.Is(p.mountErr, ErrMountTable) || !errors.Is(p.mountErr, errMountMismatch) {
		t.Errorf("a table the system disagrees with: mountErr = %v, want ErrMountTable and errMountMismatch", p.mountErr)
	}
}

// TestPlaneDetachedPartFallsBackOrRefuses: the decision plane's walk crosses mounts, so from a file bound alone out of a
// deny_read directory (pub/keyfile bound from secret/key) it met the bind's root and then pub/, and allowed the read
// at every plane axis (conformance mounts-bind/read-bind-alias-file, 2026-11-11). Such a table is one the plane
// cannot hold: tier cgroup falls back to the listener and refuses startup, as tier bpflsm does before anything
// is loaded. A bind of the directory itself or of its parent is held: the walk passes the entry. Not parallel: it
// points the package's mount table at a file of its own.
func TestPlaneDetachedPartFallsBackOrRefuses(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.MkdirAll(secret, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secret, "key"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	rt := &agent.RuleTable{FS: []agent.FSRule{{Kind: agent.FSDenyRead, Path: secret, Resolved: secret, Raw: "./secret/"}}}
	rows, err := decide.CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	table := func(lines ...string) string {
		p := filepath.Join(t.TempDir(), "mountinfo")
		body := "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n" + strings.Join(lines, "\n") + "\n"
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	held := table("30 22 8:1 "+secret+" "+dir+"/pub/alias rw - ext4 /dev/sda1 rw",
		"31 22 8:1 "+dir+" "+dir+"/pub/up rw - ext4 /dev/sda1 rw",
		"32 22 8:1 "+secret+"/key "+secret+"/inner rw - ext4 /dev/sda1 rw")
	if err := detachedParts(rows, func() *mountSnapshot { return snapshotFile(held) }); err != nil {
		t.Errorf("binds of the entry, of its parent and of a file within it: %v, want held", err)
	}
	file := table("32 22 8:1 " + secret + "/key " + dir + "/pub/keyfile rw - ext4 /dev/sda1 rw")
	if err := detachedParts(rows, func() *mountSnapshot { return snapshotFile(file) }); !errors.Is(err, ErrPlaneDetachedPart) || !strings.Contains(err.Error(), dir+"/pub/keyfile") {
		t.Errorf("a file of the entry bound beneath a sibling: %v, want ErrPlaneDetachedPart naming the bind", err)
	}
	if err := detachedParts(rows, func() *mountSnapshot { return snapshotFile(filepath.Join(dir, "absent")) }); !errors.Is(err, ErrPlaneDetachedPart) || !errors.Is(err, ErrMountTable) {
		t.Errorf("an unreadable table: %v, want ErrPlaneDetachedPart and ErrMountTable", err)
	}

	saved, savedLive := mountInfoPath, mountLive
	mountInfoPath, mountLive = file, nil // the test's own table is not the system's
	t.Cleanup(func() { mountInfoPath, mountLive = saved, savedLive })
	if err := tier3Plane(PlaneSetup{Mode: ebpfbindings.PlaneLSM}, rt, &Run{}); !errors.Is(err, ErrPlaneCannotHold) || !errors.Is(err, ErrPlaneDetachedPart) {
		t.Errorf("tier3Plane = %v; want ErrPlaneCannotHold for the detached part", err)
	}
	f, plane := planeFixture(t, ebpfbindings.PlaneFmodRet, func(o *Options) { o.newListener = nil })
	f.backend.opts.newListener = newFixture(t).backend.opts.newListener
	f.table.FS = append(f.table.FS, rt.FS...)
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if h != nil {
		defer h.Close()
	}
	if !errors.Is(err, ErrListenerAlias) {
		t.Fatalf("detached fallback Prepare = %v, want startup refusal", err)
	}
	if len(plane.fills) != 0 {
		t.Errorf("the fallback run filled the plane: %v", plane.fills)
	}
}

// snapshotFile is a test's mount table read as Prepare reads one, with no check against the system.
func snapshotFile(path string) *mountSnapshot {
	mt, raw, err := agent.ReadMountSnapshot(path)
	return newMountSnapshot(mt, raw, err, nil)
}

// TestSetuidRefusesReadsOnlyTheListenerHolds is fix round 1's finding 5: under setuid: true a setuid program the run
// starts can regain CAP_SYS_ADMIN and clone a mount tree with open_tree(2), a mount no fanotify mark asks about, and
// the filter does not refuse that call. This release refuses a listener run with setuid: true and any deny_read
// or name rule. Allowed cases must complete Prepare, rather than passing on an unrelated error.
func TestSetuidRefusesReadsOnlyTheListenerHolds(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name                                       string
		setuid, denied, unenforced, names, refused bool
	}{
		{"setuid with listener-only read", true, true, true, false, true},
		{"setuid with Landlock-held read", true, true, false, false, true},
		{"setuid with built-in names", true, false, false, true, true},
		{"setuid without denied reads", true, false, false, false, false},
		{"no setuid", false, true, true, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			rt := *f.table
			rt.FS = slices.Clone(rt.FS)
			if !c.denied {
				rt.FS = slices.DeleteFunc(rt.FS, func(r agent.FSRule) bool { return r.Kind == agent.FSDenyRead })
			}
			for i := range rt.FS {
				if rt.FS[i].Kind == agent.FSDenyRead {
					rt.FS[i].Unenforced = c.unenforced
				}
			}
			if !c.names {
				rt.NameDeny = nil
			}
			contract := agent.Contract{}
			if rt.Contract != nil {
				contract = *rt.Contract
			}
			contract.Setuid = c.setuid
			rt.Contract = &contract
			h, err := f.backend.Prepare(context.Background(), &rt, f.run)
			if h != nil {
				t.Cleanup(func() {
					if err := h.Close(); err != nil {
						t.Error(err)
					}
				})
			}
			if c.refused {
				if !errors.Is(err, ErrListenerSetuid) || h != nil {
					t.Fatalf("Prepare = %v, handle %v; want startup setuid refusal", err, h)
				}
			} else if err != nil || h == nil {
				t.Fatalf("allowed Prepare must succeed: handle %v, error %v", h, err)
			}
		})
	}
}
