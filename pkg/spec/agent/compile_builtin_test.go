// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBuiltinFIFOIsImmutableAndNestedReadIsHeld(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "screen")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	k := &compiler{c: &Contract{}, rt: &RuleTable{Builtins: &BuiltinRefusals{Runtime: []string{dir}}, FS: []FSRule{{Path: dir, Resolved: dir, Kind: FSWrite}}}}
	k.builtinFIFOs()
	if len(k.rt.FS) != 2 {
		t.Fatalf("FIFO target missing: %+v", k.rt.FS)
	}
	r := k.rt.FS[1]
	if r.Canonical() != fifo || r.Kind != FSDenyRead || r.RuleName() != BuiltinHostIPC || !r.Unenforced {
		t.Fatalf("wrong immutable FIFO target: %+v", r)
	}
	if w, ok := k.nestedWrite[fifo]; !ok || w.resolved != dir {
		t.Fatalf("nested FIFO read would bypass held-read selection: %+v", k.nestedWrite)
	}
}

func TestBuiltinUnreadableSubtreeIsAReadTarget(t *testing.T) {
	dir := t.TempDir()
	orig := readDirN
	readDirN = func(f *os.File, n int) ([]os.DirEntry, error) {
		if f.Name() == dir {
			return nil, os.ErrPermission
		}
		return orig(f, n)
	}
	t.Cleanup(func() { readDirN = orig })
	k := &compiler{rt: &RuleTable{Builtins: &BuiltinRefusals{Runtime: []string{dir}}}}
	k.builtinFIFOs()
	if len(k.rt.FS) != 1 || k.rt.FS[0].RuleName() != BuiltinHostIPC || k.rt.FS[0].Canonical() != dir {
		t.Fatalf("unreadable subtree silently omitted: %+v", k.rt.FS)
	}
}

func TestBuiltinWriteRowsHaveNoOptOutOrOverlapRequirement(t *testing.T) {
	f := newFixture(t)
	rt, _ := f.compile(f.load("version: 0\nname: builtin-rows\ncommand: [\"python\"]\nfs:\n  deny_read: []\n  deny_write: []\n"))
	if len(rt.DenyWrite) == 0 || len(rt.Builtins.Names) == 0 {
		t.Fatal("immutable rows disappeared with empty deny lists and no write grants")
	}
	for _, p := range []string{"/run/user/4242/bus", filepath.Join(f.home, ".screen", "fifo")} {
		r, ok := rt.DenyWriteTarget(p, false)
		if !ok || r.RuleName() != BuiltinHostIPC {
			t.Errorf("%s: %+v %v", p, r, ok)
		}
	}
	for _, r := range rt.DenyWrite {
		if r.BuiltinRule != "" && r.Unenforced {
			t.Errorf("nonoverlapping immutable target spuriously needs a plane: %+v", r)
		}
	}
}

func TestBuiltinPeerExceptionRequiresExactExistingParent(t *testing.T) {
	dir := t.TempDir()
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	b := &BuiltinRefusals{PeerSockets: []string{filepath.Join(alias, "ssh-agent.socket"), filepath.Join(dir, "ssh-agent.socket"), filepath.Join(dir, "missing/ssh-agent.socket")}}
	k := &compiler{rt: &RuleTable{Builtins: b}}
	k.builtinPeerNames()
	if len(b.PeerNames) != 1 || b.PeerNames[0].Parent != dir || b.PeerNames[0].Name != "ssh-agent.socket" {
		t.Fatalf("native exception broadened or duplicated: %+v", b.PeerNames)
	}
}

func TestBuiltinRefusalsOmittedFromObserve(t *testing.T) {
	f := newFixture(t)
	rt, _ := f.compile(f.load("version: 0\nname: observe-builtin\ncommand: [\"python\"]\nhost_sockets: true\n"), WithObserve())
	if rt.Builtins != nil {
		t.Fatal("record-only table installs the immutable relay state")
	}
	for _, r := range append(rt.FS, rt.DenyWrite...) {
		if r.BuiltinRule != "" {
			t.Errorf("record-only table carries %s", r.BuiltinRule)
		}
	}
}

func TestBuiltinRelativeEnvironmentAddsResolvedRefusals(t *testing.T) {
	f := newFixture(t)
	invoking, target := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(target, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(target, "sub"), filepath.Join(invoking, "link")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMUX_TMPDIR", "mux")
	t.Setenv("SCREENDIR", "link/../screen")
	rt, _ := f.compile(f.load("version: 0\nname: relative-ipc\ncommand: [\"python\"]\nhost_sockets: true\n"), WithCwd(invoking))
	for _, p := range []string{filepath.Join(invoking, "mux/tmux-4242/server"), filepath.Join(target, "screen/server")} {
		if got := rt.Builtins.UnixRule(p, true); got != BuiltinHostIPC {
			t.Errorf("relative environment refusal %s = %q", p, got)
		}
	}
}

func TestBuiltinUnplaceableEnvironmentFailsClosed(t *testing.T) {
	f := newFixture(t)
	if err := os.Symlink("loop", filepath.Join(f.project, "loop")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCREENDIR", "loop/../screen")
	_, ds, err := f.compileErr(f.load("version: 0\nname: unknown-ipc\ncommand: [\"python\"]\n"))
	if err == nil || !strings.Contains(render(ds), "cannot be placed for builtin.host_ipc") {
		t.Fatalf("unknown refusal base compiled: %v %s", err, render(ds))
	}
}

// A directory can be listed without being searchable. Its children are then
// present in getdents but absent from every successful stat until an outside
// chmod. The immutable fallback must cover that entire directory.
func TestBuiltinFIFOListingWithoutSearch(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory search permission")
	}
	dir := t.TempDir()
	fifo := filepath.Join(dir, "screen")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("listing: %v, %v", entries, err)
	}
	if _, err := os.Stat(fifo); !os.IsPermission(err) {
		t.Fatalf("stat: %v, want permission denied", err)
	}
	k := &compiler{rt: &RuleTable{Builtins: &BuiltinRefusals{Runtime: []string{dir}}}}
	k.builtinFIFOs()
	if len(k.rt.FS) != 1 || k.rt.FS[0].Canonical() != dir || k.rt.FS[0].RuleName() != BuiltinHostIPC {
		t.Fatalf("unsearchable listed subtree omitted: %+v, %s", k.rt.FS, render(k.ds.list))
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if !Covers(k.rt.FS[0].Canonical(), fifo) {
		t.Fatal("restored search permission exposes the FIFO")
	}
}

func TestBuiltinFIFOMetadataErrorsFailCompilation(t *testing.T) {
	for _, target := range []string{"loop", "file/child"} {
		t.Run(target, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "file"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(dir, "loop")); err != nil {
				t.Fatal(err)
			}
			k := &compiler{rt: &RuleTable{Builtins: &BuiltinRefusals{Runtime: []string{dir}}}}
			k.builtinFIFOs()
			if !hasCode(k.ds.list, CodeUnenforced) || !strings.Contains(render(k.ds.list), "cannot stat FIFO inventory entry") {
				t.Fatalf("metadata error silently omitted: %s", render(k.ds.list))
			}
		})
	}
}

func TestBuiltinFIFOBudgetProtectsUninventoriedSubtree(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 4097; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	k := &compiler{rt: &RuleTable{Builtins: &BuiltinRefusals{Runtime: []string{dir}}}}
	k.builtinFIFOs()
	if len(k.rt.FS) != 1 || k.rt.FS[0].Canonical() != dir || k.rt.FS[0].RuleName() != BuiltinHostIPC {
		t.Fatalf("bounded scan lost coverage: %+v", k.rt.FS)
	}
	if firstError(k.ds.list) != nil {
		t.Fatalf("budget fallback failed: %s", render(k.ds.list))
	}
}
