// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"golang.org/x/sys/unix"
)

func TestBuiltinHostIdentityUnreachable(t *testing.T) {
	root := tempDir(t)
	blocked := filepath.Join(root, "private")
	mkTree(t, root, "private/", "private/server.sock", "reachable.sock")
	if err := os.Chmod(blocked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o700) })
	paths := []string{filepath.Join(root, "missing/server.sock")}
	if os.Geteuid() != 0 {
		paths = append(paths, filepath.Join(blocked, "server.sock"))
		if _, err := os.Stat(paths[1]); !errors.Is(err, unix.EACCES) {
			t.Fatalf("fixture must be unsearchable: %v", err)
		}
	}
	rt := &agent.RuleTable{Builtins: &agent.BuiltinRefusals{Nodes: paths}}
	bd := newBuilder(context.Background(), rt, Run{}, profileFor(7), &fakeSyscalls{})
	defer func() { _ = bd.fds.closeAll() }()
	if err := bd.builtinDirectories(); err != nil {
		t.Fatalf("unreachable host server prevents launch: %v", err)
	}
	if len(bd.builtinDirs) != 0 {
		t.Fatalf("unreachable identities recorded present: %v", bd.builtinDirs)
	}
	// The reachable node still has a held identity, even if renamed later.
	reachable := filepath.Join(root, "reachable.sock")
	rt.Builtins.Nodes = append(paths, reachable)
	if err := bd.builtinDirectories(); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(reachable, &st); err != nil {
		t.Fatal(err)
	}
	if bd.builtinDirs[[2]uint64{uint64(st.Dev), st.Ino}] != agent.BuiltinHostIPC {
		t.Fatal("reachable server identity was not pinned")
	}
	if err := os.Rename(reachable, reachable+".moved"); err != nil {
		t.Fatal(err)
	}
	if len(bd.fds.open) != 1 {
		t.Fatalf("pinned identities: %d, want one retained descriptor", len(bd.fds.open))
	}
}

func TestBuiltinHostIdentityUnexpectedErrorsFailClosed(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "file")
	loop := filepath.Join(root, "loop")
	if err := os.Symlink("loop", loop); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{loop, filepath.Join(root, "file/server.sock")} {
		bd := newBuilder(context.Background(), &agent.RuleTable{Builtins: &agent.BuiltinRefusals{Nodes: []string{path}}}, Run{}, profileFor(7), &fakeSyscalls{})
		if err := bd.builtinDirectories(); err == nil {
			t.Errorf("uncertain host identity %s was silently skipped", path)
		}
		_ = bd.fds.closeAll()
	}
}

func TestBuiltinNamesPinMissingAncestorsAtPrepare(t *testing.T) {
	root := tempDir(t)
	parent := filepath.Join(root, "missing/podman")
	rows := &decide.PlaneRows{Keyed: []string{parent}, Protected: []decide.PlaneListenRow{{
		Path: "builtin:" + filepath.Join(parent, "podman.sock"), Parent: parent, Name: "podman.sock", Rule: 0x8000,
	}}}
	h, err := New(Options{syscalls: &fakeSyscalls{abi: 7}}).Prepare(context.Background(), &agent.RuleTable{}, Run{Plane: rows})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()
	row := rows.Protected[0]
	if row.Parent != root || row.Name != "missing" {
		t.Fatalf("first absent component is not protected: %+v", row)
	}
	if _, ok := h.PlaneListenParent(row.Path); !ok {
		t.Fatal("immutable parent was not retained for the plane")
	}
}

func TestBuiltinUnreachableRequiresTraversalEvidence(t *testing.T) {
	for _, errno := range []error{unix.ENOENT, unix.EACCES} {
		if !builtinUnreachable(classifyOpenErr("server.sock", 0, errno)) {
			t.Errorf("traversal %v was not classified unreachable", errno)
		}
		if builtinUnreachable(fmt.Errorf("inspecting an opened descriptor: %w", errno)) {
			t.Errorf("non-traversal %v was silently discarded", errno)
		}
	}
	for _, errno := range []error{unix.ELOOP, unix.ENOTDIR, unix.EIO, unix.EPERM, unix.EMFILE, unix.ENFILE, unix.ENAMETOOLONG} {
		if builtinUnreachable(classifyOpenErr("server.sock", 0, errno)) {
			t.Errorf("uncertain traversal %v was silently discarded", errno)
		}
	}
}
