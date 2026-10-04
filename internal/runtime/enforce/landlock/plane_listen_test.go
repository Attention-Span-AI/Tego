// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"golang.org/x/sys/unix"
)

func TestPlaneListenerParentsAreDistinctHeldDescriptors(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "out/")
	parent := filepath.Join(root, "out")
	rt := &agent.RuleTable{Contract: contractWith(true, true), FS: []agent.FSRule{fsRule(agent.FSWrite, parent)}}
	rows := &decide.PlaneRows{Keyed: []string{parent}, ListenPolicy: true,
		Listen: []decide.PlaneListenRow{{Path: filepath.Join(parent, "one"), Parent: parent, Name: "one"},
			{Path: filepath.Join(parent, "two"), Parent: parent, Name: "two"}},
		Neutral: []decide.NeutralRule{{Path: parent, Access: agent.AccessReadDir}}}
	h, err := New(Options{syscalls: &fakeSyscalls{abi: 7}}).Prepare(context.Background(), rt, Run{Plane: rows})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()
	base, _ := h.PlaneHeld(parent)
	one, ok1 := h.PlaneListenParent(rows.Listen[0].Path)
	two, ok2 := h.PlaneListenParent(rows.Listen[1].Path)
	if !ok1 || !ok2 || one == two || one == base || two == base {
		t.Fatalf("not distinct: base=%d first=%d/%v second=%d/%v", base, one, ok1, two, ok2)
	}
	var want unix.Stat_t
	if err := unix.Fstat(base, &want); err != nil {
		t.Fatal(err)
	}
	for _, fd := range []int{one, two} {
		var got unix.Stat_t
		if err := unix.Fstat(fd, &got); err != nil {
			t.Fatal(err)
		}
		if got.Dev != want.Dev || got.Ino != want.Ino {
			t.Fatal("duplicate lost held identity")
		}
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatalf("fd=%d flags=%d err=%v", fd, flags, err)
		}
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.PlaneListenParent(rows.Listen[0].Path); ok {
		t.Fatal("answers after Close")
	}
	for _, fd := range []int{one, two} {
		if err := unix.Fstat(fd, &want); !errors.Is(err, unix.EBADF) {
			t.Fatalf("not released: fd=%d err=%v", fd, err)
		}
	}
}

func TestPlaneListenerDuplicateParentsRespectDescriptorBudget(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "out/")
	parent := filepath.Join(root, "out")
	bd := newBuilder(context.Background(), &agent.RuleTable{}, Run{Plane: &decide.PlaneRows{
		Listen: []decide.PlaneListenRow{{Path: filepath.Join(parent, "one"), Parent: parent}}}}, profileFor(7), &fakeSyscalls{})
	defer func() { _ = bd.fds.closeAll() }()
	if _, err := bd.hold(parent, kindPlaneKey, 0); err != nil {
		t.Fatal(err)
	}
	bd.fds.budgeted = true
	bd.fds.budget = FDBudget{Limit: len(bd.fds.open)}
	if err := bd.planeListenParents(); !errors.Is(err, ErrFDExhausted) {
		t.Fatalf("want budget refusal, got %v", err)
	}
	if len(bd.fds.open) != 1 {
		t.Fatal("failed duplicate left an owned descriptor")
	}
}
