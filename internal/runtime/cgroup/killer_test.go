// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"strings"
	"testing"
)

func TestKillerWithoutManager(t *testing.T) {
	if err := (Killer{}).Kill(); err == nil {
		t.Fatal("nil manager accepted")
	}
}

// killOnly is a Manager whose Kill records the cgroup it was asked to kill; every other method is unused.
type killOnly struct {
	Manager
	got []string
	err error
}

func (m *killOnly) Kill(c Cgroup) error {
	m.got = append(m.got, c.Path)
	return m.err
}

func TestKillerWritesThroughTheManager(t *testing.T) {
	m := &killOnly{}
	if err := (Killer{Manager: m, Cgroup: Cgroup{Path: "/sys/fs/cgroup/run-1.scope"}}).Kill(); err != nil {
		t.Fatal(err)
	}
	if len(m.got) != 1 || m.got[0] != "/sys/fs/cgroup/run-1.scope" {
		t.Fatalf("Kill reached the manager as %v", m.got)
	}
	boom := errors.New("boom")
	m.err = boom
	err := (Killer{Manager: m, Cgroup: Cgroup{Path: "/x"}}).Kill()
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "cgroup.kill /x") {
		t.Fatalf("a failed write is %v", err)
	}
}
