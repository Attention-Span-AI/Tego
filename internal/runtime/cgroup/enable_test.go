// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// refusingSlice lays out tego.slice under fs's root as a slice that offers every run controller and whose
// cgroup.subtree_control refuses a write: a directory stands in for the file, so the open for writing fails
// (EISDIR) as the kernel's EBUSY or EACCES would, whoever runs the test.
func refusingSlice(t *testing.T, fs *FS) string {
	t.Helper()
	top := filepath.Join(fs.Root(), identity.TopSlice)
	if err := os.MkdirAll(filepath.Join(top, fileSubtreeCtl), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(top, fileControllers), []byte("cpu memory pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return top
}

// TestEnableControllersReportsTheRefusal: the write of "+cpu +memory +pids" to a slice's subtree_control had its
// error discarded, so a controller the slice could not enable surfaced later only as SetLimits' "not delegated",
// with the real cause gone. enableControllers now returns the refusal, naming each controller.
func TestEnableControllersReportsTheRefusal(t *testing.T) {
	fs := newTestFS(t)
	top := refusingSlice(t, fs)
	err := fs.enableControllers(top)
	if err == nil {
		t.Fatal("a refused subtree_control write returned no error")
	}
	for _, c := range []string{"+cpu", "+memory", "+pids", fileSubtreeCtl} {
		if !strings.Contains(err.Error(), c) {
			t.Errorf("error %q does not name %s", err, c)
		}
	}
	// A root that is no cgroup filesystem offers no controllers: nothing to enable, nothing refused.
	if err := fs.enableControllers(t.TempDir()); err != nil {
		t.Errorf("a directory with no cgroup.controllers: %v", err)
	}
}

// TestCreateCarriesTheEnableRefusalToSetLimits: Create still succeeds when a slice refuses a controller (the
// scope's own cgroup.controllers says what is enabled, case 31), and the refusal is handled there: SetLimits'
// missing-controller error for that controller carries it.
func TestCreateCarriesTheEnableRefusalToSetLimits(t *testing.T) {
	fs := newTestFS(t)
	refusingSlice(t, fs)
	c, err := fs.Create("retriever", "r-abc")
	if err != nil {
		t.Fatalf("Create failed over a refused controller: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	err = fs.SetLimits(c, Limits{MemoryMax: 1 << 30})
	var missing *MissingControllerError
	if !errors.As(err, &missing) || missing.Controller != "memory" {
		t.Fatalf("SetLimits = %v, want a missing memory controller", err)
	}
	if !strings.Contains(err.Error(), "+memory") || !strings.Contains(err.Error(), identity.TopSlice) {
		t.Errorf("error %q does not carry the refused +memory write in %s", err, identity.TopSlice)
	}
}
