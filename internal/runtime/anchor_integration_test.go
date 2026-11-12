// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestIntegrationRootSweepAnchorsTheOwnersRun is the shared-ledger-root case as root: an admin's sweep
// ends another account's orphan. It used to be anchored in the sweeper's own chain.log, where the run's
// owner never looks, so their `events --verify` reported ErrAnchorMissing for a run nobody tampered
// with. The owner here is an account with no passwd entry, so no home, and the line belongs beside the
// ledger root: where that account's own launcher anchored its runs on this root. It used to be nobody, whose
// home is /nonexistent on Debian and Ubuntu but / on the RHEL family: there the sweep anchored the run in
// /.tego/chain.log, as AnchorPath's rule says for a home that exists, and the test failed (AlmaLinux 9.8,
// 2026-11-10).
func TestIntegrationRootSweepAnchorsTheOwnersRun(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: only root can end another account's run")
	}
	homeless := uidWithoutPasswd(t)
	base := t.TempDir()
	root := filepath.Join(base, "runs")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	const orphan = "r-00000000-000000000000a-theirs"
	startedRun(t, root, orphan)
	if err := filepath.Walk(filepath.Join(root, orphan), func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, homeless, homeless)
	}); err != nil {
		t.Fatal(err)
	}
	own := filepath.Join(t.TempDir(), ".tego", ledger.ChainLogFile)
	res, err := Sweep(context.Background(), root, KeepForever, WithSweepManager(nil), WithSweepAnchor(own))
	if err != nil || res.Orphaned != 1 {
		t.Fatalf("Sweep: %+v %v", res, err)
	}
	if _, err := os.Stat(own); err == nil {
		t.Fatalf("the sweeper's own anchor %s was written for another account's run", own)
	}
	r, err := ledger.OpenReader(filepath.Join(root, orphan))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	rep, err := r.Verify(context.Background(), ledger.NewFileChainAnchor(filepath.Join(base, ledger.ChainLogFile)))
	if err != nil || !rep.Anchored || !rep.Ended {
		t.Fatalf("the swept run is not anchored beside its ledger root: %+v %v", rep, err)
	}
}

// uidWithoutPasswd is a uid the passwd database names no entry for, as the sweep reads it (config.LookupPasswd), so
// its home is none on every distribution.
func uidWithoutPasswd(t *testing.T) int {
	t.Helper()
	for uid := 65533; uid > 60000; uid-- {
		if _, err := config.LookupPasswd(uid); err != nil {
			return uid
		}
	}
	t.Fatal("every uid from 60001 to 65533 has a passwd entry")
	return 0
}
