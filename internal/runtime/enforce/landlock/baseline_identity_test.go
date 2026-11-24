// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/fsplan"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestBaselinePreparationChecksOpenedIdentity(t *testing.T) {
	dir := tempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	layer := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(layer, []byte("baseline:\n  fs:\n    deny_read: ["+strconv.Quote(secret)+"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, ds, err := config.LoadSources(config.Sources{User: layer}, dir, os.Getuid(), config.TrustAbort)
	if err != nil {
		t.Fatalf("machine: %v %v", err, ds)
	}
	c, ds2, err := agent.LoadBytes(filepath.Join(dir, "contract.yaml"), []byte("version: 0\nname: baseline-pin\ncommand: [/bin/true]\ntier: landlock\n"), nil)
	if err != nil {
		t.Fatalf("contract: %v %v", err, ds2)
	}
	rt, ds2, err := agent.Compile(c, m, agent.WithHome(dir), agent.WithCwd(dir))
	if err != nil {
		t.Fatalf("compile: %v %v", err, ds2)
	}
	if err := os.Rename(secret, secret+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	bd := newBuilder(context.Background(), rt, Run{}, profileFor(7), &fakeSyscalls{abi: 7})
	t.Cleanup(func() {
		if err := bd.fds.closeAll(); err != nil {
			t.Error(err)
		}
	})
	if _, err := bd.hold(secret, kindPlaneKey, 0); err == nil || !strings.Contains(err.Error(), "baseline target") {
		t.Fatalf("ordinary/plane-key descriptor accepted replacement: %v", err)
	}
	if _, err := bd.snapshotAt(secret, secret, fsplan.NewGrants(nil)); err == nil || !strings.Contains(err.Error(), "baseline target") {
		t.Fatalf("read-deny snapshot descriptor accepted replacement: %v", err)
	}
}
