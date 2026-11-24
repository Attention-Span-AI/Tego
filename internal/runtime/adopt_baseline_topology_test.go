// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func adoptionBaselineIdentityTable(t *testing.T) (*agent.RuleTable, string) {
	t.Helper()
	dir := t.TempDir()
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
	c, ds2, err := agent.LoadBytes(filepath.Join(dir, "contract.yaml"), []byte("version: 0\nname: adopt-node\ncommand: [/bin/true]\ntier: cgroup\n"), nil)
	if err != nil {
		t.Fatalf("contract: %v %v", err, ds2)
	}
	rt, ds2, err := agent.Compile(c, m, agent.WithHome(dir), agent.WithCwd(dir))
	if err != nil {
		t.Fatalf("compile: %v %v", err, ds2)
	}
	return rt, secret
}

func TestAdoptionRechecksBaselineAtMigration(t *testing.T) {
	for _, afterMove := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-move", true: "after-move"}[afterMove], func(t *testing.T) {
			f := newAdoptFixture(t)
			f.backend.plane = "lsm"
			spec := f.spec(t)
			spec.Boundary = true
			// Enter the internal lifecycle using the ordinary empty snapshot. The
			// public slice-6 record gate remains closed; this fixture exercises the
			// later identity seam directly without admitting a product launch.
			a, err := newAdoption(f.rt, spec, f.deps)
			if err != nil {
				t.Fatal(err)
			}
			rt, secret := adoptionBaselineIdentityTable(t)
			replaced := false
			replace := func() {
				if replaced {
					return
				}
				replaced = true
				if err := os.Rename(secret, secret+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(secret, []byte("replacement"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if afterMove {
				f.host.onAdd = func(pid int) {
					if pid == 200 {
						replace()
					}
				}
			}
			// Install only at this internal seam, after the empty snapshot's
			// record preparation. This test always fails identity admission and
			// publishes no record; it does not bypass the public release gate.
			f.backend.onArm = func() {
				a.r.rt = rt
				if !afterMove {
					replace()
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err = a.run(ctx)
			if err == nil || !strings.Contains(err.Error(), "baseline identity") {
				t.Fatalf("changed target crossed migration boundary: %v", err)
			}
			if !replaced {
				t.Fatal("replacement seam was not reached")
			}
			if !afterMove && len(f.host.moves) != 0 {
				t.Fatalf("processes moved before failed identity check: %v", f.host.moves)
			}
			if got := f.host.in(adoptSession); len(got) != 4 {
				t.Fatalf("failure did not release every process: %v", got)
			}
		})
	}
}
