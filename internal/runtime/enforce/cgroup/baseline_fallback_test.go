// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestBaselinePrepareRechecksActualFallback(t *testing.T) {
	for _, offeredPlane := range []bool{false, true} {
		t.Run(strconv.FormatBool(offeredPlane), func(t *testing.T) {
			f := newFixture(t)
			if err := os.Chmod(f.dir, 0o700); err != nil {
				t.Fatal(err)
			}
			secret := filepath.Join(f.dir, "baseline-secret")
			if err := os.WriteFile(secret, []byte("fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(secret, secret+".alias"); err != nil {
				t.Fatal(err)
			}
			layer := filepath.Join(f.dir, "baseline-config.yaml")
			if err := os.WriteFile(layer, []byte("baseline:\n  fs:\n    deny_read: ["+strconv.Quote(secret)+"]\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			m, ds, err := config.LoadSources(config.Sources{User: layer}, f.dir, os.Getuid(), config.TrustAbort)
			if err != nil {
				t.Fatalf("machine: %v %v", err, ds)
			}
			c, ds2, err := agent.LoadBytes(filepath.Join(f.dir, "baseline-contract.yaml"), []byte("version: 0\nname: baseline-fallback\ncommand: [/bin/true]\ntier: cgroup\n"), nil)
			if err != nil {
				t.Fatalf("contract: %v %v", err, ds2)
			}
			rt, ds2, err := agent.Compile(c, m, agent.WithHome(f.dir), agent.WithCwd(f.dir))
			if err != nil {
				t.Fatalf("compile: %v %v", err, ds2)
			}
			if offeredPlane {
				f.backend.opts.Plane.Mode = ebpfbindings.PlaneLSM
				f.run.PlaneErr = errors.New("modeled plane capacity failure")
			}
			h, err := f.backend.Prepare(context.Background(), rt, f.run)
			if h != nil {
				_ = h.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "baseline mechanism") {
				t.Fatalf("actual listener fallback was accepted: %v", err)
			}
			if len(f.kernel.calls) != 0 {
				t.Fatalf("kernel state installed before baseline fallback refusal: %v", f.kernel.calls)
			}
		})
	}
}
