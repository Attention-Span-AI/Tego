// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestBaselineOutsideWriteGrantKeysProtectedMetadata(t *testing.T) {
	for _, linkedChild := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "linked-child"}[linkedChild], func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			secret := filepath.Join(dir, "secret")
			protected := secret
			if linkedChild {
				if err := os.Mkdir(secret, 0o700); err != nil {
					t.Fatal(err)
				}
				protected = filepath.Join(secret, "token")
			}
			if err := os.WriteFile(protected, []byte("fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			if linkedChild {
				if err := os.Link(protected, filepath.Join(dir, "outside-link")); err != nil {
					t.Fatal(err)
				}
			}
			layer := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(layer, []byte("baseline:\n  fs:\n    deny_write: ["+strconv.Quote(secret)+"]\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			m, ds, err := config.LoadSources(config.Sources{User: layer}, dir, os.Getuid(), config.TrustAbort)
			if err != nil {
				t.Fatalf("load machine: %v %v", err, ds)
			}
			c, ds2, err := agent.LoadBytes(filepath.Join(dir, "agent.yaml"), []byte("version: 0\nname: baseline-metadata\ncommand: [/bin/true]\ntier: cgroup\n"), nil)
			if err != nil {
				t.Fatalf("load contract: %v %v", err, ds2)
			}
			rt, ds2, err := agent.Compile(c, m, agent.WithHome(dir), agent.WithCwd(dir))
			if err != nil {
				t.Fatalf("compile: %v %v", err, ds2)
			}
			rows, err := CompilePlane(rt)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range rows.FS {
				if r.Path == protected {
					if r.Kind&PlaneProtected == 0 || r.Kind&PlaneModifyAllow != 0 || r.Modify.Section != PlaneDenyWriteRule {
						t.Fatalf("baseline target/link row lost deny-write metadata semantics: %+v", r)
					}
					return
				}
			}
			t.Fatal("baseline target/linked child outside all write grants has no plane metadata row")
		})
	}
}
