// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

type baselineRecordBackend struct {
	*adoptBackend
	blockCopy bool
}

type baselineRecordHandle struct{ *adoptHandle }

func (*baselineRecordHandle) Verdict() record.Verdict { return record.VerdictObserved }

func (b *baselineRecordBackend) Prepare(ctx context.Context, rt *agent.RuleTable, ref enforce.RunRef) (api.Handle, error) {
	h, err := b.adoptBackend.Prepare(ctx, rt, ref)
	if err != nil {
		return nil, err
	}
	if b.blockCopy {
		if err := os.Mkdir(filepath.Join(ref.RunDir, "effective.yaml"), 0700); err != nil {
			return nil, err
		}
	}
	return &baselineRecordHandle{h.(*adoptHandle)}, nil
}

func adoptionBaselineRecordFixture(t *testing.T) *adoptFixture {
	t.Helper()
	f := newAdoptFixture(t)
	home := t.TempDir()
	if err := os.Chmod(home, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "config.yaml")
	if err := os.WriteFile(path, []byte("ledger_root: "+f.root+"\nbaseline: {env: {deny: [TOKEN]}}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	load := func() (*config.Machine, error) {
		m, _, err := config.LoadSources(config.Sources{User: path}, home, os.Getuid(), config.TrustAbort)
		return m, err
	}
	m, err := load()
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := agent.LoadBytes(filepath.Join(home, "agent.yaml"), []byte("version: 0\nname: recorded-adoption\ncommand: [/bin/true]\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	rt, ds, err := agent.Compile(c, m, agent.WithHome(home), agent.WithOwnBinaries(""), agent.WithMountInfo(""), agent.WithObserve(), agent.Offline())
	if err != nil {
		t.Fatalf("%v %v", err, ds)
	}
	f.rt, f.deps.Config, f.deps.ReloadConfig = rt, m, load
	f.deps.Enforce = &baselineRecordBackend{adoptBackend: f.backend}
	return f
}

func TestAdoptBaselineRecordRefusalsBeforeMigration(t *testing.T) {
	for _, name := range []string{"baseline record evidence", "effective contract copy"} {
		t.Run(name, func(t *testing.T) {
			f := adoptionBaselineRecordFixture(t)
			if name == "baseline record evidence" {
				f.rt.EffectiveHash[0] ^= 1
			} else {
				f.deps.Enforce.(*baselineRecordBackend).blockCopy = true
			}
			_, err := Adopt(t.Context(), f.rt, f.spec(t), f.deps)
			if err == nil || !strings.Contains(err.Error(), `admission check "`+name+`" during preparation`) {
				t.Fatalf("Adopt = %v, want named record refusal %q before movement", err, name)
			}
			assertAdmissionCleanup(t, f)
		})
	}
}

func TestAdoptBaselineRecordPreparedBeforeMigrationWait(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(map[bool]string{false: "known owner", true: "unknown owner"}[unknown], func(t *testing.T) {
			f := adoptionBaselineRecordFixture(t)
			f.deps.BaselineOwnerUnknown = unknown
			waiting, release := holdAdmissionMigration(t, f)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			spec := f.spec(t)
			var a *adoption
			spec.Started = func(AdoptStarted) { cancel() }
			var err error
			a, err = newAdoption(f.rt, spec, f.deps)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, err := a.run(ctx); done <- err }()
			select {
			case <-waiting:
			case err := <-done:
				t.Fatalf("did not wait: %v", err)
			case <-ctx.Done():
				t.Fatal("did not reach migration lock")
			}
			b := a.baselineStart.Baseline
			if b == nil || b.Mode != "not-applied" || b.OwnerKnown == unknown {
				t.Fatalf("prepared evidence = %+v", b)
			}
			data, err := os.ReadFile(filepath.Join(a.r.dir, "effective.yaml"))
			if err != nil || !bytes.Equal(data, b.EffectiveContract) {
				t.Fatalf("effective copy missing before movement: %v", err)
			}
			f.host.mu.Lock()
			moves := len(f.host.moves)
			f.host.mu.Unlock()
			if moves != 0 {
				t.Fatal("moved while migration lock held")
			}
			before, err := os.Stat(filepath.Join(a.r.dir, "effective.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			release()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			after, err := os.Stat(filepath.Join(a.r.dir, "effective.yaml"))
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("snapshot copy was rewritten during final admission: %v", err)
			}

		})
	}
}
