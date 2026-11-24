// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

type admissionSkipBackend struct {
	*adoptBackend
	reading func() (enforce.ProgramSkips, error)
}

type admissionSkipHandle struct {
	*adoptHandle
	reading func() (enforce.ProgramSkips, error)
}

func (b *admissionSkipBackend) Prepare(ctx context.Context, rt *agent.RuleTable, ref enforce.RunRef) (api.Handle, error) {
	h, err := b.adoptBackend.Prepare(ctx, rt, ref)
	if err != nil {
		return nil, err
	}
	return &admissionSkipHandle{adoptHandle: h.(*adoptHandle), reading: b.reading}, nil
}

func (h *admissionSkipHandle) ProgramSkips() (enforce.ProgramSkips, error) { return h.reading() }

func TestAdoptSnapshotAdmissionRefusalsAreNamed(t *testing.T) {
	for _, name := range []string{"run directory contract", "skip counter baseline"} {
		t.Run(name, func(t *testing.T) {
			f := newAdoptFixture(t)
			sentinel := errors.New("counter unreadable")
			want := error(ErrRunDirWritable)
			if name == "run directory contract" {
				f.rt.FS = []agent.FSRule{{Kind: agent.FSWrite, Path: f.root}}
			} else {
				want = sentinel
				f.deps.Enforce = &admissionSkipBackend{adoptBackend: f.backend, reading: func() (enforce.ProgramSkips, error) { return enforce.ProgramSkips{}, sentinel }}
			}
			_, err := Adopt(t.Context(), f.rt, f.spec(t), f.deps)
			if !errors.Is(err, want) || !strings.Contains(err.Error(), `admission check "`+name+`" during preparation`) {
				t.Fatalf("Adopt = %v, want named snapshot entry %q refusing with %v", err, name, want)
			}
			if name == "skip counter baseline" {
				assertAdmissionCleanup(t, f)
			} else if len(f.host.moves) != 0 || f.cgroups.created != 0 || len(leftBehind(t, f.root)) != 0 {
				t.Fatal("run-directory refusal acquired resources or moved processes")
			}
		})
	}
}

// Skips accrued while the real migration flock is contended must remain counted
// from preparation's baseline. Re-reading it at final admission erases that interval.
func TestAdoptSnapshotsSurviveMigrationWait(t *testing.T) {
	f := newAdoptFixture(t)
	var count atomic.Uint64
	count.Store(7)
	f.deps.Enforce = &admissionSkipBackend{adoptBackend: f.backend, reading: func() (enforce.ProgramSkips, error) {
		return enforce.ProgramSkips{Deciding: count.Load()}, nil
	}}
	waiting, release := holdAdmissionMigration(t, f)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	spec := f.spec(t)
	var a *adoption
	var preparedDir string
	prepared := make(chan struct{})
	spec.Started = func(AdoptStarted) {
		<-prepared
		if a.r.dir != preparedDir {
			t.Errorf("run directory changed during final admission: %q -> %q", preparedDir, a.r.dir)
		}
		if a.r.skipState == nil || a.r.skipState.base.Deciding != 7 {
			t.Errorf("skip baseline = %+v, want preparation count 7 despite wait count 12", a.r.skipState)
		}
		cancel()
	}
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
	preparedDir = a.r.dir
	count.Store(12)
	close(prepared)
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
