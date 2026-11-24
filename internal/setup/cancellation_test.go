// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/presets"
)

func TestCanceledSetupDoesNotInspectOrCreate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir := filepath.Join(t.TempDir(), "absent")
	r := &Result{MakeDirs: []string{filepath.Join(dir, "new")}}
	if _, err := CreateContext(ctx, r, dir); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled create inspected path: %v", err)
	}
	if _, _, ok, err := ApplyContext(ctx, r, dir, CheckEnv{}); ok || !errors.Is(err, context.Canceled) {
		t.Errorf("canceled apply inspected path: ok=%v err=%v", ok, err)
	}
}

type canceledProfile struct{ cancel context.CancelFunc }

func (s canceledProfile) Resolve(name string) (string, []byte, error) {
	s.cancel() // The profile read finishes only after the caller has left.
	return (presets.Source{}).Resolve(name)
}

func TestCanceledSetupCompileCleansCreatedFolders(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &Result{Contract: []byte("version: 0\nname: bot\nextends: tego/no-secrets\ncommand: [/bin/true]\n"), MakeDirs: []string{filepath.Join(dir, "new", "child")}}
	env := CheckEnv{Options: []agent.CompileOption{agent.WithPATH("/usr/bin:/bin"), agent.WithHome(t.TempDir())}}
	if ds, ok := Check(r.Contract, dir, env); !ok {
		t.Fatalf("fixture does not compile: %v", ds)
	}
	env.Profiles = (&agent.ProfileChain{}).WithBuiltin(canceledProfile{cancel})
	made, _, ok, err := ApplyContext(ctx, r, dir, env)
	if ok || !errors.Is(err, context.Canceled) || len(made) != 0 {
		t.Errorf("compile resumed into success: made=%v ok=%v err=%v", made, ok, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "new")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("canceled setup left directories: %v", err)
	}
}
