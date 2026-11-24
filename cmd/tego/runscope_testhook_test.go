// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package main

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestScopeEntryInMainAcceptsInheritedPipesBeforeAnyOwner follows cmd/tego's real main, GuardPrivilege and
// cli.Main dispatch. The request is larger than a pipe can buffer, so a complete write proves scopedMain read
// it instead of failing the inherited seal at entry. Its forbidden noun refuses before placement or run state.
func TestScopeEntryInMainAcceptsInheritedPipesBeforeAnyOwner(t *testing.T) {
	request, send, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer request.Close()
	defer send.Close()
	receive, response, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer receive.Close()
	defer response.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "machine.yaml")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+filepath.Join(dir, "runs")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, os.Args[0], "__user_scope")
	cmd.Env = testutil.TegoEnv(t, dir, mainEnv+"=1", "TEGO_CONFIG="+cfg)
	cmd.ExtraFiles = []*os.File{request, response}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	_ = request.Close()
	_ = response.Close()
	if err := send.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	writeErr := gob.NewEncoder(send).Encode(struct{ Argv, Env []string }{
		Argv: []string{"tego", "forbidden-scope-noun", strings.Repeat("x", 2<<20)},
	})
	_ = send.Close()
	err = cmd.Wait()
	if writeErr != nil {
		t.Fatalf("main did not read the inherited request: %v; status %v; stderr %s", writeErr, err, stderr.String())
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 125 || stderr.Len() != 0 {
		t.Fatalf("forbidden noun: status %v; stderr %s", err, stderr.String())
	}
}
