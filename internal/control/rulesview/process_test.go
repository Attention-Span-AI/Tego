// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBoundedViewPreservesRun(t *testing.T) {
	f := newFixture(t, "r-aaaaaaaa-0000000000015-prfchg")
	if err := os.WriteFile(filepath.Join(f.dir, "events.jsonl"), f.lines.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	reply, err := viewCall(context.Background(), "inforce", f.root, f.run, "", "", Options{Machine: f.m})
	if err != nil {
		t.Fatal(err)
	}
	if reply.InForce == nil || reply.InForce.CopyPath == "" {
		t.Fatalf("empty reply: %+v", reply)
	}
	local := inForce(context.Background(), f.root, f.run, Options{Machine: f.m})
	if local.Contract.Compiled == nil || local.Contract.Table == "" {
		t.Fatalf("fixture did not compile locally: view=%s contract=%s diagnostics=%s", local.Err, local.Contract.Err, local.Contract.Diagnostics)
	}
	if reply.InForce.Contract.Compiled != nil {
		t.Error("rendered reply carried a partial compiled policy")
	}
	if reply.InForce.Contract.Table != local.Contract.Table || reply.InForce.Contract.Text != local.Contract.Text {
		t.Error("rendered reply lost the helper's table or source text")
	}
}

func TestBoundedViewRedactsPrivatePolicy(t *testing.T) {
	f := newFixture(t, "r-aaaaaaaa-0000000000016-secret")
	secret := "private-helper-env-canary"
	text := sourceText + "\nenv:\n  set:\n    TOKEN: " + secret + "\n"
	if err := os.WriteFile(f.source, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "contract.yaml"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "events.jsonl"), f.lines.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	local := inForce(context.Background(), f.root, f.run, Options{Machine: f.m})
	if !strings.Contains(local.Contract.Table, secret) {
		t.Fatalf("fixture table never contained canary: %s %s", local.Contract.Err, local.Contract.Table)
	}
	for _, operation := range []string{"load", "inforce"} {
		reply, err := viewCall(context.Background(), operation, f.root, f.run, "", "", Options{Machine: f.m})
		if err != nil {
			t.Fatal(err)
		}
		contract := reply.Contract
		if reply.InForce != nil {
			contract = reply.InForce.Contract
		}
		if contract.Err != "" || contract.Table == "" {
			t.Fatalf("%s fixture: %+v", operation, contract)
		}
		if strings.Contains(contract.Table, secret) || strings.Contains(contract.Text, secret) {
			t.Fatalf("%s display projection leaked env.set", operation)
		}
		if !strings.Contains(contract.Table, Hidden) {
			t.Fatalf("%s table omitted redaction marker", operation)
		}
	}
}
