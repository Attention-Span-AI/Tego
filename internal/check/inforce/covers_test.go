// SPDX-License-Identifier: Apache-2.0

package inforce

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestABuiltInRuleWithOneKeyReadsBackFromItsJSON: a built-in rule whose list resolved to exactly one rule key on this
// machine (one secret file in the home, one hooks folder beneath the write entry) has that key and no Covers, nil, not
// an empty list: Covers is omitempty, so the view the dashboard and `tego rules --json` serve reads back with nil, and an
// empty list made the in-process view differ from its own JSON. It did on a machine whose home holds one of the usual
// secret files and no other (internal/control/cli's TestRulesUsesDashboardView in the KVM guest, whose home is empty
// but for the run's own records, 2026-11-11); a home with several, as a CI runner's, hid it.
func TestABuiltInRuleWithOneKeyReadsBackFromItsJSON(t *testing.T) {
	root := t.TempDir()
	f := fixture{root: root, home: filepath.Join(root, "home"), proj: filepath.Join(root, "proj"), bin: filepath.Join(root, "bin")}
	for _, d := range []string{filepath.Join(f.home, ".ssh"), filepath.Join(f.proj, "work", ".git", "hooks"), f.bin} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(f.home, ".ssh", "id_ed25519"), []byte("fake\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.bin, "bash"), []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	rt := f.compileOn(t, "version: 0\nname: one\ncommand: [\"bash\"]\nfs:\n  write: [\"./work/\"]\nnet:\n  allow: []\n", nil, config.Builtin())
	v := Of(rt, backend.TierLandlock, "")
	for _, key := range []string{"built-in.deny_read", "built-in.deny_write"} {
		r := findRule(t, &v, key, "")
		if r.RuleKey == "" {
			t.Fatalf("%s has no rule key, so this machine does not test one key: %+v", key, r)
		}
		if r.Covers != nil {
			t.Errorf("%s: one key %s and Covers %#v, want nil", key, r.RuleKey, r.Covers)
		}
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var back View
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	for i, r := range v.Rules() {
		if got := back.Rules()[i]; !reflect.DeepEqual(got, r) {
			t.Errorf("rule %s after its JSON: %#v\nwant %#v", r.Key, got, r)
		}
	}
}
