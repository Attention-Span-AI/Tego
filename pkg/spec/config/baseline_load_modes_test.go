// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestBaselineDecisionAndObservationLoads(t *testing.T) {
	dir := trustedDir(t)
	bad := writeFile(t, dir, "bad", "baseline: {env: {deny: [SECRET]}}", 0o666)
	good := writeFile(t, dir, "good", "baseline: {env: {deny: [OTHER]}}", 0o600)
	src := Sources{User: bad, EnvFile: good}
	m, ds, err := LoadSources(src, dir, os.Getuid(), TrustAbort)
	if m != nil || !errors.Is(err, ErrUntrusted) || !strings.HasPrefix(err.Error(), "machine config untrusted: "+bad) || len(ds) != 0 {
		t.Fatalf("decision must refuse once with original error: %v %v %v", m, ds, err)
	}
	m, ds, err = LoadSources(src, dir, os.Getuid(), TrustWarn)
	if err != nil || m == nil || m.BaselineKnown() || m.baseline.Empty() || HasErrors(ds) {
		t.Fatalf("observation: %v %v %v", m, ds, err)
	}
	if snap, known := m.BaselineSnapshot(); known || snap.Empty() || len(snap.Entries()) != 1 {
		t.Fatalf("unknown became empty: %+v %v", snap, known)
	}
	layers := m.LayerSources()
	if layers[1].State != LayerUnknown || layers[1].SHA256 != "" || !strings.Contains(layers[1].Reason, "group or other writable") || layers[2].State != LayerPresent {
		t.Fatal(layers)
	}
	if countCode(ds, CodeBaselineUnknown) != 1 || !strings.Contains(ds[0].Message, "baseline UNKNOWN") {
		t.Fatal(ds)
	}
}

func TestBaselineMissingPasswdHomeDoesNotSelectUserLayer(t *testing.T) {
	src, home, _ := Resolve(2147483000, true)
	if home != "" || src.User != "" {
		t.Fatalf("unknown uid resolved: %+v %q", src, home)
	}
	src.Etc = "" // discovery only; no host layer participates in this test
	for _, mode := range []TrustMode{TrustAbort, TrustWarn} {
		m, ds, err := LoadSources(src, home, os.Getuid(), mode)
		if err != nil || m == nil || !m.BaselineKnown() || !m.baseline.Empty() || m.LayerSources()[1].State != LayerUnselected || len(ds) != 0 {
			t.Fatalf("mode %v: %+v %v %v", mode, m, ds, err)
		}
	}
}

func TestBaselineHomeRequiredOnlyForTilde(t *testing.T) {
	dir := trustedDir(t)
	target := writeFile(t, dir, "target", "secret", 0o600)
	writeFile(t, dir, "secret", "another owner's secret", 0o600)
	for _, value := range []string{target, "~/secret"} {
		path := writeFile(t, dir, "config", "baseline:\n  fs:\n    deny_read: ["+value+"]\n", 0o600)
		m, ds, err := LoadSources(Sources{EnvFile: path}, "", os.Getuid(), TrustAbort)
		if err != nil || m == nil || !m.BaselineKnown() {
			t.Fatalf("home-independent load: %v %v", ds, err)
		}
		got, err := m.baseline.Resolve(BaselineOwner{UID: 2147483000})
		if value == target {
			if err != nil || len(got.Entries) != 1 || got.Entries[0].Target != target {
				t.Fatalf("absolute path needs no home: %+v %v", got, err)
			}
			continue
		}
		if err == nil {
			t.Fatal("resolved ~/ without owner home")
		}
		for _, want := range []string{"env layer", path + ":3", "fs.deny_read", "~/secret", "2147483000", "absolute path", "user with a passwd entry"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("home refusal omits %q: %v", want, err)
			}
		}
		got, err = m.baseline.Resolve(BaselineOwner{UID: 1001, Home: dir})
		if err != nil || len(got.Entries) != 1 || got.Entries[0].Target != dir+"/secret" || got.Owner.UID != 1001 {
			t.Fatalf("owner context was not used: %+v %v", got, err)
		}
	}
}

func TestBaselineLoadRetainsSourcesWithoutEnforcementClaim(t *testing.T) {
	dir := trustedDir(t)
	src := Sources{Etc: writeFile(t, dir, "etc", "baseline: {env: {deny: [TOKEN]}}", 0o644), User: writeFile(t, dir, "user", "baseline: {env: {deny: [TOKEN]}}", 0o600), EnvFile: writeFile(t, dir, "env", "baseline: {exec: {deny: ['git push']}}", 0o600)}
	for _, mode := range []TrustMode{TrustAbort, TrustWarn} {
		m, ds, err := fixtureLoad(src, dir, os.Getuid(), mode)
		if err != nil || !m.BaselineKnown() || countCode(ds, CodeBaselineNotApplied) != 0 {
			t.Fatalf("%v %v", ds, err)
		}
		if len(m.baseline.Entries()) != 2 || len(m.baseline.Entries()[1].Sources) != 2 {
			t.Fatal(m.baseline.Entries())
		}
	}
}

func TestUnknownSourceCannotBeErasedByBaselineAssignment(t *testing.T) {
	m := Builtin()
	markUnknown(m, "user.yaml", "user.yaml", LayerUser, os.ErrPermission, new([]Diagnostic))
	m.baseline = Baseline{}
	b, known := m.BaselineSnapshot()
	if m.BaselineKnown() || known || b.Empty() {
		t.Fatal("assigning baseline erased unknown source")
	}
	b, known = (*Machine)(nil).BaselineSnapshot()
	if known || b.Empty() {
		t.Fatal("nil machine became known empty baseline")
	}
}
