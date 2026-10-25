// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package cli

import (
	"errors"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestMachineTestHooks is the test build's machine config switches, TEGO_TEST_PLANE and TEGO_TEST_LINGER: each
// sets its own setting as an /etc layer would, both compose, a linger that does not parse sets nothing, and neither
// applies under AT_SECURE or when AT_SECURE cannot be read.
func TestMachineTestHooks(t *testing.T) {
	t.Parallel()
	plain := func() (bool, error) { return false, nil }
	secure := func() (bool, error) { return true, nil }
	unknown := func() (bool, error) { return false, errors.New("no auxv") }
	for _, c := range []struct {
		plane, linger string
		at            func() (bool, error)
		wantPlane     string
		wantLinger    time.Duration
		hook          bool
	}{
		{"", "", plain, "", 5 * time.Minute, false},
		{"lsm", "", plain, "lsm", 5 * time.Minute, true},
		{"", "0s", plain, "", 0, true},
		{"", "2s", plain, "", 2 * time.Second, true},
		{"fmod_ret", "2s", plain, "fmod_ret", 2 * time.Second, true},
		{"", "soon", plain, "", 5 * time.Minute, false},
		{"lsm", "-1s", plain, "lsm", 5 * time.Minute, true},
		{"lsm", "0s", secure, "", 5 * time.Minute, false},
		{"lsm", "0s", unknown, "", 5 * time.Minute, false},
	} {
		hook := machineTestHooks(c.plane, c.linger, c.at, nil)
		if (hook != nil) != c.hook {
			t.Errorf("plane %q linger %q: hook %v, want %v", c.plane, c.linger, hook != nil, c.hook)
			continue
		}
		m := config.Builtin()
		builtinPlane := m.BPF.Plane.Value
		if hook != nil {
			hook(m)
		}
		want := c.wantPlane
		if want == "" {
			want = builtinPlane
		}
		if m.BPF.Plane.Value != want || m.BPF.Linger.Value != c.wantLinger {
			t.Errorf("plane %q linger %q: plane %q linger %v, want %q %v", c.plane, c.linger, m.BPF.Plane.Value,
				m.BPF.Linger.Value, want, c.wantLinger)
		}
		if c.linger != "" && m.BPF.Linger.Value == c.wantLinger && c.wantLinger != 5*time.Minute &&
			(m.BPF.Linger.Source.Layer != config.LayerEtc || m.BPF.Linger.Source.File != "$"+EnvTestLinger) {
			t.Errorf("linger %q: source %+v, want the /etc layer named $%s", c.linger, m.BPF.Linger.Source, EnvTestLinger)
		}
	}
}

// TestTestPricesHook: a test build names the price table under the test home, not the passwd home, where no layer
// set one; a layer's own `prices:` stands; with no test home it names none; and AT_SECURE leaves it alone.
func TestTestPricesHook(t *testing.T) {
	t.Parallel()
	plain := func() (bool, error) { return false, nil }
	secure := func() (bool, error) { return true, nil }
	unknown := func() (bool, error) { return false, errors.New("no auxv") }
	if testPricesHook("/h", secure) != nil || testPricesHook("/h", unknown) != nil {
		t.Error("the hook applies under AT_SECURE or an unreadable auxv")
	}
	builtin := config.Builtin()
	testPricesHook("/h", plain)(builtin)
	if want := "/h/.tego/prices.yaml"; builtin.Prices.Value != want {
		t.Errorf("builtin prices %q, want %q", builtin.Prices.Value, want)
	}
	none := config.Builtin()
	testPricesHook("", plain)(none)
	if none.Prices.Value != "" {
		t.Errorf("with no test home prices %q, want none", none.Prices.Value)
	}
	set := config.Builtin()
	set.Prices = config.Setting[string]{Value: "/etc/p.yaml", Source: config.Provenance{Layer: config.LayerEnvFile}}
	testPricesHook("/h", plain)(set)
	if set.Prices.Value != "/etc/p.yaml" {
		t.Errorf("a layer's prices became %q", set.Prices.Value)
	}
}
