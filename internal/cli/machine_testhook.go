// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// EnvTestPlane names the decision plane's pin of a binary built with -tags tegotesthooks: auto, lsm, fmod_ret or
// fanotify, as bpf.plane in /etc/tego/config.yaml would (fanotify, which no config names, rules every plane mode
// out). test/conformance runs tier cgroup once per mode a machine offers with it (ADR 0017's mode axis), and the
// guest suites run a plane mode or the listener on one boot, without writing the host's /etc. A product build does
// not contain this file; a test build ignores it under AT_SECURE, like every TEGO_TEST_ variable.
const EnvTestPlane = "TEGO_TEST_PLANE"

// EnvTestLinger is bpf.linger for a binary built with -tags tegotesthooks, a duration as the config spells one
// ("0s", "2s", "5m"), as /etc/tego/config.yaml would set it: ADR 0022's kill tests run the real binary at linger 0
// and at a linger of seconds without writing the host's /etc. The launcher hands its linger to its reaper and to the
// build's timer, so both follow it. A value that does not parse sets nothing and says so on stderr. Ignored under
// AT_SECURE, as EnvTestPlane is.
const EnvTestLinger = "TEGO_TEST_LINGER"

func init() {
	machineTestHook = chainHooks(
		machineTestHooks(os.Getenv(EnvTestPlane), os.Getenv(EnvTestLinger), config.DetectSecureExec, os.Stderr),
		testPricesHook(os.Getenv(EnvTestOwnLogHome), config.DetectSecureExec))
}

// chainHooks runs the non-nil hooks in order; nil when there are none.
func chainHooks(hooks ...func(*config.Machine)) func(*config.Machine) {
	var all []func(*config.Machine)
	for _, h := range hooks {
		if h != nil {
			all = append(all, h)
		}
	}
	if len(all) == 0 {
		return nil
	}
	return func(m *config.Machine) {
		for _, h := range all {
			h(m)
		}
	}
}

// testPricesHook keeps a test build off the invoking user's own ~/.tego/prices.yaml, which the built-in `prices`
// default names under the passwd home whatever $HOME and $TEGO_CONFIG say. Where no layer set `prices`, it names
// <home>/.tego/prices.yaml for the EnvTestOwnLogHome home the other state (own log) already follows, or, with that
// unset, none at all (a test build fails closed, as testOwnLogHome does). A `prices:` a layer wrote stands. nil under
// AT_SECURE or when AT_SECURE cannot be read, like every TEGO_TEST_ variable.
func testPricesHook(home string, secureExec func() (bool, error)) func(*config.Machine) {
	if secure, err := secureExec(); err != nil || secure {
		return nil
	}
	return func(m *config.Machine) {
		if m.Prices.Source.Layer != config.LayerBuiltin {
			return
		}
		m.Prices.Value = ""
		if home != "" {
			m.Prices.Value = filepath.Join(home, ".tego", "prices.yaml")
		}
	}
}

// machineTestHooks is the machine config hook the two variables' values make: nil when neither is set, under
// AT_SECURE, or when AT_SECURE cannot be read. Each value is recorded as an /etc layer's, under the variable's name.
func machineTestHooks(plane, linger string, secureExec func() (bool, error), stderr *os.File) func(*config.Machine) {
	if plane == "" && linger == "" {
		return nil
	}
	if secure, err := secureExec(); err != nil || secure {
		return nil
	}
	var hooks []func(*config.Machine)
	if plane != "" {
		hooks = append(hooks, func(m *config.Machine) {
			m.BPF.Plane.Value = plane
			m.BPF.Plane.Source = config.Provenance{File: "$" + EnvTestPlane, Layer: config.LayerEtc}
		})
	}
	if linger != "" {
		d, err := config.ParseDuration(linger)
		if err != nil {
			if stderr != nil {
				_, _ = fmt.Fprintf(stderr, "tego: %s=%q sets nothing: %v\n", EnvTestLinger, linger, err)
			}
		} else {
			hooks = append(hooks, func(m *config.Machine) { setTestLinger(m, d) })
		}
	}
	if len(hooks) == 0 {
		return nil
	}
	return func(m *config.Machine) {
		for _, h := range hooks {
			h(m)
		}
	}
}

func setTestLinger(m *config.Machine, d time.Duration) {
	m.BPF.Linger.Value = d
	m.BPF.Linger.Source = config.Provenance{File: "$" + EnvTestLinger, Layer: config.LayerEtc}
}
