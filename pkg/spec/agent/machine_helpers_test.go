// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// Test helpers that build the machine config's ceiling and setting values.

func tierCeil(t backend.Tier) config.Ceiling[config.TierSetting] {
	if t == "" || t == backend.TierAuto {
		return config.Ceiling[config.TierSetting]{Value: config.TierSetting{Auto: true}}
	}
	return config.Ceiling[config.TierSetting]{Value: config.TierSetting{Tier: string(t)}, Bounded: true}
}

func capCeil(s string) config.Ceiling[config.CaptureSetting] {
	if s == "" || s == "auto" {
		return config.Ceiling[config.CaptureSetting]{Value: config.CaptureSetting{Auto: true}}
	}
	return config.Ceiling[config.CaptureSetting]{Value: config.CaptureSetting{Capture: s}, Bounded: true}
}

func bounded[T comparable](v T) config.Ceiling[T] { return config.Ceiling[T]{Value: v, Bounded: true} }

func machineWith(ledger string, cpu float64, memB int64, pids int, tokens int64, cost float64, wall, stall time.Duration, repeats int) *config.Machine {
	return &config.Machine{
		Tier: tierCeil(backend.TierAuto), Capture: capCeil("auto"),
		LedgerRoot: config.Setting[string]{Value: ledger},
		Limits: config.Limits{
			CPU: bounded(cpu), Memory: bounded(config.ByteSize(memB)), Pids: bounded(pids), Tokens: bounded(tokens),
			CostUSD: bounded(cost), Wall: bounded(wall), StallAfter: bounded(stall), Repeats: bounded(repeats),
		},
	}
}

// zeroCeil is a machine ceiling explicitly set to zero: bounded, value zero. E12 requires it to refuse
// every positive request, which is what distinguishes it from an unbounded ceiling.
func zeroCeil[T comparable]() config.Ceiling[T] {
	var zero T
	return config.Ceiling[T]{Value: zero, Bounded: true}
}
