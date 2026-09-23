// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"log/slog"

	"github.com/attention-span-ai/tego/internal/runtime/observe"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// observeFactory builds the tier's kernel recorder, the thing that drains the ring buffer the tracing
// programs write to and turns each sample into a ledger event (docs/p0/enforce-cgroup-observe.md §2.4).
//
// It is handed to runtime.Deps as a factory rather than as a built source because the ring buffer is
// named by a build hash the enforcement handle computes at Prepare time, inside the run. A forwarder can
// be built beforehand because it binds its own socket; there is nothing here to read until the tier has
// attached. The runtime calls this with the hash once it has one, and only for a tier that has one.
//
// It lives in internal/cli because internal/runtime cannot construct it: internal/runtime/observe imports
// internal/runtime (for ActivityStamper, DecisionPlaneNamer, PathHookNamer, KernelReading, Queue and the Gap*
// names), so the arrow points one way and the composition root is here.
func observeFactory(rt *agent.RuleTable, log *slog.Logger) func(string) (source.Source, error) {
	return func(bpfHash string) (source.Source, error) {
		if bpfHash == "" {
			return nil, fmt.Errorf("observe: the enforcement handle named no bpf build")
		}
		r, err := observe.New(observeOptions(rt, bpfHash, log))
		if err != nil {
			return nil, err
		}
		return r, nil
	}
}

// observeOptions is what observeFactory builds the recorder with.
func observeOptions(rt *agent.RuleTable, bpfHash string, log *slog.Logger) observe.Options {
	return observe.Options{
		// The compiled table is what stamps each sample with the entry it matched and the verdict
		// that entry implies; the recorder decides nothing (§5 R8-R13).
		Rules: rt,
		// Nil Reader means open the pinned ring buffer under bpffs named by this hash, which is
		// the production path; a test injects its own reader instead. The build's pinned run set
		// opens with it: at Start the recorder reads the ring only when this run is the build's only
		// one, and then keeps to this run's slot (§2 "Run scope", §3 "Ring buffer").
		BPFHash: bpfHash,
		// Why a run's record could not be scoped, or which other run of the build holds the ring,
		// is detail a gap reason cannot carry. Both are warnings, which tego.log keeps at every
		// log.level. The process-cache line at debug is the one the machine's level decides.
		Logger: log,
		// A read error that ends the drain mid-run is the recorder's own gap (kernel-record-failed), and the
		// run goes on; the error itself is logged when it happens. It was set nowhere, so the error reached
		// tego.log only as the source's Stop error at shutdown.
		OnError: func(err error) {
			log.Error("observe: the kernel record stopped reading its ring buffer; the rest of the run is not recorded",
				"err", err)
		},
	}
}
