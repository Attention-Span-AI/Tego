// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// The Least privilege and Unused permissions tabs read the whole run (and Unused compiles its contract) on every
// request: about 2 s and 1 s for a run of 100k lines. Each result is kept per run in a bounded cache
// (ledgerview.Results, which holds the rules: the run's events file stamped, a live run's costly result reused for
// at most 2 s, every result for at most 5 min) under a key of everything else it reads:
//
//   - Learn: the chain anchor's path and the anchor file's identity, size and mtime (the proposal keeps tego's own
//     directories, the anchor's among them, out of it).
//   - Drift: the same, the run's contract copy (contract.yaml), the machine config the copy compiles against (a
//     digest of its every field) and the PATH the compile looks programs up on.
//
// A result that failed (an error, the request cancelled) is not kept.

// maxResults bounds each cache: the runs whose tabs were opened last.
const maxResults = 64

type learnKey struct {
	anchor   string
	anchorAt fileStamp
}

type driftKey struct {
	learnKey
	copy    fileStamp
	machine [sha256.Size]byte
	path    string
}

var (
	learned = ledgerview.NewResults[learnKey, *Learned](maxResults, false)
	drifted = ledgerview.NewResults[driftKey, *Drifted](maxResults, false)
)

// resultSlot is the cache slot of run id under root.
func resultSlot(root, id string) string { return filepath.Clean(root) + "\x00" + id }

// machineSum is a digest of every field of m: a machine config read again with other values is another key. A
// pointer field prints as its address, so an equal config loaded again may miss once, never match wrongly.
func machineSum(m *config.Machine) [sha256.Size]byte {
	if m == nil {
		return [sha256.Size]byte{}
	}
	return sha256.Sum256(fmt.Appendf(nil, "%#v", *m))
}

// cachedLearn is Learn through the cache.
func cachedLearn(ctx context.Context, root, anchor, id string) *Learned {
	run, ok := ledgerview.StampRun(root, id)
	if !ok {
		return learnRun(ctx, root, anchor, id)
	}
	return learned.Get(resultSlot(root, id), run, learnKey{anchor: anchor, anchorAt: stampOf(anchor)}, func() (*Learned, bool) {
		l := learnRun(ctx, root, anchor, id)
		return l, l.Err == "" && ctx.Err() == nil
	})
}

// cachedDrift is Drift through the cache.
func cachedDrift(ctx context.Context, root, id string, o Options) *Drifted {
	run, ok := ledgerview.StampRun(root, id)
	if !ok {
		return driftRun(ctx, root, id, o)
	}
	k := driftKey{learnKey: learnKey{anchor: o.Anchor, anchorAt: stampOf(o.Anchor)},
		copy: stampOf(filepath.Join(root, id, ledger.ContractFile)), machine: machineSum(o.Machine), path: os.Getenv("PATH")}
	return drifted.Get(resultSlot(root, id), run, k, func() (*Drifted, bool) {
		d := driftRun(ctx, root, id, o)
		return d, d.Err == "" && ctx.Err() == nil
	})
}
