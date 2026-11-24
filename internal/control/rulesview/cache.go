// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/attention-span-ai/tego/internal/contracts"
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
//     digest of its every field), the PATH the compile looks programs up on and the state of each folder of it
//     (pathState), so a program installed or removed there is seen at the next view, not at the entry's age limit.
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
	// pathAt is the state of the PATH's folders (pathState): a program installed in one or removed from it moves it.
	pathAt string
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
		copy: stampOf(filepath.Join(root, id, ledger.ContractFile)), machine: machineSum(o.Machine), path: optionPATH(ctx, o)}
	k.pathAt = pathState(k.path)
	return drifted.Get(resultSlot(root, id), run, k, func() (*Drifted, bool) {
		d := driftRun(ctx, root, id, o)
		return d, d.Err == "" && ctx.Err() == nil
	})
}

func optionPATH(ctx context.Context, o Options) string {
	if o.Caller != nil {
		return o.PATH
	}
	return contracts.CallerContext(ctx).PATH
}

// maxPathDirs bounds the PATH folders pathState looks at.
const maxPathDirs = 64

// pathState is each folder of path, as the compile looks programs up in it: its identity, mode, owner and
// modification and change times (a name made in it, removed from it or renamed moves them), or that it is missing.
// A program made executable in place, or replaced by a write over its own file, moves none of them: the entry's age
// limit (ledgerview.maxResultAge) still bounds that. A relative or empty element is not a folder the compile reads
// the same way twice, and is left out.
func pathState(path string) string {
	var b strings.Builder
	n := 0
	for _, d := range filepath.SplitList(path) {
		if !filepath.IsAbs(d) {
			continue
		}
		if n++; n > maxPathDirs {
			break
		}
		var st syscall.Stat_t
		if err := syscall.Stat(d, &st); err != nil {
			fmt.Fprintf(&b, "%s:none|", d)
			continue
		}
		fmt.Fprintf(&b, "%s:%d:%d:%o:%d:%d.%d:%d.%d|", d, st.Dev, st.Ino, st.Mode, st.Uid, st.Mtim.Sec, st.Mtim.Nsec, st.Ctim.Sec, st.Ctim.Nsec)
	}
	return b.String()
}
