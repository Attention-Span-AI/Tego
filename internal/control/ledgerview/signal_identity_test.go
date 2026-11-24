// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"fmt"
	"testing"
	"time"
)

// Equal line marks do not identify their source ledger. Separate stores can
// publish the same local revision, and a changed revision must also discard a
// live fold built from another file rather than treating its lines as a prefix.
func TestSignalSeparatesEqualRunVersionsInDifferentLedgers(t *testing.T) {
	for i, equalRevision := range []bool{true, false} {
		t.Run(fmt.Sprintf("equal-revision=%t", equalRevision), func(t *testing.T) {
			id := fmt.Sprintf("r-aaaaaaaa-0000000000092-ledgr%d", i)
			at := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
			const target = "/p/workpapers/plan.data"
			if IsSecretPath(target) {
				t.Fatal("fixture must require the contract's sensitive-path context")
			}
			roots := []string{t.TempDir(), t.TempDir()}
			start := line(id, "reader", 0, at, "run_start", `"tier":"landlock","command":["sh"],"cwd":"/p"`)
			// A refused action is counted by its refusal note. Keep just that
			// note here, so both records have exactly the same two line marks.
			writeRun(t, roots[0], id, start,
				line(id, "reader", 1, at.Add(time.Second), "refused", `"op":"open","target":"`+target+`","rule":"unmatched","reason":"read-denied"`))
			writeRun(t, roots[1], id, start,
				line(id, "reader", 1, at.Add(time.Second), "fs", `"op":"open","path":"`+target+`","flags":0,"verdict":"allow","rule":"unmatched"`))
			var versions []*Run
			for j, root := range roots {
				store := Open(root)
				// Store revisions are local, initially seeded by the clock. Pin
				// that seed to exercise both a cache hit and the live-fold path.
				store.mu.Lock()
				store.rev = 1000
				if !equalRevision {
					store.rev += uint64(j)
				}
				store.mu.Unlock()
				r, err := LoadRun(root, id)
				if err != nil {
					t.Fatal(err)
				}
				live := *r
				live.Live = true // Retain the fold without launching a process.
				versions = append(versions, &live)
			}
			a, b := versions[0], versions[1]
			if (a.Rev == b.Rev) != equalRevision {
				t.Fatalf("revision precondition: %d and %d", a.Rev, b.Rev)
			}
			if a.ID != b.ID || a.LastSeq != b.LastSeq || len(a.Events) != 2 || len(b.Events) != 2 ||
				markOf(&a.Events[0]) != markOf(&b.Events[0]) || markOf(&a.Events[1]) != markOf(&b.Events[1]) ||
				a.Live != b.Live || len(a.Pending) != len(b.Pending) {
				t.Fatal("fixture must hold every other cached version field and fold line mark equal")
			}
			if a.file.dev == b.file.dev && a.file.ino == b.file.ino {
				t.Fatal("fixture must use distinct events files")
			}
			sensitive := Sensitive{Entries: []string{"./workpapers/"}, Cwd: "/p"}
			for _, check := range []struct {
				name             string
				run              *Run
				allowed, refused int
			}{{"A", a, 0, 1}, {"B", b, 1, 0}, {"A again", a, 0, 1}} {
				sig := Signal(check.run, sensitive)
				if len(sig.Secrets) != 1 || sig.Secrets[0].Path != target ||
					sig.Secrets[0].Allowed != check.allowed || sig.Secrets[0].Refused != check.refused {
					t.Errorf("%s: got sensitive touches %+v; want allowed=%d refused=%d for its own ledger", check.name, sig.Secrets, check.allowed, check.refused)
				}
			}
		})
	}
}
