// SPDX-License-Identifier: Apache-2.0

package rows

import (
	"crypto/sha256"
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
)

// TestStagedReadDifferential is the staged read's differential over a large corpus (ADR 0048 (3)): for every row and
// contract of prefixRows, every pair of its vocabulary and 1500 seeded vectors of up to 13 tokens, it decides every
// prefix and the whole vector. It counts the prefix decisions that are Final and do not refuse while the whole vector
// is refused (a first stage that would have let a refused exec run: must be 0), the Final non-refusals that differ
// from the whole vector in any other way (must be 0 too), and the Final refusals that differ (the fail-closed
// direction: a staged read refuses what the whole vector would not, allowed). It logs a hash of every whole-vector
// decision, so two trees can be shown to decide whole vectors alike.
//
// It decides about 6.5 million prefixes, so it runs only when TEGO_STAGED_DIFF is set (to 1, or to a file that gets
// one line per differing Final prefix decision):
//
//	TEGO_STAGED_DIFF=1 go test -count=1 -run TestStagedReadDifferential -v ./pkg/policy/execmatch/rows/
func TestStagedReadDifferential(t *testing.T) {
	env := os.Getenv("TEGO_STAGED_DIFF")
	if env == "" {
		t.Skip("TEGO_STAGED_DIFF is not set")
	}
	prs := prefixRows(t)
	rng := rand.New(rand.NewPCG(1111, 11))
	h := sha256.New()
	var lines []string
	decisions, failOpen, otherOpen, closed := 0, 0, 0, 0
	for _, pr := range prs {
		type vec struct {
			argv0 string
			toks  []string
		}
		var vecs []vec
		for _, a := range pr.vocab {
			for _, b := range pr.vocab {
				vecs = append(vecs, vec{pr.tool, []string{a, b}})
			}
		}
		for i := range 1500 {
			v := vec{pr.tool, make([]string, 1+rng.IntN(13))}
			if i%3 == 1 {
				v.argv0 = ""
			}
			for j := range v.toks {
				v.toks[j] = pr.vocab[rng.IntN(len(pr.vocab))]
			}
			vecs = append(vecs, v)
		}
		for ci, ix := range pr.ixs {
			for _, v := range vecs {
				f := prefixFacts(pr.tool, v.argv0, v.toks)
				whole := ix.Decide(&f)
				fmt.Fprintf(h, "%s|%v|%q|%s|%s\n", pr.tool, pr.contracts[ci], f.Argv, decided(whole), whole.Via)
				for k := range len(f.Argv) {
					decisions++
					p := f
					p.Argv, p.ArgvComplete = f.Argv[:k], false
					r := ix.Decide(&p)
					if !r.Final || r.Outcome == whole.Outcome && r.Rule() == whole.Rule() {
						continue
					}
					kind := "closed"
					switch {
					case r.Outcome == execmatch.OutcomeRefused:
						closed++
					case whole.Outcome == execmatch.OutcomeRefused:
						kind = "fail-open"
						failOpen++
					default:
						kind = "differs"
						otherOpen++
					}
					lines = append(lines, fmt.Sprintf("%s|%s|%v|%q|k=%d|prefix=%s|whole=%s", kind, pr.tool, pr.contracts[ci], f.Argv, k, decided(r), decided(whole)))
				}
			}
		}
	}
	if env != "1" {
		slices.Sort(lines)
		if err := os.WriteFile(env, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("%d prefix decisions; Final and not refused while the whole vector is refused: %d; other Final non-refusals that differ: %d; Final refusals that differ: %d; whole-vector hash %x",
		decisions, failOpen, otherOpen, closed, h.Sum(nil))
	if failOpen+otherOpen > 0 {
		t.Errorf("%d Final prefix decisions do not refuse and differ from the whole vector's (%d of them where it is refused)", failOpen+otherOpen, failOpen)
	}
}
