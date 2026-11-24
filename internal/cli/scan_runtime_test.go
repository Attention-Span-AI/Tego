// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/scan"
)

func TestScanAdvancedRuntimeQuotaOverrideBeforeInputs(t *testing.T) {
	for _, tc := range []struct {
		name, debug string
		refuse      bool
	}{
		{"default", "", false}, {"other knob", "http2client=0", false},
		{"closed quota", "containermaxprocs=0", false},
		{"last zero", "containermaxprocs=1,containermaxprocs=0", false},
		{"retained quota", "containermaxprocs=1", true},
		{"last one", "containermaxprocs=0,containermaxprocs=1", true},
		{"invalid after one", "containermaxprocs=1,containermaxprocs=oops", true},
		{"overflow ignored", "containermaxprocs=4294967296", false},
		{"overflow after one", "containermaxprocs=1,containermaxprocs=4294967296", true},
		{"invalid ignored", "containermaxprocs=oops", false},
		{"signed zero", "containermaxprocs=+0", false},
		{"negative closes", "containermaxprocs=-1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GODEBUG", tc.debug)
			o, collect := fixtureAdvancedCommand(t)
			originalInputs := scanInputs
			t.Cleanup(func() { scanInputs = originalInputs })
			inputs, collections := 0, 0
			scanInputs = func() scan.Options { inputs++; return o }
			scanCollect = func(ctx context.Context, requested scan.Options) scan.Outcome {
				collections++
				return collect(ctx, requested)
			}
			scanDrop = func(uint32, uint32) error { return nil }
			for _, check := range []bool{false, true} {
				args := []string{"scan", "--advanced", "--json"}
				if check {
					args = append(args, "--check")
				}
				code, out, errs := run(t, args...)
				if tc.refuse {
					if code != 125 || inputs != 0 || collections != 0 || !strings.Contains(errs, "GODEBUG=containermaxprocs=0") {
						t.Fatalf("runtime override reached source inputs: exit%d inputs%d collections%d", code, inputs, collections)
					}
				} else if code == 125 {
					t.Fatalf("safe runtime setting refused: %d %s %s", code, out, errs)
				}
			}
		})
	}
}
