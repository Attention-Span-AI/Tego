// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/doctor"
)

// TestDoctorSummaryNamesEveryCheck: `tego help`'s line for doctor names each of R27's nine probes, D9 swap
// included; it listed eight.
func TestDoctorSummaryNamesEveryCheck(t *testing.T) {
	summary := strings.ReplaceAll(strings.ToLower(cmdDoctor().Summary), " ", "")
	for _, id := range []doctor.CheckID{doctor.CheckKernel, doctor.CheckBTF, doctor.CheckCgroupV2,
		doctor.CheckLandlock, doctor.CheckSeccomp, doctor.CheckLSM, doctor.CheckPrograms, doctor.CheckFanotify,
		doctor.CheckSwap} {
		if !strings.Contains(summary, string(id)) {
			t.Errorf("doctor's summary %q does not name the %s check", cmdDoctor().Summary, id)
		}
	}
}
