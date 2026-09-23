// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// CaptureModeOf is run_start.capture for a set of capture sources that have already been started, for the
// external test that drives a real uprobe source: that package imports this one, so only a runtime_test file
// can hold both.
func CaptureModeOf(compiled agent.CaptureMode, started []source.Source) string {
	r := &runner{deps: Deps{Capture: started}, rt: &agent.RuleTable{Capture: compiled}}
	return r.captureMode()
}
