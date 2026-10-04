// SPDX-License-Identifier: Apache-2.0

package agent_test

// This package's tests answer RuleTable.Evaluate and TestTable.Run through the decision core, which registers
// itself when linked (RegisterDecider, ADR 0028). The in-package tests cannot import it, since it imports this
// package; an external test file can, and links it into the same test binary. It is the one file under
// pkg/spec that imports internal (.golangci.yml, spec-is-pure).
import _ "github.com/attention-span-ai/tego/internal/policy/decide"
