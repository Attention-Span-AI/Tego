// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"

	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// ruleService is the dashboard's rule service for the ledger root root: it compiles every change as tego compiles a
// run (internal/control/rules check.go: the machine's profiles, the run's tier, run command grant and exec
// directories, the anchor), and refuses a contract under the served root, the machine's ledger root or tego's home.
// A nil machine config leaves the service without a compiler, which refuses every write.
func ruleService(root, anchor string, m *config.Machine) *rules.Service {
	s := &rules.Service{Ledger: root, Anchor: anchor, Machine: m}
	if m == nil {
		return s
	}
	s.Home = m.Home
	if mr, err := machineLedgerRoot(); err == nil && mr != "" && filepath.Clean(mr) != filepath.Clean(root) {
		s.Refuse = append(s.Refuse, mr)
	}
	if m.Home != "" {
		s.Refuse = append(s.Refuse, filepath.Join(m.Home, ".tego"))
	}
	return s
}
