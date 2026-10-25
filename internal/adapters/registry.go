// SPDX-License-Identifier: Apache-2.0

package adapters

import (
	"github.com/attention-span-ai/tego/internal/adapters/claudecode"
	"github.com/attention-span-ai/tego/pkg/spec/harness"
)

// Provisioner provisions one harness for one run: the method set internal/runtime's Provisioner names, declared here
// because an adapter never imports the engine.
type Provisioner interface {
	Provision(harness.Run) (harness.Provision, error)
}

// provisioners holds one entry per harness this build provisions; an adapter package adds its row.
var provisioners = map[harness.Name]Provisioner{
	harness.ClaudeCode: claudecode.Provisioner{},
}

// For is the provisioner for a resolved harness name, nil when this build has none (auto and none are never
// provisioned: the launcher resolves auto first and provisions nothing for none).
func For(name harness.Name) Provisioner {
	if name == harness.Auto || name == harness.None {
		return nil
	}
	return provisioners[name]
}
