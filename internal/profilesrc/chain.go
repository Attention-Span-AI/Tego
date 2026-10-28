// SPDX-License-Identifier: Apache-2.0

package profilesrc

import (
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/presets"
)

// Chain is the one profile source every load site reads `extends:` through, in tego and in tego-control: an
// agent.ProfileChain holding the machine config's profiles directory, which serves every name outside tego/, and the
// built-in sources, which alone serve the names under it. A package that ships built-in profiles registers its
// source here by one call line, `c.WithBuiltin(<source>)`, and nowhere else, so the dashboard's compile never drifts
// from the engine's; the presets (pkg/spec/presets, ADR 0068) are registered. internal/cli's
// TestOneProfileSourceConstructor fails for a load site that builds its own, and
// TestProfileSourcesIsTheSharedChain for a source registered in internal/cli's profileSources instead of here. A
// built-in source must not import the engine (.golangci.yml linked-into-control-never-imports-engine).
func Chain(m *config.Machine) agent.ProfileSource {
	c := &agent.ProfileChain{}
	c.WithBuiltin(presets.Source{})
	root := ""
	if m != nil {
		root = m.Profiles.Value
	}
	c.WithDir(Dir{Root: root})
	return c
}
