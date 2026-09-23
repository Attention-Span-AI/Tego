// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"github.com/attention-span-ai/tego/internal/profilesrc"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// profileSources is the one profile source every load site reads `extends:` through (compile, run, drift and a
// registry entry's load; ADR 0066 D7): profilesrc.Chain, the machine config's profiles directory and the built-in
// sources, which the dashboard's rule writes build too, so the two binaries resolve a profile to the same bytes.
// A package that ships built-in profiles registers its source in profilesrc.Chain and nowhere
// else. TestOneProfileSourceConstructor fails for a load site that builds its own.
func profileSources(m *config.Machine) agent.ProfileSource {
	return profilesrc.Chain(m)
}

// sealedSources resolves every `extends:` name, a built-in one included, to an empty profile (sealedProfiles), for
// the reload of a canonical contract.yaml.
func sealedSources() agent.ProfileSource {
	return (&agent.ProfileChain{}).WithBuiltin(sealedProfiles{}).WithDir(sealedProfiles{})
}

// dirProfiles is the profiles directory's source, profilesrc.Dir (moved there so tego-control links it): <Root>/<name>.yaml
// and never outside Root (agent-contract.md E7), read through os.Root under the machine config's trust rule.
type dirProfiles = profilesrc.Dir
