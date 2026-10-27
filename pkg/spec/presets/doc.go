// SPDX-License-Identifier: Apache-2.0

// Package presets holds tego's built-in presets, the profiles a contract extends by name under the reserved tego/
// namespace (ADR 0068, ADR 0066 D2): tego/no-secrets, tego/no-prod and tego/repo-only-writes, each in numbered
// revisions, and the host groups tego init expands into net.allow entries. It is data: the YAML files beside this
// one, embedded in the binary, and a Source that serves them by name in the shape of agent.ProfileSource, which the
// CLI's composition root registers on its agent.ProfileChain by one call line (internal/cli profileSources).
//
// A name without a pin (tego/no-secrets) is the newest revision; a pinned name (tego/no-secrets@1) is that revision
// alone. A released revision is frozen: a change is a new revision, and TestReleasedRevisionsAreFrozen holds every
// released revision's bytes to the sha256 recorded for it (README.md).
//
// Imports: the standard library only (embed among it).
// Must not import: anything under internal/, any other pkg/spec package (depguard presets-are-data).
package presets
