// SPDX-License-Identifier: Apache-2.0

package agent

// PinsUprobe reports whether the contract itself asked for capture: uprobe, rather than reaching uprobe through
// auto (Compile resolves auto to the highest mode the machine and tier allow, so rt.Capture alone cannot tell
// the two apart).
//
// The difference is whether the forwarder runs. capture: uprobe asks for the agent's own TLS to be read where
// OpenSSL encrypts it, with nothing proxied (FEATURES kill test 7 (b), "a system-Python agent via uprobes"):
// the forwarder then neither runs nor sets its base-URL variables, because a harness that honours
// ANTHROPIC_BASE_URL would send every request to the forwarder's loopback listener, whose upstream TLS is the
// launcher's and outside the run's cgroup, and the probes would see none of it. auto at a tier that runs
// uprobes runs the forwarder beside them (P0-DESIGN §2.9), so a harness whose TLS no probe can read (Claude
// Code's static BoringSSL) is still captured. capture.Select starts the sources by this.
//
// Compile leaves the forwarder's variables to a pinned-uprobe contract when the capture it resolved is uprobe
// (the tier it resolved runs uprobes and no machine ceiling lowered capture), and that is only a prediction: an
// unpinned tier resolves to the machine's ceiling without probing the machine. A run whose tier runs no uprobes
// (landlock, which every unprivileged run gets, or --observe) tops out at the forwarder (AtTier,
// capture.Select), and the forwarder's base URL is written over the contract's value (identity.Env.Apply).
// `tego run` says so on stderr with env-runtime-reserved once it knows the forwarder started, and only where
// Compile resolved uprobe (internal/cli warnForwarderEnv), so the warning follows what runs, not what Compile
// guessed, and never repeats the one Compile gave when it lowered capture itself (agent-contract R12).
//
// The merged contract is read, so a profile the contract extends pins it the same way.
func (rt *RuleTable) PinsUprobe() bool {
	return rt != nil && rt.Contract != nil && rt.Contract.Capture == CaptureUprobe
}
