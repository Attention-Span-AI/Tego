// SPDX-License-Identifier: Apache-2.0

// Package api holds the interfaces through which a prepared enforcement handle is consumed: Handle (the
// child stage's ruleset fd and seccomp filter, the facade's attach, detach and close), and the optional
// Armer, Listener and ListenerWaiter a tier's handle implements when its kernel state or its loop has a
// place in the run's lifetime (ADR 0031 (a)). internal/runtime/enforce selects and prepares the tiers and
// returns their handles as an api.Handle; internal/runtime/launch, which starts the agent's first
// process, sees a handle only through this package and so links no backend, no cilium/ebpf and no
// policy type (TestLaunchLinksNoBackend).
//
// The richer optional Handle extensions (KernelRecorder, NetRefresher, KernelNetReader and the rest) stay in
// internal/runtime/enforce: they name pkg/spec types, and only the engine type-asserts them.
//
// Imports: golang.org/x/net/bpf and the standard library only.
// Must not import: any tego package.
package api
