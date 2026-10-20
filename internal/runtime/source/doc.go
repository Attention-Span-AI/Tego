// SPDX-License-Identifier: Apache-2.0

// Package source is the contract between a run and the producers it owns (ADR 0031 (b) step 1): Source and the
// Sink it emits into, the RunRef that names the run, the Gap a source reports, the process stream a kernel
// follower is fed (ProcessHook, ProcessStream, KernelFollower), the loopback facts of a forwarder
// (LoopbackSource), the optional sink extensions a capture source reports lost spend and abandoned requests
// through (MeteredSink, AbandonSink, ReportUnmetered, ReportAbandoned), UnavailableCause, and NewPair, the
// process-wide pair token of one captured exchange.
//
// internal/runtime implements the run side; capture/uprobe, the forwarder and the kernel recorder implement
// sources. Before this package they imported internal/runtime for these types, which linked the whole engine
// (launch, the supervisor, every backend, the DNS broker) into each capture source; no capture package links it
// now (TestCaptureLinksNoEngine), and this package links nothing under internal/ (TestSourceLinksNoInternal).
//
// Imports: pkg/spec/agent, pkg/spec/record and the standard library only.
// Must not import: any other tego package, internal/runtime above all (depguard source-is-a-leaf).
package source
