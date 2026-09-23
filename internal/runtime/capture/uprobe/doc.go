// SPDX-License-Identifier: Apache-2.0

// Package uprobe attaches uprobes to SSL_write, SSL_write_ex2 or SSL_write_ex, SSL_read and SSL_read_ex in
// the libssl a process maps, filtered in the kernel by run-set membership and here by the run's own slot, and
// streams plaintext chunks keyed by SSL pointer.
//
// It is one source.Source and a source.KernelFollower: the run names the build the tier-2 handle pinned and
// feeds it the kernel record's execs, opens and exits, which is what places and removes the probes; Start
// loads the capture object under that build's pins, places the probes on the host's own libssl before the
// run's first process exists (preattach; not under record: off), opens the capture ring buffer and drains it into a
// httpstream.Assembler that turns chunks into ssl_request/ssl_response events; every process this package could not capture, and
// every connection reassembly could not follow, leaves a gap rather than a silence (§8 I4). Nothing here
// decides anything — a connection that escapes capture is enforce's refusal, never this package's (R38).
//
// Discovery, symbol choice and the attach cache are all testable with no kernel at all: the ELF reader
// works on ordinary files, /proc is injected, and the attacher is an interface. What needs root is only the
// last step, attaching, and its tests are behind the integration tag.
//
// Imports: internal/bpf, internal/ledger, internal/platform/proc, internal/runtime/source (the run's Source
// contract, ADR 0031 (b) step 1), internal/runtime/capture/httpstream, internal/runtime/cgroup,
// internal/runtime/derive, internal/runtime/derive/anthropic, internal/runtime/hoststate, pkg/spec/agent,
// pkg/spec/identity, pkg/spec/record,
// github.com/cilium/ebpf (with its link and ringbuf packages), and from the standard library net (SplitHostPort) and net/http (the Method
// constants) in events.go, which is all either is for
// Must not import: net/http for anything but those constants (no client, server or transport); internal/runtime,
// launch, the supervisor, any enforce package, the DNS broker, the recorder, limits, the deputy or the approval
// broker (TestCaptureLinksNoEngine)
package uprobe
