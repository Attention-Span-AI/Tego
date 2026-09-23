// SPDX-License-Identifier: Apache-2.0

// Package forwarder runs the plaintext localhost forwarder for agents with bundled TLS (Claude Code,
// Codex, uv Pythons): one loopback listener per declared models[] entry, each bound to one upstream,
// plaintext in and TLS out. It rewrites Host and SNI, adds the run's identity headers, narrows
// Accept-Encoding to the codings its record decodes with a decoder of fixed size, and forwards every other
// header and the body byte for byte, never buffers a response, answers HEAD /api/hello itself, and emits
// the same ssl_request/ssl_response pair the uprobe path emits for the same call.
//
// Imports: standard library net/http, internal/ledger (the header allow-list), internal/runtime/source (the
// run's Source contract), internal/runtime/ask (the approval broker's Request API, ask_hold.go),
// internal/runtime/capture/httpstream (the content-coding decoders, R15), internal/runtime/derive and
// derive/anthropic (the provider dispatch), internal/platform/{hostaddr,proc}, internal/modelroutes (the run's live
// route overlay, route.go, ADR 0127), pkg/policy/httppolicy, pkg/policy/modelroute, pkg/spec, golang.org/x/sys/unix.
// Must not import: cilium/ebpf; internal/runtime, launch, the supervisor, any enforce package, the DNS broker, the
// recorder, limits or the deputy (TestCaptureLinksNoEngine)
//
// It serves one run and no one else: a loopback bind is not an authorization, so before reading a
// connection's first byte the process on the other end is verified through /proc to belong to the run's
// cgroup subtree.
// Requests from anything else are answered 403 (R19a, CVE-2025-52882). When configured, HTTP/2 streams,
// CONNECT tunnels and WebSocket upgrades use the same peer admission and their own bounded policy paths.
//
// A models[] entry that declares routes (ADR 0127) may have its requests sent to one of them while the run lives:
// each request reads the run's route overlay (internal/modelroutes) and goes to the route a person put in force, with
// Host, SNI and certificate verification the route's, and its line names the route it took. The agent never chooses:
// it keeps calling the same listener, and the overlay is in the run directory it cannot write.
//
// It applies the compiled proxy request, tunnel and upgrade policy before upstream delivery, including
// configured request holds. Direct connections that bypass its base-URL variable still depend on the
// enforcement tier's compiled net.allow; a destination refusal there is enforce's net verdict=refused,
// not a capture gap (R38).
package forwarder
