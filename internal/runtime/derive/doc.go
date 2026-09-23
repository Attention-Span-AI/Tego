// SPDX-License-Identifier: Apache-2.0

// Package derive turns captured bytes into decisions, steps and attribution: it dispatches an exchange
// by its declared provider or upstream host to a provider parser, turns tool_use blocks and unreadable
// bodies into decision events, numbers a run's model turns as steps by time (E28a) and stamps the
// attribution every action event carries.
//
// Imports: internal/runtime/derive/*, pkg/spec
// Must not import: cilium/ebpf, net/http server
//
// It owns no bytes: capture assembles and blobs them, derive only reads what it is handed. The
// transport-neutral Message here is what both capture paths produce, so a parser never learns whether
// the uprobes or the forwarder saw the exchange.
package derive
