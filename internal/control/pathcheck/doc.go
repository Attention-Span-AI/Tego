// SPDX-License-Identifier: Apache-2.0

// Package pathcheck runs the dashboard's path-dependent operations in the same
// bounded, own-image helper as the command catalogue. Service threads never
// inspect recorded source paths or paths typed in the browser.
//
// Imports: internal/contracts and the standard library.
// Must not import: internal/runtime, internal/policy, internal/bpf, internal/cli.
package pathcheck
