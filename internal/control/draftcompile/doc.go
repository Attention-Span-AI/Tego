// SPDX-License-Identifier: Apache-2.0

// Package draftcompile bounds compilation of untrusted dashboard drafts. A short
// admission wait and two slots cap child processes; cancellation and a total
// compilation deadline kill the child, so compiler filesystem operations cannot
// hold the HTTP worker. A request shares three seconds of compilation and
// admission time across helper calls; publishing and syncing the reviewed file
// do not consume that budget and remain subject to request cancellation.
// The child runs the loader/compiler, using nextrun's offline resolver. It
// reads inherited profiles and machine layers and the paths strictly required by
// compilation (path identity, exec loaders and protected configuration). It never
// starts an agent or writes a contract. Kernel filesystem stalls are contained in
// the child; a slot stays occupied until that child has been reaped.
// The serving process supplies a compiler-pool identity across path helpers.
// Two abstract socket leases remain inherited until actual child exit, including
// when a parent helper is abandoned. No socket data is sent or read.
// Preset composition uses that same pool and deadline: setup.Compose probes
// project markers and client-named write paths only in the child. Its serialized
// result retains the contract bytes and public metadata setup.Create needs.
// Composition never creates the planned directories.
// The review digest covers the complete compiled data, including private matcher
// indexes and opaque DNS, HTTP, proxy and gate policies. Built-in grammar code
// uses stable slot identities within the service session; unknown callbacks are
// refused. The parent fingerprints immutable grammar once; its child registers
// the same references without rebuilding that declaration. Data-object addresses
// are used only to resolve trusted grammar refs and never enter the digest.
// Time values use their UTC instant, without process monotonic-clock state.
//
// Imports: standard library, gopkg.in/yaml.v3, internal/nextrun,
// internal/profilesrc, internal/platform/proc, internal/setup, pkg/spec, pkg/policy/execmatch.
// Must not import: decision engine, runtime, web, rules, ledger writers.
package draftcompile
