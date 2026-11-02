// SPDX-License-Identifier: Apache-2.0

// Package drift computes declared versus done per rule, unused MCP servers and skills, and config drift by contract hash.
// A declared MCP server is unused only in a run whose record could have shown it start; otherwise it is
// reported as unobservable (docs/p0/limits-check-doctor-cli.md R15). The report carries the gap line (R34), and lists
// the images the run's exec lines flagged fileless or dropped, whatever their verdict (R17a).
//
// Imports: internal/ledger, pkg/spec
// Must not import: internal/runtime
package drift
