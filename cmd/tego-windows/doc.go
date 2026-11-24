// SPDX-License-Identifier: Apache-2.0

// Command tego-windows is the native Windows tego command. It carries arguments
// as base64 JSON to Tego's Linux, inside Windows, without a command shell. It
// also opens the dashboard in the person's browser through its relay mode
// (`tego.exe __relay <port>`, relay.go): a [::1] listener that admits only this
// Windows user's processes and carries their connections over one wsl.exe child
// to the dashboard (docs/adr/0123-dashboard-threat-model.md, "A browser on Windows").
// Imports: standard library, internal/platform/proc, internal/platform/winpeer, internal/relaymux,
// golang.org/x/sys/windows.
// Must not import: the Linux engine, dashboard, ledger or enforcement packages.
package main
