// SPDX-License-Identifier: Apache-2.0

// Package pricetable is the price table of spec/config/v0's `prices` setting: the versioned list of what each model
// costs per million tokens, its load under the machine config's trust rule (FromMachine), and the one lookup that
// prices a model response (PriceTable.Cost). It is a leaf both sides read: the engine's limits watcher prices a
// response against a cost budget with it (internal/runtime/limits aliases these names), and every reader of a receipt
// prices a run with it too (`tego receipt`, `tego measure` and the dashboard's Receipt tab, through Lazy), so one run
// has one cost wherever it is shown. A table that cannot be used prices nothing and says why (Warning); it never fails a
// run or a report.
//
// Imports: internal/ledger, pkg/spec/config, gopkg.in/yaml.v3. Must not import: internal/runtime, internal/control,
// internal/cli.
package pricetable
