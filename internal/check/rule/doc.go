// SPDX-License-Identifier: Apache-2.0

// Package rule changes a contract's rules, as text, for the next run. It has two entries:
//
//   - Apply turns one thing a run did into a rule (tego rule, the dashboard's event page): a contract's text, one
//     ledger event of a run of it and an action (block, ask or allow) give the new text, a summary, a line diff and
//     the change's Direction. A line an ask entry decided (asked, approved, denied, timed out) blocks as "never":
//     at the entry's own scope an fs.ask_read entry moves to fs.deny_read with the same spelling, an fs.ask or
//     net.ask entry goes; a narrower scope refuses that path alone (EntryLevel is the entry's scope).
//   - ApplyEdits makes structured edits (the dashboard's Change rules form, tego rules edit): one entry added to or
//     removed from one of eight lists, or "never" on an ask entry. It refuses an entry the file does not spell, the
//     first entry of an absent net: section or exec.allow list, and an entry that would break its line, and it says
//     each change in words (Asks you before it reads X → Can never read X) with Narrows, Widens or Mixed, from a
//     lexical model of the file (direction.go) that a page confirms a widening by.
//
// The edit is made on the YAML node tree, so the file's comments and key order are kept; where the change is one
// list item added to or removed from a block list the text is spliced line by line and every other byte is kept.
// An added line carries "# from run <id> line #N, <date>" (Apply) or "# added via <via>, <date>" (ApplyEdits).
//
// What it never does: widen past the one path, program or host the event names (a folder only when the caller asks
// for it, and then the event's own directory), lift an entry the top-level file does not spell (a built-in
// protection, a profile's entry), switch exec: to deny-list mode, add the first entry of a net: section or an
// exec.allow list, or return a contract the caller's compiler refuses. Nothing here does I/O or reads a clock: the
// caller passes the date and the compiler (Request.Check, EditRequest.Check, which ApplyEdits requires).
//
// Imports: pkg/spec/record, pkg/spec/agent (the built-in deny_read list), pkg/policy/execmatch, yaml.v3.
// Must not import: internal/runtime, internal/ledger, anything that does I/O.
package rule
