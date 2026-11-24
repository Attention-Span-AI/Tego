// SPDX-License-Identifier: Apache-2.0

package ledgerview

// What the tests of what a run version keeps read.

func keptTallyCount(r *Run) int { return r.memo.tallies.len() }

// keptTallyTotal is the tallies of every version of the run the store still holds: only the newest.
func keptTallyTotal(r *Run) int { return r.memo.tallies.len() }

func keptGroupCount(r *Run) int { return r.memo.groups.len() }

func keptGroupTotal(r *Run) int { return r.memo.groups.len() }
