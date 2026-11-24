// SPDX-License-Identifier: Apache-2.0

package receipt

// MadeBy names the tego that made a receipt (binding.receipt_by) or checked one (checked_by), by its version and commit
// as `tego version` prints them.
type MadeBy struct {
	TegoVersion string `json:"tego_version"`
	Commit      string `json:"commit"`
}

// Binding ties a receipt to the record it was computed from, so a copy of the receipt can be checked against a copy of
// the record on any machine (`tego receipt --check`). It binds; it vouches for nothing: Limits says what it rests on.
// Only `tego receipt --json` sets it (Options.Bind).
type Binding struct {
	V int `json:"v"`
	// ReceiptSHA256 commits to every receipt value except this digest itself. It detects edits, not authorship.
	ReceiptSHA256          string          `json:"receipt_sha256,omitempty"`
	EffectiveHash          string          `json:"effective_hash,omitempty"`
	BaselineSHA256         string          `json:"baseline_sha256,omitempty"`
	BaselineEvidenceSHA256 string          `json:"baseline_evidence_sha256,omitempty"`
	ContractHash           string          `json:"contract_hash,omitempty"`
	Capabilities           map[string]bool `json:"capabilities,omitempty"`
	// BinarySHA256 identifies the producer image; another architecture's checker need not have the same hash.
	BinarySHA256 string `json:"binary_sha256,omitempty"`
	// Chain is the record as the receipt's own pass read it; nil when the chain did not hold, with Error saying why.
	Chain *BoundChain `json:"chain,omitempty"`
	// ReceiptBy is the tego that computed the receipt: a check compares numbers only when it is the same build.
	ReceiptBy MadeBy `json:"receipt_by"`
	// Limits is a fixed list of codes (the Limit constants), each with its words.
	Limits []Limit `json:"limits"`
	// Error is why no chain is bound: a line that breaks the chain or fails validation, with its number.
	Error string `json:"error,omitempty"`
}

// BoundChain is the record a receipt was computed from: the run every line names, how many complete lines chained,
// the last one's id (head) and whether it is run_end, as `tego events --verify` counts them; and the size and sha256
// of every byte read (each complete line with its "\n" when it has one, then a torn tail), so for a record at rest
// sha256 is what sha256sum prints for events.jsonl.
type BoundChain struct {
	Run        string `json:"run"`
	Lines      uint64 `json:"lines"`
	Head       string `json:"head"`
	Ended      bool   `json:"ended"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256"`
	TornBytes  int    `json:"torn_bytes"`
	NewerLines int    `json:"newer_lines"`
}

// Limit is one thing a bound receipt and its check rest on, as a code a program can match and words a person reads.
type Limit struct {
	Code string `json:"code"`
	Why  string `json:"why"`
}

// BindingVersion is binding.v, the shape of the binding block this tego writes and reads. A check cannot check a
// binding of a version it does not read.
const BindingVersion = 2

// BaselineBindingVersion adds dual hashes and machine evidence without changing older bindings.
const BaselineBindingVersion = 3

// The limit codes. A code never changes; its words may.
const (
	// LimitLaunchingUser: the user who started the run can rewrite the record and the receipt together (always).
	LimitLaunchingUser = "launching-user-can-rewrite"
	// LimitRecordOnly: the run was watched (tier observe), so the agent itself could rewrite the record.
	LimitRecordOnly = "record-only"
	// LimitTailNotSynced: lines are not synced to disk during the run (always).
	LimitTailNotSynced = "tail-not-synced"
	// LimitNoSignature: no key vouches for the receipt or the record (always, until one does).
	LimitNoSignature = "no-signature"
)
