// SPDX-License-Identifier: Apache-2.0

package receipt

// The receipt's activity sections: where the run connected, the programs it ran and the secret-looking files it read.

// Verdicts counts what happened to the tries of one action: recorded only (a watched run decides nothing), allowed
// by a rule, or refused.
type Verdicts struct {
	Observed int `json:"observed"`
	Allowed  int `json:"allowed"`
	Refused  int `json:"refused"`
}

// Connection is one destination the run connected to (ip:port, name:port when the line names the host, or
// unix:<path>), how many times it tried, and what happened to those tries.
type Connection struct {
	Destination string   `json:"destination"`
	Count       int      `json:"count"`
	Verdicts    Verdicts `json:"verdicts"`
	// Sends is how many of Count were UDP datagrams the run sent (record.NetOpSend); the rest are connects, and a UDP
	// connect sends nothing. Absent when none was, and for a ledger from before the op, where a send counts as a connect.
	Sends int `json:"sends,omitempty"`
}

// Program is one program the run started, by path, and how many times.
type Program struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}

// SensitiveRead is one secret-looking or rule-guarded file the run opened or tried to, and what happened to the
// tries.
type SensitiveRead struct {
	Path     string   `json:"path"`
	Verdicts Verdicts `json:"verdicts"`
}

// Total is every try counted.
func (v Verdicts) Total() int { return v.Observed + v.Allowed + v.Refused }
