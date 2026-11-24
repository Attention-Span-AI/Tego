// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"

	"github.com/attention-span-ai/tego/internal/platform/hostaddr"
)

// routingCheck is doctor's line on the routing tables Tego does not read as this host's (hostaddr.LocalTable): a table
// that holds `local`, `broadcast` or `anycast` routes but that no policy rule the run's own traffic can match leads to
// (Cilium's `local default dev lo table 2004` behind a mark), or a policy-rule dump that could not be
// read. It is a fact about the host, never a tier's condition and never doctor's exit.
type routingCheck struct {
	// Unread is the tables' numbers, as LocalTable.Unread.
	Unread []uint32 `json:"unread_tables,omitempty"`
	// Words is the sentence, hostaddr.LocalTable.UnreadWords, or what could not be read.
	Words string `json:"words"`
}

// checkRouting reads the host's routing tables as a run's snapshot does (hostaddr.ReadLocalTable, unprivileged) and
// returns nil when every table with such routes is read. Rules that cannot be read are said as that: the run's checks
// then fail closed (the snapshot keeps its last table or reads the interfaces' addresses alone).
func checkRouting(read func() (hostaddr.LocalTable, error)) *routingCheck {
	t, err := read()
	if err != nil {
		return &routingCheck{Words: "the routing tables and policy rules could not be read (" + err.Error() +
			"); a net rule or block that names this host then counts only the interfaces' addresses, or the last tables read"}
	}
	if w := t.UnreadWords(); w != "" {
		return &routingCheck{Unread: t.Unread, Words: w}
	}
	return nil
}

// writeRoutingCheck writes the check as one line, the state "note", like the multicall line. A nil check writes nothing.
func writeRoutingCheck(w io.Writer, c *routingCheck) error {
	if c == nil {
		return nil
	}
	if _, err := fmt.Fprintf(w, "\nnote routing: %s\n", c.Words); err != nil {
		return fmt.Errorf("doctor: write routing: %w", err)
	}
	return nil
}
