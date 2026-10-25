// SPDX-License-Identifier: Apache-2.0

package askclient

import (
	"strings"

	"github.com/attention-span-ai/tego/internal/ledger"
)

// LedgerTarget is the target an ask, answer or first_write refusal line records for a held request of operation op
// on target: the one function behind the runtime's lines, the broker's list and detail and
// tego-control's cards (TestLedgerTargetSingleSource).
// These lines are the audit record of what a human was shown and granted, so a filesystem path or connect
// destination stays exact, as the fs/net action it governs records it (record-ledger R9a: fs paths remain
// unchanged). Only a forwarder request target, "authority METHOD path", has its path projected onto R9a's public
// routes; the authority is the declared model's and the method a token. A malformed request target keeps nothing.
func LedgerTarget(op, target string) string {
	if op != "http_request" {
		return target
	}
	authority, rest, ok := strings.Cut(target, " ")
	method, path, ok2 := strings.Cut(rest, " ")
	if !ok || !ok2 || authority == "" || method == "" {
		return "/" + ledger.RedactedValue
	}
	return authority + " " + method + " " + ledger.RedactTarget(path)
}
