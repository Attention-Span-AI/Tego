// SPDX-License-Identifier: Apache-2.0

package record

import (
	"strconv"
	"unicode/utf8"
)

// MaxDetailBytes is the longest run_end detail a writer records. The detail is a cause for a person to read, and it
// can carry text from outside tego (an embedder's Started hook error, a worker's wrapped error): unbounded, it could
// make run_end longer than a ledger line may be, and the one line that ends the run unwritable.
const MaxDetailBytes = 4096

// CutDetail is detail as run_end records it: unchanged when it is at most MaxDetailBytes, else cut at a UTF-8
// character boundary and ended with " [cut N bytes]", N the bytes left out, the whole at most MaxDetailBytes. The cut
// is said, never silent, so a reader knows the cause was longer than what it reads.
func CutDetail(detail string) string {
	if len(detail) <= MaxDetailBytes {
		return detail
	}
	// The marker's number is at most len(detail)'s digits, so reserving that many bytes always fits it.
	room := MaxDetailBytes - len(" [cut  bytes]") - len(strconv.Itoa(len(detail)))
	for room > 0 && !utf8.RuneStart(detail[room]) {
		room--
	}
	return detail[:room] + " [cut " + strconv.Itoa(len(detail)-room) + " bytes]"
}
