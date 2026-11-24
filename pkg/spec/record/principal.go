// SPDX-License-Identifier: Apache-2.0

package record

// validateAnswerPrincipal retains the unwritten team principal reservation when
// a later writer revision raises the reader ceiling. It grants no approval.
func validateAnswerPrincipal(minor int, raw []byte) error {
	if err := belowMinor("answer.principal", true, minor, MinorPrincipal); err != nil {
		return err
	}
	var principal string
	if err := decodeField("answer.principal", raw, &principal); err != nil {
		return err
	}
	if !stoppedByRe.MatchString(principal) {
		return fieldErr("principal", "answer.principal", "not a team principal reference")
	}
	return nil
}
