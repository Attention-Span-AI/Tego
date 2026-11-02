// SPDX-License-Identifier: Apache-2.0

package forwarder

// What this file exports, only this package's tests call.

// newProcAdmitter is an admitter with an exact lookup of its own (a test's).
func newProcAdmitter() *procAdmitter { return newProcAdmitterOn(newTCPDiag(nil)) }
