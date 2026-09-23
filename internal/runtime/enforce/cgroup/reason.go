// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// reasonToCode and codeToReason are the one translation between the kernel's numeric reason index and the
// closed set of spec/reason/REASON-CHANNEL.md. The kernel never carries strings, and userspace never invents
// a reason the kernel did not report, so the two tables must stay exact inverses of each other — reason_test
// asserts that.
var (
	reasonToCode = map[record.Reason]bpf.ReasonCode{
		record.ReasonWriteOutsideContract:  bpf.ReasonWriteOutsideContract,
		record.ReasonDeleteOutsideContract: bpf.ReasonDeleteOutsideContract,
		record.ReasonRenameOutsideContract: bpf.ReasonRenameOutsideContract,
		record.ReasonMkdirOutsideContract:  bpf.ReasonMkdirOutsideContract,
		record.ReasonReadDenied:            bpf.ReasonReadDenied,
		record.ReasonPathUnresolved:        bpf.ReasonPathUnresolved,
		record.ReasonExecNotAllowed:        bpf.ReasonExecNotAllowed,
		record.ReasonNetNotAllowed:         bpf.ReasonNetNotAllowed,
		record.ReasonNetHTTP:               bpf.ReasonNetHTTP,
	}
	codeToReason = func() map[bpf.ReasonCode]record.Reason {
		out := make(map[bpf.ReasonCode]record.Reason, len(reasonToCode))
		for r, c := range reasonToCode {
			out[c] = r
		}
		return out
	}()
)

// kernelReason maps a kernel reason byte back to the ledger's code. An unknown byte yields "" rather than a guess:
// a decoder that gets one records the event without a reason and raises a gap.
func kernelReason(c bpf.ReasonCode) record.Reason {
	return codeToReason[c]
}
