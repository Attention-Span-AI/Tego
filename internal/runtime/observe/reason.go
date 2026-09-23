// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The reason index table. struct tego_hdr carries `__u8 reason`, enum tego_reason_code of
// bpf/include/events.h, because a BPF program cannot carry strings; this table maps the kernel's numbers to
// record.Reason. It is the kernel's numbering, internal/bpf.ReasonCode, and nothing else: it once numbered
// record.Reasons in their own order, which agreed with the kernel up to 7 and named 8 and up after other codes
// (8, the kernel's net-not-allowed, read exec-gate). TestReasonTableIsEventsH reads events.h itself so the two
// cannot drift again.
//
// Index 0 is "no reason", the value every allowed or merely observed event carries. The decision plane's own
// codes (refer, deny-write-ancestor, identity-mismatch) name no v1 reason code and are not here: a plane refusal
// is named from the hook and op (planeFS, planeExecReason), with its cause in plane_reason.
const (
	ReasonNone                  = uint8(bpf.ReasonNone)
	ReasonWriteOutsideContract  = uint8(bpf.ReasonWriteOutsideContract)
	ReasonDeleteOutsideContract = uint8(bpf.ReasonDeleteOutsideContract)
	ReasonRenameOutsideContract = uint8(bpf.ReasonRenameOutsideContract)
	ReasonMkdirOutsideContract  = uint8(bpf.ReasonMkdirOutsideContract)
	ReasonReadDenied            = uint8(bpf.ReasonReadDenied)
	ReasonPathUnresolved        = uint8(bpf.ReasonPathUnresolved)
	ReasonExecNotAllowed        = uint8(bpf.ReasonExecNotAllowed)
	ReasonNetNotAllowed         = uint8(bpf.ReasonNetNotAllowed)
	ReasonNetHTTP               = uint8(bpf.ReasonNetHTTP)
)

// reasonByIndex is the index table itself, position i holding the code kernel number i names.
var reasonByIndex = [...]record.Reason{
	ReasonNone:                  "",
	ReasonWriteOutsideContract:  record.ReasonWriteOutsideContract,
	ReasonDeleteOutsideContract: record.ReasonDeleteOutsideContract,
	ReasonRenameOutsideContract: record.ReasonRenameOutsideContract,
	ReasonMkdirOutsideContract:  record.ReasonMkdirOutsideContract,
	ReasonReadDenied:            record.ReasonReadDenied,
	ReasonPathUnresolved:        record.ReasonPathUnresolved,
	ReasonExecNotAllowed:        record.ReasonExecNotAllowed,
	ReasonNetNotAllowed:         record.ReasonNetNotAllowed,
	ReasonNetHTTP:               record.ReasonNetHTTP,
}

// ReasonFor maps a kernel reason number to its record.Reason. Index 0 and every number this table does not name
// yield "" and false: an unknown number is recorded as a reasonless event plus a gap, never as a guessed code.
func ReasonFor(index uint8) (record.Reason, bool) {
	if int(index) >= len(reasonByIndex) || reasonByIndex[index] == "" {
		return "", false
	}
	return reasonByIndex[index], true
}
