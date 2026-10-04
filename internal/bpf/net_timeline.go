// SPDX-License-Identifier: Apache-2.0

package bpf

import "structs"

const (
	MapNetTimeline  = "tego_net_timeline"
	MaxNetIntervals = 16
)

type NetTimelineKey struct {
	_             structs.HostLayout
	RunIdx, Index uint32
}

// NetDecision is one composed verdict until its exclusive monotonic deadline.
// The final decision has deadline zero and remains valid without a refresh.
type NetDecision struct {
	_               structs.HostLayout
	Verdict, Reason uint8
	RuleIdx         uint16
	Pad             uint32
	DeadlineNS      uint64
}

type NetTimeline struct {
	_          structs.HostLayout
	Count, Pad uint32
	Steps      [MaxNetIntervals]NetDecision
}
