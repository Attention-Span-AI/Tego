// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestReasonRoundTrip asserts the two tables are exact inverses: a reason the kernel can carry must come back
// as the same ledger code, in both directions.
func TestReasonRoundTrip(t *testing.T) {
	t.Parallel()
	for r, c := range reasonToCode {
		if got := ReasonCode(r); got != c {
			t.Errorf("ReasonCode(%s) = %d, want %d", r, got, c)
		}
		if got := Reason(c); got != r {
			t.Errorf("Reason(%d) = %s, want %s", c, got, r)
		}
		if !r.Valid() {
			t.Errorf("%s is not a valid record.Reason", r)
		}
	}
	if len(codeToReason) != len(reasonToCode) {
		t.Fatalf("tables are not bijective: %d codes for %d reasons", len(codeToReason), len(reasonToCode))
	}
}

// TestReasonUnknown asserts an unmappable value is reported as absent, never as a wrong code. A limit reason
// has no kernel representation and an unknown byte has no ledger meaning.
func TestReasonUnknown(t *testing.T) {
	t.Parallel()
	for _, r := range []record.Reason{record.ReasonLimitTokens, record.ReasonAskDenied, record.Reason("nonsense")} {
		if got := ReasonCode(r); got != bpf.ReasonNone {
			t.Errorf("ReasonCode(%s) = %d, want ReasonNone", r, got)
		}
	}
	for _, c := range []bpf.ReasonCode{200, 255} {
		if got := Reason(c); got != "" {
			t.Errorf("Reason(%d) = %q, want the empty reason", c, got)
		}
	}
	if Reason(bpf.ReasonNone) != "" {
		t.Errorf("ReasonNone must map to no reason, got %q", Reason(bpf.ReasonNone))
	}
}

// TestEveryKernelCodeIsMapped asserts no reason byte the C header defines is left without a ledger code:
// bpf/include/events.h and this table are edited together or not at all.
func TestEveryKernelCodeIsMapped(t *testing.T) {
	t.Parallel()
	all := []bpf.ReasonCode{
		bpf.ReasonWriteOutsideContract, bpf.ReasonDeleteOutsideContract, bpf.ReasonRenameOutsideContract,
		bpf.ReasonMkdirOutsideContract, bpf.ReasonReadDenied, bpf.ReasonPathUnresolved,
		bpf.ReasonExecNotAllowed, bpf.ReasonNetNotAllowed, bpf.ReasonNetHTTP,
	}
	for _, c := range all {
		if Reason(c) == "" {
			t.Errorf("kernel reason code %d has no ledger reason", c)
		}
	}
	if len(all) != len(reasonToCode) {
		t.Fatalf("%d kernel codes, %d mapped reasons", len(all), len(reasonToCode))
	}
}
