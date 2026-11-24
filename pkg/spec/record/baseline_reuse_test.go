// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"testing"
)

func TestBaselineDecodePayloadSyntaxErrorClearsEvidence(t *testing.T) {
	_, p := baselineStartFixture(t)
	e := Event{Kind: KindRunStart, Payload: json.RawMessage(`{"record_minor":`)}
	if err := e.DecodePayload(&p); err == nil {
		t.Fatal("syntax error accepted")
	}
	if p.Baseline != nil || p.EffectiveHash != "" {
		t.Fatal("syntax error retained earlier evidence")
	}
}
