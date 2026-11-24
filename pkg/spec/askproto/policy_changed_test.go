// SPDX-License-Identifier: Apache-2.0

package askproto

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestApprovalPolicyChangedWireRefusal(t *testing.T) {
	raw, err := json.Marshal(Response{Error: "ask: the approval policy file changed since this run started", Code: "approval-policy-changed"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeResponse(raw)
	if err == nil || Code(err) != "approval-policy-changed" || !strings.Contains(err.Error(), "tego stop <run>") || !strings.Contains(err.Error(), "relaunch with the same ledger configuration") {
		t.Fatalf("changed policy wire refusal lost recovery: %v (code %s)", err, Code(err))
	}
}
