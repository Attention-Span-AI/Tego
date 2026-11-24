// SPDX-License-Identifier: Apache-2.0

package askproto

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestLocalRolesProtocolRefusalAndActor(t *testing.T) {
	raw, err := json.Marshal(Response{Error: ErrOwnerOnly.Error(), Code: Code(ErrOwnerOnly)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeResponse(raw)
	if !errors.Is(err, ErrOwnerOnly) || !strings.Contains(err.Error(), "root from a terminal outside any governed run") {
		t.Fatalf("refusal: %v", err)
	}
	d := Decision{AskID: "q-0123456789abcdef0123456789abcdef", Approved: true, By: "uid:0 pid:42", AnswerAuthority: AnswerAuthority{Actor: &LocalApprovalActor{PID: 42, StartBootNS: 10, UserNamespace: InitialUserNamespace, Source: "kernel-local-uid", Role: "owner"}}}
	raw, err = json.Marshal(Response{Decision: &d})
	if err != nil {
		t.Fatal(err)
	}
	r, err := DecodeResponse(raw)
	if err != nil || r.Decision.Actor == nil || r.Decision.Actor.Validate() != nil {
		t.Fatalf("actor: %+v %v", r, err)
	}
	// Client-supplied identity is never an accepted command field.
	_, err = DecodeCommand([]byte(`{"nonce":"0123456789abcdef0123456789abcdef","action":"answer","ask_id":"q-0123456789abcdef0123456789abcdef","approve":true,"actor":{"uid":0,"role":"owner"}}`))
	if !errors.Is(err, ErrProtocol) {
		t.Fatal("accepted claimed actor")
	}
}
