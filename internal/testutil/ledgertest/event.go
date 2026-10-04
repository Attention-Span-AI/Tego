// SPDX-License-Identifier: Apache-2.0

// Package ledgertest builds typed, validated events for tests. It does not invent
// ledger hashes or chain links; a real ledger writer remains responsible for them.
package ledgertest

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Event creates an unchained v1 event with deterministic identity and time.
// The caller's edit supplies action or terminal fields before validation.
func Event(t testing.TB, kind record.Kind, payload any, edit ...func(*record.Event)) *record.Event {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal %s payload: %v", kind, err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || object == nil {
		t.Fatalf("%s payload is not an object: %s", kind, data)
	}
	e := &record.Event{V: record.Version, TS: time.Unix(1_700_000_000, 0).UTC(), MonoNS: 1,
		Run: "r-fixture", Agent: "fixture", PID: 42, TID: 42, Kind: kind, Source: record.SourceSupervisor, Payload: data}
	for _, apply := range edit {
		apply(e)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("invalid %s fixture: %v", kind, err)
	}
	return e
}

// Decode decodes a produced event's typed payload with a useful failure message.
func Decode[T any](t testing.TB, event *record.Event) T {
	t.Helper()
	var value T
	if event == nil {
		t.Fatal("decode nil event")
	}
	if err := json.Unmarshal(event.Payload, &value); err != nil {
		t.Fatalf("decode %s payload %s: %v", event.Kind, event.Payload, err)
	}
	return value
}
