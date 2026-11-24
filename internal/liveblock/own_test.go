// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestEpochIsAskedFor: an overlay no writer asked an Epoch for is what it was (no epoch in its bytes); one that was asked
// writes it, and a reader that does not know the field decodes the file as before.
func TestEpochIsAskedFor(t *testing.T) {
	at := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	o := New("r-0123abcd-mabc12-abcdef")
	if _, _, err := o.Add(KindExec, "cat", "uid:1 pid:2 cli", at); err != nil {
		t.Fatal(err)
	}
	b, err := o.Encode()
	if err != nil || strings.Contains(string(b), "epoch") {
		t.Fatalf("an overlay no one asked an epoch for: %s, %v", b, err)
	}
	if _, ok := o.AddIdentity(KindExec, "cat"); ok {
		t.Error("an overlay with no epoch shows a block to be someone's")
	}
	if !o.EnsureEpoch() {
		t.Fatal("no epoch made")
	}
	first := o.Epoch
	o.EnsureEpoch()
	if o.Epoch != first {
		t.Error("EnsureEpoch changed an epoch the file has")
	}
	c, _, err := o.Add(KindExec, "ls", "uid:1 pid:2 cli", at)
	if err != nil {
		t.Fatal(err)
	}
	id, ok := o.AddIdentity(KindExec, "ls")
	if !ok || !id.Known() || id.Serial != c.Serial || !id.At.Equal(at) || id.Epoch != first {
		t.Fatalf("identity %+v, %v", id, ok)
	}
	if b, err = o.Encode(); err != nil {
		t.Fatal(err)
	}
	var older struct {
		V      int      `json:"v"`
		Serial uint64   `json:"serial"`
		Blocks []Entry  `json:"blocks"`
		Change []Change `json:"changes"`
	}
	if err := json.Unmarshal(b, &older); err != nil || len(older.Blocks) != 2 {
		t.Fatalf("a reader that ignores the epoch: %+v, %v", older, err)
	}
	back, err := Decode(b, "")
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := back.AddIdentity(KindExec, "ls"); !ok || !got.Is(id) {
		t.Errorf("identity after a round trip: %+v, %v", got, ok)
	}
	if (Own{Epoch: first, Serial: 1}).Is(Own{Epoch: first, Serial: 1}) {
		t.Error("an identity with no instant is Known")
	}
	o.Epoch = "not-hex"
	if err := o.Validate(""); err == nil {
		t.Error("a malformed epoch is valid")
	}
}
