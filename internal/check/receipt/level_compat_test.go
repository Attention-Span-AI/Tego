// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
)

// olderReceipt rewrites the bound receipt at path as a tego from before the coverage levels made it: no gap has a level,
// and a binding of v 2 or later has its digest made over what is left.
func olderReceipt(t *testing.T, path string, keepOne bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	gaps := gapsOf(m)
	if len(gaps) < 2 {
		t.Fatalf("the run has %d coverage gaps, want at least two", len(gaps))
	}
	for i, g := range gaps {
		if !keepOne || i > 0 {
			delete(g, "level")
		}
	}
	if b := m["binding"].(map[string]any); b["v"] != json.Number("1") {
		digest, err := payloadDigest(m)
		if err != nil {
			t.Fatal(err)
		}
		b["receipt_sha256"] = digest
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestReceiptFromBeforeTheLevelsStillChecks: a receipt that has no level on its coverage gaps (C165 is additive within
// receipt_v 1) is compared with the record for every other value, at every binding this tego reads, and still matches
// when nothing else differs; a receipt with a level on some gaps and none on the rest is not from before the key, and
// one whose level was edited does not match either. A level is never taken for better than its code says
// (pkg/spec/receipt's TestLevelsNeverReadBetterThanTheCode).
func TestReceiptFromBeforeTheLevelsStillChecks(t *testing.T) {
	for _, version := range []int{1, 2} {
		p := boundPair(t, []line{start("off", false), end(2e9, 0)}, version)
		olderReceipt(t, p.receipt, false)
		if res := Check(context.Background(), CheckInput{Receipt: p.receipt, Record: p.dir, By: testBy}); res.Result != CheckMatch || res.BindingVersion != version {
			t.Errorf("binding v%d: a receipt with no levels does not match: %+v", version, res)
		}
	}
	p := boundPair(t, []line{start("off", false), end(2e9, 0)}, 1)
	olderReceipt(t, p.receipt, true)
	if res := Check(context.Background(), CheckInput{Receipt: p.receipt, Record: p.dir, By: testBy}); res.Result != CheckMismatch {
		t.Errorf("a receipt with a level on one gap and none on the others matches: %+v", res)
	}
	p = boundPair(t, []line{start("off", false), end(2e9, 0)}, 1)
	data, err := os.ReadFile(p.receipt)
	if err != nil {
		t.Fatal(err)
	}
	edited := bytes.Replace(data, []byte(`"level": "none"`), []byte(`"level": "partial"`), 1)
	if bytes.Equal(edited, data) {
		t.Fatal("the receipt has no level none to edit")
	}
	if err := os.WriteFile(p.receipt, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	if res := Check(context.Background(), CheckInput{Receipt: p.receipt, Record: p.dir, By: testBy}); res.Result != CheckMismatch {
		t.Errorf("a receipt whose level was edited matches: %+v", res)
	}
}
