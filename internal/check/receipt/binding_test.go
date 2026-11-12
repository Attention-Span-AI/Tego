// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// testBy is the tego these tests make and check receipts as.
var testBy = MadeBy{TegoVersion: "v0.1.2", Commit: "0123456789abcdef0123456789abcdef01234567"}

// boundRun is a short ended run with a refusal, a write and a connection.
func boundRun() []line {
	rw := "fs.write[./out/]"
	return []line{
		start("off", true),
		{kind: record.KindFS, at: time.Second, verdict: record.VerdictAllow, rule: rw,
			payload: record.FSPayload{Op: record.FSOpen, Path: "/p/out/a.txt", Flags: 0o1101}},
		{kind: record.KindFS, at: 2 * time.Second, verdict: record.VerdictRefused, rule: rw, reason: record.ReasonWriteOutsideContract,
			payload: record.FSPayload{Op: record.FSOpen, Path: "/home/u/.bashrc", Flags: 0o1101}},
		{kind: record.KindNet, at: 3 * time.Second, verdict: record.VerdictAllow, rule: "net.allow[pypi.org]",
			payload: record.NetPayload{Proto: "tcp", Dst: "151.101.0.223:443", Host: "pypi.org"}},
		end(4*time.Second, 0),
	}
}

// receiptJSON is rc as `tego receipt --json` writes it, decoded into a map.
func receiptJSON(t *testing.T, rc *Receipt) (map[string]any, []byte) {
	t.Helper()
	var buf bytes.Buffer
	if err := rc.JSON(&buf); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	return m, buf.Bytes()
}

// TestReceiptWithoutBindIsUnchanged: Compute without Bind writes no binding key, so the dashboard's receipt and tego
// run's end summary, which never bind, print what they printed before.
func TestReceiptWithoutBindIsUnchanged(t *testing.T) {
	rc := compute(t, boundRun(), Options{})
	m, _ := receiptJSON(t, rc)
	if _, ok := m["binding"]; ok || rc.Binding != nil {
		t.Errorf("an unbound receipt carries a binding: %v", m["binding"])
	}
}

// TestReceiptJSONKeysOnlyGrow: a bound receipt keeps every key of the unbound one, with the same JSON type and value,
// and adds the one key binding (receipt_v 1: keys only grow).
func TestReceiptJSONKeysOnlyGrow(t *testing.T) {
	plain, _ := receiptJSON(t, compute(t, boundRun(), Options{}))
	bound, _ := receiptJSON(t, compute(t, boundRun(), Options{Bind: &testBy}))
	for k, v := range plain {
		got, ok := bound[k]
		if !ok {
			t.Errorf("binding dropped the key %q", k)
			continue
		}
		a, _ := json.Marshal(v)
		b, _ := json.Marshal(got)
		if !bytes.Equal(a, b) {
			t.Errorf("binding changed %q: %s, was %s", k, b, a)
		}
	}
	for k := range bound {
		if _, ok := plain[k]; !ok && k != "binding" {
			t.Errorf("binding added the key %q beside binding", k)
		}
	}
	if _, ok := bound["binding"]; !ok {
		t.Error("a bound receipt has no binding key")
	}
}

// TestReceiptBindingChain: the binding names the record the receipt read: its run, line count, head and end as Verify
// reports them, and the size and sha256 of events.jsonl as sha256sum prints them; receipt_by is the tego that made it.
func TestReceiptBindingChain(t *testing.T) {
	r := ledgerOf(t, boundRun())
	r.SkipNewerVersions()
	rc, err := Compute(context.Background(), r, Options{Bind: &testBy})
	if err != nil {
		t.Fatal(err)
	}
	b := rc.Binding
	if b == nil || b.Chain == nil {
		t.Fatalf("no binding: %+v", b)
	}
	data, err := os.ReadFile(filepath.Join(r.Dir(), ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	rep, err := r.Verify(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	c := b.Chain
	if b.V != BindingVersion || c.Run != rc.Run || c.Lines != rep.Lines || c.Head != rep.Head || !c.Ended ||
		c.Bytes != int64(len(data)) || c.SHA256 != hex.EncodeToString(sum[:]) || c.TornBytes != 0 || c.NewerLines != 0 ||
		b.ReceiptBy != testBy || b.Error != "" {
		t.Errorf("binding %+v chain %+v, verify %+v", b, c, rep)
	}
}

// TestReceiptBindingLimits: limits is a fixed list of codes: record-only exactly when the run was watched (tier
// observe), the other three always; and no word in it says signed or proof.
func TestReceiptBindingLimits(t *testing.T) {
	for _, tier := range []string{"landlock", "observe"} {
		lines := boundRun()
		lines[0].payload = record.RunStartPayload{Tier: tier, Capture: "off"}
		rc := compute(t, lines, Options{Bind: &testBy})
		if rc.Binding == nil {
			t.Fatalf("tier %s: no binding", tier)
		}
		var codes []string
		for _, l := range rc.Binding.Limits {
			codes = append(codes, l.Code)
			if l.Why == "" {
				t.Errorf("limit %s has no why", l.Code)
			}
		}
		want := []string{LimitLaunchingUser, LimitTailNotSynced, LimitNoSignature}
		if tier == "observe" {
			want = []string{LimitLaunchingUser, LimitRecordOnly, LimitTailNotSynced, LimitNoSignature}
		}
		if strings.Join(codes, ",") != strings.Join(want, ",") {
			t.Errorf("tier %s: limits %v, want %v", tier, codes, want)
		}
		m, _ := receiptJSON(t, rc)
		b, _ := json.Marshal(m["binding"])
		if overclaims(string(b)) {
			t.Errorf("tier %s: the binding overclaims: %s", tier, b)
		}
	}
}

// TestReceiptBrokenChainStillPrints: a receipt over a record whose chain breaks is still computed, as it was before
// binding (it is a report), and its binding binds no head and says why.
func TestReceiptBrokenChainStillPrints(t *testing.T) {
	r := ledgerOf(t, boundRun())
	path := filepath.Join(r.Dir(), ledger.EventsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte("/home/u/.bashrc"), []byte("/home/u/.zshrc_"), 1)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	rc, err := Compute(context.Background(), r, Options{Bind: &testBy})
	if err != nil {
		t.Fatalf("a broken chain stopped the receipt: %v", err)
	}
	if rc.Binding == nil || rc.Binding.Chain != nil || !strings.Contains(rc.Binding.Error, "line 2") {
		t.Errorf("binding %+v, want no chain and an error naming line 2", rc.Binding)
	}
	if rc.Refusals.Total != 1 {
		t.Errorf("the receipt's numbers changed: %+v", rc.Refusals)
	}
}

// overclaims reports whether s says more than a binding or a check knows.
func overclaims(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "proof") || strings.Contains(l, "signed") || strings.Contains(l, "tamper")
}
