// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/attention-span-ai/tego/internal/testutil/jsonschema"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Binding-only consumers must detect edits to displayed totals before facts runs.
func TestBindingRejectsEditedTotal(t *testing.T) {
	p := v2Pair(t)
	editReceipt(t, p.receipt, func(m map[string]any) { obj(m, "refusals")["total"] = 999 })
	res := Check(context.Background(), CheckInput{Receipt: p.receipt, Record: p.dir, By: MadeBy{TegoVersion: "another", Commit: "build"}})
	if res.Result != CheckMismatch {
		t.Fatalf("edited total with facts unavailable: %s, want mismatch", res.Result)
	}
}

func TestBindingVersion2Metadata(t *testing.T) {
	p := v2Pair(t)
	data, err := os.ReadFile(p.receipt)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	b := obj(m, "binding")
	if b["v"] != float64(2) {
		t.Fatalf("binding v %v, want2", b["v"])
	}
	for _, k := range []string{"binary_sha256", "receipt_sha256"} {
		if s, _ := b[k].(string); len(s) != 64 {
			t.Errorf("%s = %v", k, b[k])
		}
	}
	if res := checked(t, p, testBy); res.Result != CheckMatch {
		t.Fatalf("unmodified pair: %+v", res)
	}
}

func TestBindingUnknownVersionCannotMatch(t *testing.T) {
	p := v2Pair(t)
	editReceipt(t, p.receipt, func(m map[string]any) { obj(m, "binding")["v"] = 999 })
	res := checked(t, p, testBy)
	if res.Result != CheckCannot || res.ExitCode() != 125 || !strings.Contains(step(res, "receipt").Why, "999") {
		t.Fatalf("unknown binding %+v", res)
	}
}

func v2Pair(t *testing.T) pair {
	t.Helper()
	lines := boundRun()
	start := lines[0].payload.(record.RunStartPayload)
	start.ContractHash = strings.Repeat("d", 64)
	lines[0].payload = start
	r := ledgerOf(t, lines)
	rc, err := Compute(context.Background(), r, Options{Bind: &testBy})
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := rc.JSON(&b); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(path, b.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return pair{r.Dir(), path}
}

func TestBindingV1StillChecks(t *testing.T) {
	p := boundPair(t, boundRun()) // historical comparison fixtures deliberately use BindVersion 1
	res := checked(t, p, testBy)
	if res.Result != CheckMatch || res.BindingVersion != 1 {
		t.Fatalf("old receipt: %+v", res)
	}
	var b bytes.Buffer
	if err := res.Text(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "Binding version: 1") {
		t.Fatal(b.String())
	}
}

func TestBindingProducerHashDoesNotIdentifyChecker(t *testing.T) {
	p := v2Pair(t)
	editReceipt(t, p.receipt, func(m map[string]any) {
		obj(m, "binding")["binary_sha256"] = strings.Repeat("a", 64)
		h, err := payloadDigest(m)
		if err != nil {
			t.Fatal(err)
		}
		obj(m, "binding")["receipt_sha256"] = h
	})
	res := checked(t, p, testBy)
	if res.Result != CheckMatch {
		t.Fatalf("same release, different producer image: %+v", res)
	}
	found := false
	for _, s := range res.NotCompared {
		if s == "binding.binary_sha256" {
			found = true
		}
	}
	if !found {
		t.Fatalf("producer hash not named as taken: %v", res.NotCompared)
	}
}

func TestBindingCommitsEveryReceiptField(t *testing.T) {
	p := v2Pair(t)
	data, err := os.ReadFile(p.receipt)
	if err != nil {
		t.Fatal(err)
	}
	var original map[string]any
	if err := json.Unmarshal(data, &original); err != nil {
		t.Fatal(err)
	}
	for key, val := range original {
		t.Run(key, func(t *testing.T) {
			var m map[string]any
			if err := json.Unmarshal(data, &m); err != nil {
				t.Fatal(err)
			}
			switch v := val.(type) {
			case string:
				m[key] = v + "edited"
			case float64:
				m[key] = v + 1
			case bool:
				m[key] = !v
			default:
				m[key] = "edited"
			}
			out, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p.receipt, out, 0600); err != nil {
				t.Fatal(err)
			}
			res := Check(context.Background(), CheckInput{Receipt: p.receipt, Record: p.dir, By: MadeBy{TegoVersion: "other", Commit: "build"}})
			if res.Result == CheckMatch || res.Result == CheckMatchUnended || res.Complete {
				t.Fatalf("edited %s accepted: %+v", key, res)
			}
		})
	}
}

func TestRequireEndedAndTeardown(t *testing.T) {
	forBindingVersions(t, requireEndedAndTeardown)
}

func requireEndedAndTeardown(t *testing.T, bindVersion int) {
	for _, tc := range []struct {
		name   string
		ended  bool
		status string
		want   string
		code   int
	}{
		{"unended", false, "", CheckMismatch, 1},
		{"missing", true, "", CheckCannot, 125},
		{"malformed", true, `{}`, CheckCannot, 125},
		{"deferred", true, `{"schema":"tego.run-status/1","run":"r-3f9c2a1b-0dllq06ts7400-k7m2pq","scope":"/sys/fs/cgroup/tego/x","cgroup_id":"42","removed":false,"deferred":true}`, CheckMismatch, 1},
		{"unknown", true, `{"schema":"tego.run-status/1","run":"r-3f9c2a1b-0dllq06ts7400-k7m2pq","scope":"","cgroup_id":"","removed":false,"deferred":false}`, CheckMismatch, 1},
		{"stale", true, `{"schema":"tego.run-status/1","run":"r-3f9c2a1b-0dllq06ts7400-k7m2pq","scope":"/sys/fs/cgroup/tego/x","cgroup_id":"99","removed":true,"deferred":false}`, CheckMismatch, 1},
		{"incomplete", true, `{"schema":"tego.run-status/1","run":"r-3f9c2a1b-0dllq06ts7400-k7m2pq","scope":"/sys/fs/cgroup/tego/x","cgroup_id":"42","removed":true,"deferred":false}`, CheckIncomplete, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := boundRun()
			for i := range lines {
				lines[i].cgroup = 42
			}
			if !tc.ended {
				lines = lines[:len(lines)-1]
			}
			p := boundPair(t, lines, bindVersion)
			status := filepath.Join(p.dir, "run-status.json")
			if tc.status != "" {
				if err := os.WriteFile(status, []byte(tc.status), 0600); err != nil {
					t.Fatal(err)
				}
			}
			res := Check(context.Background(), CheckInput{Receipt: p.receipt, Record: p.dir, By: testBy, RequireEnded: true, StatusFile: status})
			if res.Result != tc.want || res.ExitCode() != tc.code || res.Complete {
				t.Fatalf("result %+v exit%d, want %s/%d", res, res.ExitCode(), tc.want, tc.code)
			}
		})
	}
}

func TestRequireEndedFullMatch(t *testing.T) {
	forBindingVersions(t, requireEndedFullMatch)
}

func requireEndedFullMatch(t *testing.T, bindVersion int) {
	lines := []line{start("forwarder", true),
		{kind: record.KindSSLRequest, payload: record.SSLRequestPayload{Endpoint: "messages", Method: "POST", Host: "h"}},
		{kind: record.KindSSLResponse, at: time.Second, payload: map[string]any{"request_seq": 1, "status": 200, "parser_version": "1", "model": "m", "latency_ms": 1, "usage": map[string]int{"input": 500, "output": 10}}}, end(2*time.Second, 0)}
	for i := range lines {
		lines[i].cgroup = 42
	}
	p := boundPair(t, lines, bindVersion)
	status := filepath.Join(p.dir, "run-status.json")
	data := `{"schema":"tego.run-status/1","run":"r-3f9c2a1b-0dllq06ts7400-k7m2pq","scope":"/sys/fs/cgroup/tego/x","cgroup_id":"42","removed":true,"deferred":false}`
	if err := os.WriteFile(status, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	res := Check(context.Background(), CheckInput{Receipt: p.receipt, Record: p.dir, By: testBy, RequireEnded: true})
	if res.Result != CheckMatch || !res.Complete || !res.CoverageComplete || res.ExitCode() != 0 {
		t.Fatalf("full comparison: %+v", res)
	}
	generic := checked(t, p, testBy)
	if generic.Complete {
		t.Fatal("generic comparison claimed completion without teardown check")
	}
}

func TestCheckReceiptRejectsLinksAndFIFO(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		p := v2Pair(t)
		link := filepath.Join(t.TempDir(), "receipt.json")
		if err := os.Symlink(p.receipt, link); err != nil {
			t.Fatal(err)
		}
		if _, err := readReceipt(link); err == nil {
			t.Fatal("accepted receipt symlink")
		}
	})
	t.Run("FIFO without writer", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "receipt.json")
		if err := syscall.Mkfifo(path, 0600); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := readReceipt(path); done <- err }()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("accepted FIFO")
			}
		case <-time.After(time.Second):
			// Release an old blocking opener before reporting the regression.
			fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_NONBLOCK, 0)
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("reader did not return after cleanup")
			}
			if err := syscall.Close(fd); err != nil {
				t.Fatal(err)
			}
			t.Fatal("receipt open blocked on FIFO without a writer")
		}
	})
}

func TestCheckJSONSchemaAgreement(t *testing.T) {
	p := v2Pair(t)
	res := checked(t, p, testBy)
	jsonschema.Validate(t, "../../../spec/receipt/check-v1.schema.json", res)
	bad := *res
	bad.Complete = true
	bad.Ended = false
	if err := jsonschema.Check("../../../spec/receipt/check-v1.schema.json", &bad); err == nil {
		t.Fatal("schema allows complete unended result")
	}
	jsonschema.Validate(t, "../../../spec/receipt/check-v1.schema.json", checked(t, boundPair(t, boundRun()), testBy))
	jsonschema.Validate(t, "../../../spec/receipt/check-v1.schema.json", Check(context.Background(), CheckInput{Receipt: "missing", Record: p.dir, By: testBy}))
}

func TestBindingResealedEditsFailFacts(t *testing.T) {
	for _, field := range []string{"total", "contract_hash", "capability"} {
		t.Run(field, func(t *testing.T) {
			p := v2Pair(t)
			editReceipt(t, p.receipt, func(m map[string]any) {
				switch field {
				case "total":
					obj(m, "refusals")["total"] = 999
				case "contract_hash":
					obj(m, "binding")["contract_hash"] = strings.Repeat("e", 64)
				case "capability":
					caps := obj(obj(m, "binding"), "capabilities")
					for k, v := range caps {
						caps[k] = !v.(bool)
						break
					}
				}
				h, err := payloadDigest(m)
				if err != nil {
					t.Fatal(err)
				}
				obj(m, "binding")["receipt_sha256"] = h
			})
			res := checked(t, p, testBy)
			if step(res, "binding").Result != StepPass || step(res, "facts").Result != StepFail || res.Result != CheckMismatch {
				t.Fatalf("resealed %s %+v", field, res)
			}
		})
	}
}

func TestFrozenBindingV1ReceiptStillChecks(t *testing.T) {
	res := Check(context.Background(), CheckInput{Receipt: "testdata/binding1/receipt.json", Record: "testdata/binding1", By: testBy})
	if res.Result != CheckMatch || res.BindingVersion != 1 || res.ExitCode() != 0 {
		t.Fatalf("frozen v1 %+v", res)
	}
}

func TestBindingV2NoSignatureWords(t *testing.T) {
	rc := compute(t, boundRun(), Options{Bind: &testBy})
	for _, limit := range rc.Binding.Limits {
		if limit.Code == LimitNoSignature {
			if limit.Why != "This JSON carries no signature. A CI signature is a detached bundle checked separately." {
				t.Fatalf("no-signature: %s", limit.Why)
			}
			return
		}
	}
	t.Fatal("no no-signature limit")
}
