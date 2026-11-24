// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"encoding/csv"
	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDownloadsReportRefusedLines(t *testing.T) {
	data, err := os.ReadFile("../../../spec/record/v1/fixtures/baseline/applied.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Replace(bytes.Split(data, []byte{'\n'})[0], []byte(`"plane":""`), []byte(`"plane":null`), 1)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, queryRun), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, queryRun, "events.jsonl"), append(append(bytes.Clone(bad), '\n'), append(bad, '\n')...), 0600); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	for _, ext := range []string{"jsonl", "csv"} {
		for _, q := range []string{"?run=" + queryRun, "?run=" + queryRun + "&where=kind:exec", "?run=" + queryRun + "&order=newest"} {
			w := do(s, "GET", "/logs."+ext+q, "127.0.0.1:8484", c)
			body := w.Body.String()
			for _, want := range []string{"plane", "byte offset 0", queryRun} {
				if !strings.Contains(body, want) {
					t.Errorf("%s%s lost %s: %s", ext, q, want, body)
				}
			}
			if ext == "csv" {
				rd := csv.NewReader(strings.NewReader(body))
				rd.FieldsPerRecord = -1
				rows, err := rd.ReadAll()
				if err != nil {
					t.Fatal(err)
				}
				if len(rows) != 3 || !strings.HasPrefix(rows[1][0], "# ") {
					t.Errorf("refusal serialized as event: %q", rows)
				}
			} else if strings.Count(body, `"tego_export_note"`) != 2 || strings.Contains(body, `"kind"`) {
				t.Errorf("refusal serialized as event: %s", body)
			}
		}
	}
}

func TestRunViewShowsLineRefusals(t *testing.T) {
	root, lines := queryFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	path := filepath.Join(root, queryRun, "events.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "")+"{broken\n{broken\n"), 0600); err != nil {
		t.Fatal(err)
	}
	body := do(s, "GET", "/runs/"+queryRun, "127.0.0.1:8484", c).Body.String()
	if strings.Count(body, "Record refused:") != 2 || !strings.Contains(body, "byte offset") {
		t.Fatalf("run view lost refusals: %s", body)
	}
}

func TestRunViewRetainsRefusalsAfterEviction(t *testing.T) {
	root, lines := queryFixture(t)
	path := filepath.Join(root, queryRun, "events.jsonl")
	// Valid events surround two refused, classifiable non-start records.
	bad := strings.Replace(lines[1], `"v":1`, `"v":0`, 1)
	if bad == lines[1] {
		t.Fatal("version mutation did not fire")
	}
	body := lines[0] + bad + lines[1] + bad + strings.Join(lines[2:], "")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := ledgerview.LoadRun(root, queryRun)
	if err != nil {
		t.Fatal(err)
	}
	if before.Bad != 2 || len(before.LineErrors) != 2 {
		t.Fatalf("initial refusals: %+v", before)
	}
	old := ledgerview.MaxResidentBytes
	ledgerview.MaxResidentBytes = 1
	t.Cleanup(func() { ledgerview.MaxResidentBytes = old })
	evict := func() {
		t.Helper()
		snap, err := ledgerview.Load(root)
		if err != nil {
			t.Fatal(err)
		}
		if snap.Find(queryRun).Events != nil {
			t.Fatal("window was not evicted")
		}
	}
	evict()
	after, err := ledgerview.LoadRun(root, queryRun)
	if err != nil {
		t.Errorf("known refusals prevented LoadRun: %v", err)
	}
	if after != nil && (after.Bad != 2 || !reflect.DeepEqual(before.LineErrors, after.LineErrors) || len(after.Events) != len(before.Events)) {
		t.Fatalf("rehydration changed events or refusals: bad=%d errors=%+v events=%d", after.Bad, after.LineErrors, len(after.Events))
	}
	evict()
	s := newServer(t, root)
	c := login(t, s)
	w := do(s, "GET", "/runs/"+queryRun, "127.0.0.1:8484", c)
	if w.Code != 200 || strings.Count(w.Body.String(), "Record refused:") != 2 {
		t.Fatalf("evicted run HTTP status=%d body=%s", w.Code, w.Body.String())
	}
}
