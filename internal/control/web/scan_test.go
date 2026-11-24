// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/pathcheck"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
)

var updateScan = flag.Bool("update-scan", false, "rewrite Overview scan guide goldens")

func TestOverviewScanGuideGoldens(t *testing.T) {
	for _, state := range guidetest.ScanCases {
		t.Run(state, func(t *testing.T) {
			f := guidetest.Make(t, guidetest.Fresh)
			if e := guide.StoreCheck(f.Home, f.Probe); e != nil {
				t.Fatal(e)
			}
			want := f.PutScan(t, state)
			server := guideServer(t, f)
			got := readGuide(t, get(t, server, login(t, server), "/"))
			if (got.Steps[2].State == guide.Done) != want {
				t.Fatalf("find %+v", got.Steps[2])
			}
			in := f.Inputs(t)
			in.Dir = ""
			in.Now = guidetest.CheckTime.Add(time.Minute)
			words := guide.Compute(t.Context(), in).Words(f.Home)
			for i, w := range words.Steps {
				if got.Steps[i].Fact != flat(w.Fact) {
					t.Fatalf("word mismatch %q / %q", got.Steps[i].Fact, w.Fact)
				}
			}
			if !want && !strings.Contains(strings.Join(got.NotKnown, " "), "Run tego scan from your project folder.") {
				t.Fatal("no command to run")
			}
			b, e := json.MarshalIndent(got, "", "  ")
			if e != nil {
				t.Fatal(e)
			}
			b = append(f.Normal(b), '\n')
			path := filepath.Join("testdata", "scan-"+state+".golden")
			if *updateScan {
				if e = os.WriteFile(path, b, 0644); e != nil {
					t.Fatal(e)
				}
			} else {
				expected, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				if !bytes.Equal(b, expected) {
					t.Fatalf("Overview differs from %s:\n%s", path, b)
				}
			}
		})
	}
}
func TestOverviewScanReplacementInvalidatesGuide(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	if e := guide.StoreCheck(f.Home, f.Probe); e != nil {
		t.Fatal(e)
	}
	s := guideServer(t, f)
	cookie := login(t, s)
	first := readGuide(t, get(t, s, cookie, "/"))
	if first.Steps[2].State != guide.Todo {
		t.Fatal(first.Steps[2])
	}
	f.PutScan(t, "b")
	next := readGuide(t, get(t, s, cookie, "/"))
	if next.Steps[2].State != guide.Done {
		t.Fatal("same ledger retained old find", next.Steps[2])
	}
	f.PutScan(t, "invalid")
	last := readGuide(t, get(t, s, cookie, "/"))
	if last.Steps[2].State != guide.Todo {
		t.Fatal("invalid result retained positive", last.Steps[2])
	}
}

func TestOverviewStoredCheckReplacementInvalidatesGuide(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	s := guideServer(t, f)
	cookie := login(t, s)
	first := readGuide(t, get(t, s, cookie, "/"))
	if first.Steps[1].State != guide.Todo {
		t.Fatal(first.Steps[1])
	}
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	next := readGuide(t, get(t, s, cookie, "/"))
	if next.Steps[1].State != guide.Done {
		t.Fatal("same ledger retained old check", next.Steps[1])
	}
	if err := os.WriteFile(guide.CheckPath(f.Home), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	last := readGuide(t, get(t, s, cookie, "/"))
	if last.Steps[1].State != guide.NotKnown {
		t.Fatal("invalid check retained positive", last.Steps[1])
	}
}

func TestOverviewGuideCacheKeyUsesBoundedHelper(t *testing.T) {
	f := guidetest.Make(t, guidetest.Finished)
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	s := guideServer(t, f)
	cookie := login(t, s)
	if got := readGuide(t, get(t, s, cookie, "/overview")); got.Rule != guide.RuleEnforceDone {
		t.Fatal(got.Rule)
	}
	marker := helperHangMarker(t)
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := requestEndingWithAStoppedWorker(t)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+"/", nil).WithContext(ctx)
	req.AddCookie(cookie)
	response := httptest.NewRecorder()
	before := handlerGoroutines()
	started := time.Now()
	s.ServeHTTP(response, req)
	if time.Since(started) > 2*time.Second || response.Code != http.StatusOK || !strings.Contains(response.Body.String(), pathcheck.Unavailable) {
		t.Fatalf("unavailable key reused a positive guide or exceeded bound: status=%d elapsed=%s body=%s", response.Code, time.Since(started), response.Body.String())
	}
	if s.guide.last != nil {
		t.Fatal("unavailable key retained an older positive guide memo")
	}
	if after := handlerGoroutines(); after != before {
		t.Errorf("handler goroutines before=%d after=%d", before, after)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if got := readGuide(t, get(t, s, cookie, "/overview")); got.Rule != guide.RuleEnforceDone {
		t.Fatal("recovery retained unavailable key", got.Rule)
	}
}
