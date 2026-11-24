// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rules"
)

type regionChangeProbe struct {
	*rules.Service
	calls    int
	plan     *rules.ChangePlan
	readOnly bool
}

func (p *regionChangeProbe) PlanChange(ctx context.Context, req rules.ChangeReq) (*rules.ChangePlan, error) {
	p.calls++
	p.readOnly = req.PreviewOnly
	plan, err := p.Service.PlanChange(ctx, req)
	p.plan = plan
	return plan, err
}

// These are all GET handlers calling the peer decision: newForm and rulesPreview.
// Exercise their real service, authentication, region rendering and shared cache.
func TestBuilderRegionCacheBypass(t *testing.T) {
	for _, route := range []string{"new", "structured"} {
		for _, unknown := range []bool{false, true} {
			for _, readerFirst := range []bool{false, true} {
				name := route
				if unknown {
					name += "/uncertain"
				} else {
					name += "/governed"
				}
				if readerFirst {
					name += "/reader-first"
				} else {
					name += "/person-first"
				}
				t.Run(name, func(t *testing.T) {
					f := newChangeFix(t)
					c := f.ref(t, f.source)
					probe := &regionChangeProbe{Service: f.svc}
					f.s.cfg.Rules = probe
					header := "r-top:0"
					target := "/rules/change/preview?" + url.Values{"c": {c.Ref}, "base": {c.Base}, "op": {"add"}, "key": {"exec.allow"}, "v": {"/bin/echo"}}.Encode()
					marker := "What changes"
					credential := regexp.MustCompile(`name="ack" value="([^"]+)"`)
					if route == "new" {
						f.s.cfg.Setup = f.svc
						dir := filepath.Join(filepath.Dir(f.proj), "region-new")
						if err := os.Mkdir(dir, 0700); err != nil {
							t.Fatal(err)
						}
						header = "content:0"
						target = "/rules/new?" + url.Values{"mode": {"blank"}, "dir": {dir}, "name": {"region-new"}, "cmd": {"/bin/echo"}, "preview": {"1"}, "to": {"project"}}.Encode()
						marker = "Preview: region-new"
						credential = regexp.MustCompile(`name="base" value="([^"]+)"`)
					}
					// Bound the sequence to the cache window without a timing assertion on this loaded host.
					// Refresh retained timestamps before each ask; old code must see a warm entry.
					ask := func(reader bool) string {
						t.Helper()
						trustPeer(f.s)
						if reader {
							f.s.governed = func(*http.Request) error {
								if unknown {
									return errGovernedUnknown
								}
								return &governedError{Run: rulesRunB}
							}
						}
						f.s.regionCache.mu.Lock()
						for k, e := range f.s.regionCache.m {
							e.at = time.Now()
							f.s.regionCache.m[k] = e
						}
						f.s.regionCache.mu.Unlock()
						before := probe.calls
						w := doRegions(f.s, target, "127.0.0.1:8484", f.c, header)
						body := w.Body.String()
						if route == "structured" {
							if w.Code != http.StatusOK || body == "" || probe.calls != before+1 {
								t.Fatalf("structured preview was not rendered fresh: status=%d calls=%d -> %d", w.Code, before, probe.calls)
							}
							if probe.plan == nil || probe.plan.Err != "" || probe.readOnly != reader || (probe.plan.Ack == "") != reader {
								t.Fatal("structured preview has wrong peer decision or acknowledgement")
							}
							return probe.plan.Ack
						}
						if w.Code != http.StatusOK || !strings.Contains(body, marker) || !strings.Contains(body, "/bin/echo") || strings.Contains(body, rulesCanary) {
							t.Fatalf("reader=%t: invalid preview: %d %s", reader, w.Code, body)
						}
						if reader {
							if credential.MatchString(body) || strings.Contains(body, `name="base"`) || regexp.MustCompile(`name="draft" value="[^"]+"`).MatchString(body) || !strings.Contains(body, "Saving is not available") {
								t.Error("reader received review credentials, composition handle or Save rendering")
							}
						} else if !credential.MatchString(body) || strings.Contains(body, "Saving is not available") || !strings.Contains(body, `type="submit"`) {
							t.Error("person did not receive save-eligible form")
						}
						return body
					}
					first := ask(readerFirst)
					second := ask(!readerFirst)
					person := first
					if readerFirst {
						person = second
					}
					again := ask(false)
					if route == "structured" && person == again {
						t.Error("structured previews shared a review identity")
					}
					a, b := credential.FindStringSubmatch(person), credential.FindStringSubmatch(again)
					if len(a) == 2 && len(b) == 2 && a[1] == b[1] {
						t.Error("person's separate previews shared a review identity")
					}
					f.s.regionCache.mu.Lock()
					n := len(f.s.regionCache.m)
					f.s.regionCache.mu.Unlock()
					if n != 0 {
						t.Errorf("per-review preview stored %d shared cache entries", n)
					}
				})
			}
		}
	}
}

func TestRegionCachePeerEligibility(t *testing.T) {
	for _, target := range []string{"/", "/runs/" + harmRun} {
		t.Run(target, func(t *testing.T) {
			s := newServer(t, fixture(t))
			c := login(t, s)
			// cfg.Now is the existing render seam; live-state loading and cache access do not call it.
			renders := 0
			now := s.cfg.Now()
			s.cfg.Now = func() time.Time { renders++; return now }
			have := "r-top:0"
			ask := func(wantRender bool) {
				t.Helper()
				s.regionCache.mu.Lock()
				for k, e := range s.regionCache.m {
					e.at = time.Now()
					s.regionCache.m[k] = e
				}
				s.regionCache.mu.Unlock()
				before := renders
				w := doRegions(s, target, "127.0.0.1:8484", c, have)
				if w.Code != http.StatusOK {
					t.Fatalf("region status %d", w.Code)
				}
				if (renders > before) != wantRender {
					t.Errorf("render calls %d -> %d, want render=%t", before, renders, wantRender)
				}
			}
			personChecks := 0
			s.governed = func(*http.Request) error { personChecks++; return nil }
			ask(true)
			ask(false) // An ordinary person's page still hits the shared cache.
			if personChecks != 2 {
				t.Errorf("person peer decisions = %d, want two including cache hit", personChecks)
			}
			for _, err := range []error{&governedError{Run: harmRun}, errGovernedUnknown} {
				calls := 0
				s.governed = func(*http.Request) error { calls++; return err }
				ask(true) // Neither reads a person's warm entry ...
				ask(true)
				if calls != 2 {
					t.Errorf("peer decisions = %d, want one on every region request", calls)
				}
				s.regionCache.bump()
				s.memos.m = nil
				ask(true) // ... nor populates an empty cache.
				if len(s.regionCache.m) != 0 || len(s.memos.m) != 0 {
					t.Error("reader populated shared region state")
				}
				trustPeer(s)
				ask(true)
				ask(false)
			}
		})
	}
}

func TestRegionMemoPeerEligibility(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	target := "/runs/" + harmRun
	have := map[string]string{"r-top": "0"}
	if got := regionAsk(t, s, c, target, have); got != http.StatusOK {
		t.Fatalf("first ask: %d", got)
	}
	if got := regionAsk(t, s, c, target, have); got != http.StatusNoContent {
		t.Fatalf("person memo hit: %d", got)
	}
	for _, err := range []error{&governedError{Run: harmRun}, errGovernedUnknown} {
		s.governed = func(*http.Request) error { return err }
		if got := regionAsk(t, s, c, target, have); got != http.StatusOK {
			t.Errorf("reader reused person's memo: %d", got)
		}
	}
}
