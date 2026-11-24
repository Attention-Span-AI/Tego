// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/control/pathcheck"
	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestRecordedLocationsHangReturnsAndLeavesNoHandler stops actual helper
// workers. This proves bounded HTTP completion and parent goroutine ownership;
// a kernel-blocked FUSE worker and reaping remain owed in a guest.
func TestRecordedLocationsHangReturnsAndLeavesNoHandler(t *testing.T) {
	f := newRulesFix(t)
	svc := &rules.Service{Ledger: f.root, Home: f.home, Machine: &config.Machine{Home: f.home}}
	f.s.cfg.Rules = svc
	f.s.cfg.Setup = svc
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := executable + ".hang"
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		_ = os.Remove(marker)
		paths, _ := filepath.Glob(executable + ".pid.*")
		for _, path := range paths {
			pid, err := strconv.Atoi(strings.TrimPrefix(path, executable+".pid."))
			if err == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
			_ = os.Remove(path)
		}
	}
	defer cleanup()
	before := handlerGoroutines()
	for _, route := range []string{"/rules?c=" + rules.RefLexical(f.source), "/rules/change", "/rules/change?c=" + rules.RefLexical(f.source)} {
		ctx, cancel := requestEndingWithAStoppedWorker(t)
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+route, nil).WithContext(ctx)
		req.AddCookie(f.c)
		response := httptest.NewRecorder()
		at := time.Now()
		f.s.ServeHTTP(response, req)
		cancel()
		if time.Since(at) > 2*time.Second {
			t.Errorf("%s exceeded its request bound: %s", route, time.Since(at))
		}
		body := response.Body.String()
		if response.Code != http.StatusOK {
			t.Errorf("%s: status %d: %s", route, response.Code, body)
		}
		if !strings.Contains(body, pathcheck.Unavailable) {
			t.Errorf("%s lacks cannot-tell state: %s", route, body)
		}
		if strings.Contains(route, "?c=") && !strings.Contains(body, "agent.yaml") {
			t.Errorf("%s lost the recorded entry", route)
		}
		if strings.HasPrefix(route, "/rules?c=") {
			if strings.Contains(body, "href=\"/rules/change?c=") || !strings.Contains(body, "disabled aria-describedby=\"rules-soon\"") {
				t.Errorf("%s enabled change of an unavailable source", route)
			}
		}
		if strings.HasPrefix(route, "/rules/change?c=") && strings.Contains(body, "method=\"post\"") {
			t.Errorf("%s offers a change form", route)
		}
	}
	paths, _ := filepath.Glob(executable + ".pid.*")
	if len(paths) == 0 {
		t.Error("no helper was stopped; regression did not exercise the process boundary")
	}
	cleanup()
	runtime.Gosched()
	if after := handlerGoroutines(); after != before {
		t.Errorf("HTTP handler goroutines before=%d after=%d", before, after)
	}
}

// A checker that never starts (stopped before its ready frame) is not a location that does not answer: the pages
// say the checker did not start, keep the entry listed, offer no change, and never use the mount words.
func TestRecordedLocationsWhoseCheckerNeverStartsAreBusyNotStuck(t *testing.T) {
	f := newRulesFix(t)
	svc := &rules.Service{Ledger: f.root, Home: f.home, Machine: &config.Machine{Home: f.home}}
	f.s.cfg.Rules = svc
	f.s.cfg.Setup = svc
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := executable + ".nostart"
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		_ = os.Remove(marker)
		paths, _ := filepath.Glob(executable + ".pid.*")
		for _, path := range paths {
			if pid, err := strconv.Atoi(strings.TrimPrefix(path, executable+".pid.")); err == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
			_ = os.Remove(path)
		}
	}
	defer cleanup()
	for _, route := range []string{"/rules?c=" + rules.RefLexical(f.source), "/rules/change", "/rules/change?c=" + rules.RefLexical(f.source)} {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+route, nil).WithContext(ctx)
		req.AddCookie(f.c)
		response := httptest.NewRecorder()
		f.s.ServeHTTP(response, req)
		cancel()
		body := html.UnescapeString(response.Body.String()) // the words hold an apostrophe
		if response.Code != http.StatusOK || !strings.Contains(body, pathcheck.Busy) {
			t.Errorf("%s: status %d, the page lacks the checker-did-not-start words: %s", route, response.Code, body)
		}
		if strings.Contains(body, pathcheck.Unavailable) {
			t.Errorf("%s: a checker that never started was called a location that does not answer", route)
		}
		if strings.Contains(route, "?c=") && !strings.Contains(body, "agent.yaml") {
			t.Errorf("%s lost the recorded entry", route)
		}
		if strings.HasPrefix(route, "/rules/change?c=") && strings.Contains(body, "method=\"post\"") {
			t.Errorf("%s offers a change form", route)
		}
	}
}

func handlerGoroutines() int {
	buffer := make([]byte, 2<<20)
	n := runtime.Stack(buffer, true)
	count := 0
	for _, stack := range strings.Split(string(buffer[:n]), "\n\n") {
		if strings.Contains(stack, "(*Server).ServeHTTP") || strings.Contains(stack, "control/rulesview.ContractsFromRuns") || strings.Contains(stack, "control/rules.remoteService") {
			count++
		}
	}
	return count
}

// The guide's private command-origin marker must survive the trusted helper
// projection without treating arbitrary decoded commands as safe to copy.
func TestBoundedGuidePreservesBuiltCommand(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	state, built, err := checkedGuide(context.Background(), f.Inputs(t))
	if err != nil {
		t.Fatal(err)
	}
	if !built || state.Next.Command == "" {
		t.Fatalf("trusted guide lost command origin: built=%t next=%+v", built, state.Next)
	}
	if state.Next.Built() {
		t.Fatal("display transport reconstructed private policy state")
	}
}

// requestEndingWithAStoppedWorker is the context of a request whose deadline passes once one more worker of this test
// image has told its caller it is ready and stopped itself (stopOnceReady): the deadline of a request that waited
// for a location that does not answer. A fixed deadline cannot stand in for that: a request that ends before the
// worker is ready is a checker that did not start in time, which says so in its own words, and how long a helper
// takes to start depends on the machine. It ends as a deadline (context.DeadlineExceeded), not as a cancellation: a
// caller that gave up says that, in neutral words, and is not a location that does not answer. The thirty seconds
// are a guard against a worker that never gets there, not a speed claim.
func requestEndingWithAStoppedWorker(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	stopped := func() int {
		paths, _ := filepath.Glob(executable + ".pid.*")
		return len(paths)
	}
	already := stopped()
	// The request is a scope (contracts.WithBudget, which the handler's own scope reuses), so the test can tell when
	// the caller has read the helper's ready frame: ending it before that is a deadline in the start-up.
	scope, release := contracts.WithBudget(context.Background())
	ctx := &deadlineAtWill{Context: scope, end: make(chan struct{})}
	var once sync.Once
	cancel := func() { once.Do(func() { close(ctx.end); release() }) }
	go func() {
		guard := time.NewTimer(30 * time.Second)
		defer guard.Stop()
		for {
			select {
			case <-ctx.end:
				return
			case <-guard.C:
				cancel()
				return
			case <-time.After(2 * time.Millisecond):
				if stopped() > already && contracts.LocationAsked(ctx) {
					cancel()
					return
				}
			}
		}
	}()
	return ctx, cancel
}

// deadlineAtWill is a context whose deadline passes when end is closed.
type deadlineAtWill struct {
	context.Context
	end chan struct{}
}

func (c *deadlineAtWill) Done() <-chan struct{} { return c.end }
func (c *deadlineAtWill) Err() error {
	select {
	case <-c.end:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func helperHangMarker(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := executable + ".hang"
	t.Cleanup(func() {
		_ = os.Remove(marker)
		paths, _ := filepath.Glob(executable + ".pid.*")
		for _, path := range paths {
			pid, err := strconv.Atoi(strings.TrimPrefix(path, executable+".pid."))
			if err == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
			_ = os.Remove(path)
		}
	})
	return marker
}

func TestUnavailableCanonicalBookmarkKeepsCatalogue(t *testing.T) {
	f := newRulesFix(t)
	alias := filepath.Join(filepath.Dir(f.proj), "linked-project")
	if err := os.Symlink(f.proj, alias); err != nil {
		t.Fatal(err)
	}
	aliasSource := filepath.Join(alias, "agent.yaml")
	for _, run := range []string{rulesRunA, rulesRunB} {
		path := filepath.Join(f.root, run, "events.jsonl")
		text, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(strings.ReplaceAll(string(text), f.source, aliasSource)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	canonical := rules.Ref(f.source)
	if canonical == rules.RefLexical(aliasSource) {
		t.Fatal("fixture does not distinguish canonical and recorded refs")
	}
	svc := &rules.Service{Ledger: f.root, Home: f.home}
	// A cold service has never resolved the alias and cannot safely select it by
	// the canonical bookmark while its helper cannot answer.
	s, err := New(Config{Ledger: f.root, Port: port, Token: "tok123", Rules: svc, Setup: svc})
	if err != nil {
		t.Fatal(err)
	}
	trustPeer(s)
	cookie := login(t, s)
	if err := os.WriteFile(helperHangMarker(t), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	before := handlerGoroutines()
	for _, route := range []string{"/rules?c=" + canonical, "/rules/change?c=" + canonical} {
		ctx, cancel := requestEndingWithAStoppedWorker(t)
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+route, nil).WithContext(ctx)
		req.AddCookie(cookie)
		response := httptest.NewRecorder()
		s.ServeHTTP(response, req)
		cancel()
		body := response.Body.String()
		if response.Code != http.StatusOK || !strings.Contains(body, pathcheck.Unavailable) || !strings.Contains(body, "linked-project") {
			t.Errorf("%s: lost unavailable catalogue: status=%d body=%s", route, response.Code, body)
		}
		if strings.Contains(body, "No contracts yet") || strings.Contains(body, `method="post"`) || strings.Contains(body, "Contract · other-agent") {
			t.Errorf("%s: rendered a false empty state, write or unrelated selection", route)
		}
	}
	for _, route := range []string{"/rules?c=feed", "/rules/change?c=feed"} {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+route, nil).WithContext(ctx)
		req.AddCookie(cookie)
		response := httptest.NewRecorder()
		s.ServeHTTP(response, req)
		cancel()
		if response.Code != http.StatusNotFound {
			t.Errorf("invalid ref %s became an unavailable match: status=%d", route, response.Code)
		}
	}
	if after := handlerGoroutines(); after != before {
		t.Errorf("handler goroutines before=%d after=%d", before, after)
	}
}

type hangAfterCatalogue struct {
	*rules.RequestService
	marker string
	refs   []rules.ContractRef
}

func (s hangAfterCatalogue) Contracts() ([]rules.ContractRef, error) {
	if err := os.WriteFile(s.marker, nil, 0o600); err != nil {
		return nil, err
	}
	return s.refs, nil
}

func TestCurrentHelperHangKeepsSelectedContract(t *testing.T) {
	f := newRulesFix(t)
	svc := &rules.Service{Ledger: f.root, Home: f.home}
	refs, err := svc.Contracts()
	if err != nil {
		t.Fatal(err)
	}
	checked := false
	for _, ref := range refs {
		if ref.Ref == rules.RefLexical(f.source) && ref.Writable {
			checked = true
		}
	}
	if !checked {
		t.Fatal("fixture did not check the selected source before its read was stopped")
	}
	// Establish the catalogue before starting the second read's deadline. The
	// barrier stops the actual worker only after that healthy result is known.
	ctx, cancel := requestEndingWithAStoppedWorker(t)
	defer cancel()
	f.s.cfg.Rules = hangAfterCatalogue{RequestService: svc.ForRequest(ctx), marker: helperHangMarker(t), refs: refs}
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+"/rules/change?c="+rules.RefLexical(f.source), nil).WithContext(ctx)
	req.AddCookie(f.c)
	response := httptest.NewRecorder()
	before := handlerGoroutines()
	f.s.ServeHTTP(response, req)
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, pathcheck.Unavailable) || !strings.Contains(body, "agent.yaml") {
		t.Fatalf("Current timeout lost selected contract: status=%d body=%s", response.Code, body)
	}
	if strings.Contains(body, `method="post"`) {
		t.Fatal("Current timeout left a write form enabled")
	}
	if after := handlerGoroutines(); after != before {
		t.Errorf("handler goroutines before=%d after=%d", before, after)
	}
}

type unavailableNewContract struct {
	*rules.Service
	marker, path         string
	catalogueUnavailable bool
}

func (s unavailableNewContract) Contracts() ([]rules.ContractRef, error) {
	if err := os.WriteFile(s.marker, nil, 0o600); err != nil {
		return nil, err
	}
	ref := rules.ContractRef{Ref: rules.RefLexical(s.path), Path: s.path, Agent: "fresh-agent", Writable: true}
	if s.catalogueUnavailable {
		ref.Writable, ref.Why = false, pathcheck.Unavailable
	}
	return []rules.ContractRef{ref}, nil
}

// DescribeNew blocks inside an actual descriptor-reading helper operation. The
// request can already own a reusable worker by this point, so a worker-start
// marker cannot model a filesystem stall during this later operation.
func (s unavailableNewContract) DescribeNew(ctx context.Context, _ string) (*rules.NewPlan, error) {
	var response []byte
	err := pathcheck.Call(ctx, "test.source-read", s.path, &response)
	return nil, err
}

func TestUnavailableNotRunContractDoesNotOfferStart(t *testing.T) {
	for _, catalogueUnavailable := range []bool{true, false} {
		name := "description"
		if catalogueUnavailable {
			name = "catalogue"
		}
		t.Run(name, func(t *testing.T) {
			f := newRulesFix(t)
			source := filepath.Join(f.home, "fresh-agent.yaml")
			if err := os.WriteFile(source, []byte("version: 0\nname: fresh-agent\n"), 0600); err != nil {
				t.Fatal(err)
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Remove(exe + ".catalogue-read") })
			svc := &rules.Service{Ledger: f.root, Home: f.home}
			f.s.cfg.Setup = unavailableNewContract{Service: svc, marker: helperHangMarker(t), path: source, catalogueUnavailable: catalogueUnavailable}
			// The helper must reach its blocked read before the request gives up: under -race it starts in about a second.
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*testRaceScale)
			defer cancel()
			req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+"/rules?c="+rules.RefLexical(source), nil).WithContext(ctx)
			req.AddCookie(f.c)
			response := httptest.NewRecorder()
			before := handlerGoroutines()
			f.s.ServeHTTP(response, req)
			body := response.Body.String()
			if response.Code != http.StatusOK || !strings.Contains(body, pathcheck.Unavailable) || !strings.Contains(body, "fresh-agent") {
				t.Fatalf("lost unavailable not-run contract: status=%d body=%s", response.Code, body)
			}
			if !catalogueUnavailable {
				if _, err := os.Stat(exe + ".catalogue-read"); err != nil {
					t.Fatalf("description never reached the blocked helper read: %v", err)
				}
			}
			for _, unsafe := range []string{"Start it", "Contract · other-agent", `href="/rules/change?c=`, "No contracts yet"} {
				if strings.Contains(body, unsafe) {
					t.Errorf("unavailable not-run contract offered %q", unsafe)
				}
			}
			if after := handlerGoroutines(); after != before {
				t.Errorf("handler goroutines before=%d after=%d", before, after)
			}
		})
	}
}

type hangAfterCurrent struct {
	*rules.RequestService
	refs    []rules.ContractRef
	current *rules.Current
	marker  string
}

func (s hangAfterCurrent) Contracts() ([]rules.ContractRef, error) { return s.refs, nil }
func (s hangAfterCurrent) Current(string) (*rules.Current, error) {
	if err := os.WriteFile(s.marker, nil, 0o600); err != nil {
		return nil, err
	}
	return s.current, nil
}

func TestHistoryHelperHangDisablesSourceChanges(t *testing.T) {
	f := newRulesFix(t)
	svc := &rules.Service{Ledger: f.root, Home: f.home}
	refs, err := svc.Contracts()
	if err != nil {
		t.Fatal(err)
	}
	current, err := svc.Current(rules.RefLexical(f.source))
	if err != nil || current == nil || !current.Writable {
		t.Fatalf("healthy Current=%+v err=%v", current, err)
	}
	ctx, cancel := requestEndingWithAStoppedWorker(t)
	defer cancel()
	f.s.cfg.Rules = hangAfterCurrent{RequestService: svc.ForRequest(ctx), refs: refs, current: current, marker: helperHangMarker(t)}
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+"/rules/change?c="+current.Ref, nil).WithContext(ctx)
	req.AddCookie(f.c)
	response := httptest.NewRecorder()
	before := handlerGoroutines()
	f.s.ServeHTTP(response, req)
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, pathcheck.Unavailable) || !strings.Contains(body, "agent.yaml") {
		t.Fatalf("History timeout lost selected source: status=%d body=%s", response.Code, body)
	}
	if strings.Contains(body, `method="post"`) || strings.Contains(body, `action="/rules/change/preview"`) {
		t.Fatal("History timeout left source changes enabled")
	}
	if after := handlerGoroutines(); after != before {
		t.Errorf("handler goroutines before=%d after=%d", before, after)
	}
}
