// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/pathcheck"
	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
	procfs "github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

type helperStarts struct{ Launcher, Worker int }

// pageHelperCount observes actual own-image launcher and worker starts, including
// processes which exit before the response. It does not sample a process list.
func pageHelperCount(t *testing.T) func() helperStarts {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := executable + ".count"
	if err := os.Mkdir(marker, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(marker); err != nil {
			t.Error(err)
		}
	})
	return func() helperStarts {
		entries, err := os.ReadDir(marker)
		if err != nil {
			t.Fatal(err)
		}
		var starts helperStarts
		for _, entry := range entries {
			switch {
			case strings.HasPrefix(entry.Name(), "launcher-"):
				starts.Launcher++
			case strings.HasPrefix(entry.Name(), "worker-"):
				starts.Worker++
			default:
				t.Fatalf("unknown helper process role %q", entry.Name())
			}
		}
		return starts
	}
}

func TestRecordedPageUsesOneHelper(t *testing.T) {
	for _, route := range []string{"/rules", "/rules/change", "/logs", "/runs/" + rulesRunA, "/runs/" + rulesRunA + "/unused", "/runs/" + rulesRunA + "/least-privilege", "/runs/" + rulesRunB + "/rows?after=0"} {
		t.Run(route, func(t *testing.T) {
			f := newRulesFix(t)
			svc := &rules.Service{Ledger: f.root, Home: f.home, Machine: &config.Machine{Home: f.home}}
			f.s.cfg.Rules, f.s.cfg.Setup = svc, svc
			count := pageHelperCount(t)
			response := do(f.s, http.MethodGet, route, "127.0.0.1:"+strconv.Itoa(port), f.c)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			t.Logf("%s processes: %+v", route, count())
			if count() != (helperStarts{Launcher: 1, Worker: 1}) {
				t.Errorf("page processes: %+v; want one launcher and one worker", count())
			}
		})
	}
}

func TestCancelledFeedPageStartsNoHelper(t *testing.T) {
	for _, route := range []string{"/logs", "/runs/" + rulesRunA, "/runs/" + rulesRunB + "/rows?after=0"} {
		t.Run(route, func(t *testing.T) {
			f := newRulesFix(t)
			f.s.cfg.Rules = &rules.Service{Ledger: f.root, Home: f.home}
			count := pageHelperCount(t)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+route, nil).WithContext(ctx)
			request.AddCookie(f.c)
			f.s.ServeHTTP(httptest.NewRecorder(), request)
			if count() != (helperStarts{}) {
				t.Errorf("cancelled page processes: %+v", count())
			}
		})
	}
}

func TestOverviewPageUsesOneHelper(t *testing.T) {
	fixture := guidetest.Make(t, guidetest.Fresh)
	s := guideServer(t, fixture)
	cookie := login(t, s)
	count := pageHelperCount(t)
	response := do(s, http.MethodGet, "/", "127.0.0.1:"+strconv.Itoa(port), cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d", response.Code)
	}
	t.Logf("overview processes: %+v", count())
	if count() != (helperStarts{Launcher: 1, Worker: 1}) {
		t.Errorf("overview processes: %+v; want one launcher and one worker", count())
	}
}

func TestRecordedLinkSharesRequestHelper(t *testing.T) {
	f := newRulesFix(t)
	alias := filepath.Join(filepath.Dir(f.proj), "alias")
	if err := os.Symlink(f.proj, alias); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(alias, "agent.yaml")
	count := pageHelperCount(t)
	ctx, closeHelpers := contracts.WithHelperSession(context.Background())
	defer closeHelpers()
	if ref := rules.RefContext(ctx, source); ref != rules.RefLexical(f.source) {
		t.Fatalf("resolved ref=%s want=%s", ref, rules.RefLexical(f.source))
	}
	if _, err := (&rules.Service{Ledger: f.root, Home: f.home}).ForRequest(ctx).Contracts(); err != nil {
		t.Fatal(err)
	}
	if count() != (helperStarts{Launcher: 1, Worker: 1}) {
		t.Fatalf("link and catalogue processes: %+v; want one launcher and one worker", count())
	}
}

func TestCancelledRecordedLinkStartsNoHelper(t *testing.T) {
	f := newRulesFix(t)
	alias := filepath.Join(filepath.Dir(f.proj), "alias")
	if err := os.Symlink(f.proj, alias); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(alias, "agent.yaml")
	count := pageHelperCount(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ref := rules.RefContext(ctx, source); ref != rules.RefLexical(source) {
		t.Errorf("cancelled resolution inspected the alias: %s", ref)
	}
	if count() != (helperStarts{}) {
		t.Fatalf("cancelled link processes: %+v", count())
	}
}

func TestOverviewGuideStopsWithRequest(t *testing.T) {
	fixture := guidetest.Make(t, guidetest.Fresh)
	s := guideServer(t, fixture)
	original := computeGuide
	defer func() { computeGuide = original }()
	started := make(chan struct{})
	computeGuide = func(ctx context.Context, _ guide.Inputs) (guide.State, bool, error) {
		close(started)
		<-ctx.Done()
		return guide.State{}, false, ctx.Err()
	}
	priorLimit := guideCompute
	guideCompute = 2 * time.Second
	defer func() { guideCompute = priorLimit }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, closeHelpers := contracts.WithHelperSession(ctx)
	defer closeHelpers()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.setupGuide(ctx, &ledgerview.Snapshot{})
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("guide computation never started")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("guide continued after its request ended")
		<-done
	}
	if s.guide.last != nil {
		t.Fatal("cancelled guide was cached for the next viewer")
	}
}

// A started feed has the same request lifetime as source checks. Stopping the
// own-image worker proves HTTP return without waiting for its default deadline;
// a kernel-blocked filesystem worker remains owed in a guest.
func TestFeedHelperStopsWithRequest(t *testing.T) {
	f := newRulesFix(t)
	f.s.cfg.Rules = &rules.Service{Ledger: f.root, Home: f.home}
	marker := helperHangMarker(t)
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+"/logs", nil).WithContext(ctx)
	request.AddCookie(f.c)
	response := httptest.NewRecorder()
	before := handlerGoroutines()
	done := make(chan struct{})
	go func() { defer close(done); f.s.ServeHTTP(response, request) }()
	defer func() { cancel(); <-done }()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Observe the actual stopped worker before cancelling, so process startup
	// time cannot decide whether this test exercised an abandoned exchange.
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	startup := time.NewTimer(5 * time.Second)
	defer startup.Stop()
	stopped := false
	for !stopped {
		paths, err := filepath.Glob(executable + ".pid.*")
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			pid, err := strconv.Atoi(strings.TrimPrefix(path, executable+".pid."))
			if err != nil {
				t.Fatal(err)
			}
			if state, err := procfs.New().Stat(pid); err == nil && state.State == 'T' {
				stopped = true
				break
			}
		}
		if stopped {
			break
		}
		select {
		case <-done:
			t.Fatal("handler ended before its worker was stopped")
		case <-startup.C:
			t.Fatal("no worker reached the stopped state")
		case <-ticker.C:
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("feed continued after request cancellation")
		<-done
	}
	if after := handlerGoroutines(); after != before {
		t.Errorf("handler goroutines before=%d after=%d", before, after)
	}
}

func TestCancelledGuideDoesNotWaitForAnotherViewer(t *testing.T) {
	fixture := guidetest.Make(t, guidetest.Fresh)
	s := guideServer(t, fixture)
	original := computeGuide
	defer func() { computeGuide = original }()
	started, release := make(chan struct{}), make(chan struct{})
	computeGuide = func(ctx context.Context, _ guide.Inputs) (guide.State, bool, error) {
		close(started)
		select {
		case <-release:
			return guide.State{}, false, nil
		case <-ctx.Done():
			return guide.State{}, false, ctx.Err()
		}
	}
	first, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	first, closeFirst := contracts.WithHelperSession(first)
	defer closeFirst()
	firstDone := make(chan struct{})
	go func() { defer close(firstDone); s.setupGuide(first, &ledgerview.Snapshot{}) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("first viewer never started")
	}
	second, cancelSecond := context.WithCancel(context.Background())
	cancelSecond()
	secondDone := make(chan struct{})
	go func() { defer close(secondDone); s.setupGuide(second, &ledgerview.Snapshot{}) }()
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		t.Error("cancelled viewer waited for another viewer's computation")
	}
	close(release)
	<-firstDone
	<-secondDone
}

func TestGuideHelperPreservesCallerCompilerContext(t *testing.T) {
	fixture := guidetest.Make(t, guidetest.ContractMade)
	// A caller's invalid host-IPC override must also fail the guide's compile in
	// its empty-environment worker. Otherwise the guide claims this file compiles.
	if err := os.Symlink("ipc-loop", filepath.Join(fixture.Root, "ipc-loop")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMUX_TMPDIR", fixture.Root+"/ipc-loop/../ipc")
	t.Setenv("SCREENDIR", "")
	in := fixture.Inputs(t)
	expected := guide.Compute(context.Background(), in)
	blocked := false
	for _, step := range expected.Steps {
		if step.ID == guide.StepContract && step.State == guide.Blocked && step.Fact != nil && strings.Contains(*step.Fact, "TMUX_TMPDIR") {
			blocked = true
		}
	}
	if !blocked {
		t.Fatalf("fixture did not refuse the caller override: %+v", expected)
	}
	got, built, err := checkedGuide(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	wantJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wantJSON, gotJSON) || built != expected.Next.Built() {
		t.Fatalf("helper guide differs from caller:\nwant=%s\ngot=%s\nbuilt=%t want=%t", wantJSON, gotJSON, built, expected.Next.Built())
	}
}

func TestGuideHelperRequiresCallerContext(t *testing.T) {
	fixture := guidetest.Make(t, guidetest.Fresh)
	in := fixture.Inputs(t)
	in.Machine = nil
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var reply []byte
	err = pathcheck.Call(context.Background(), "control.guide", guideRequest{Inputs: data}, &reply)
	if err == nil || !strings.Contains(err.Error(), "missing guide caller context") {
		t.Fatalf("helper accepted guide without caller context: %v", err)
	}
}
