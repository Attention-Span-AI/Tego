// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A request scope has a bound of its own (WithRequestScope): a dashboard page must be answered before its server's
// write deadline, which closes the connection with no response at all. Every wait of the scope's helper exchanges ends
// by it, whatever start-up or location budget would still allow.

// fullPool is a pool of two helper slots, both taken, as a host with every reservation held by other commands' stuck
// helpers looks to a process that knows nothing of them.
func fullPool(t *testing.T) {
	t.Helper()
	allWorkers, governed := processWorkers, governedWorkers
	processWorkers, governedWorkers = helperPools(2)
	t.Cleanup(func() { processWorkers, governedWorkers = allWorkers, governed })
	for range cap(processWorkers) {
		processWorkers <- struct{}{}
	}
}

// requestScopeOf is the budget of a request scope with the given bound, with the start-up budget the product has (long).
func requestScopeOf(within time.Duration) *budget {
	b := scopeOf(10 * time.Second)
	b.until = time.Now().Add(within)
	return b
}

// A page at capacity waits for a slot no longer than its bound, and says how many helpers are alive.
func TestRequestScopeEndsTheWaitForAHelperSlotAtItsBound(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	fullPool(t)
	ctx, closeSession := WithHelperSession(context.Background())
	defer closeSession()
	ctx = context.WithValue(ctx, budgetKey{}, requestScopeOf(300*time.Millisecond))
	begin := time.Now()
	_, err := exchange(ctx, nil)
	waited := time.Since(begin)
	if err == nil || !strings.Contains(err.Error(), "2 filesystem helpers are still alive") || !IsStartupUnavailable(err) {
		t.Fatalf("the refusal does not say why: %v", err)
	}
	if waited < 250*time.Millisecond || waited > 2*time.Second {
		t.Fatalf("a page at capacity waited %v, want its bound (300ms), not the start-up budget (10s)", waited)
	}
}

// The checks of one page share the bound: five of them at capacity take the bound once, and the ones after it
// refuse at once.
func TestRequestScopeBoundsAPageOfChecksTogether(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	fullPool(t)
	ctx, closeSession := WithHelperSession(context.Background())
	defer closeSession()
	ctx = context.WithValue(ctx, budgetKey{}, requestScopeOf(400*time.Millisecond))
	begin := time.Now()
	for i := range 5 {
		// Every check says why, in the words of the first: the pool is full, not "the time is spent".
		if _, err := exchange(ctx, nil); err == nil || !IsStartupUnavailable(err) || !strings.Contains(err.Error(), "2 filesystem helpers are still alive") {
			t.Fatalf("check %d: %v", i+1, err)
		}
	}
	if waited := time.Since(begin); waited < 350*time.Millisecond || waited > 2*time.Second {
		t.Fatalf("five checks of a page bounded at 400ms took %v", waited)
	}
}

// A helper that never becomes ready is given up at the bound too.
func TestRequestScopeEndsTheWaitForAReadyFrameAtItsBound(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	ctx := withScriptedBudget(t, context.Background(), requestScopeOf(300*time.Millisecond), func(w *scriptedWorker) {
		w.sendHeader(t)
		w.readRequest(t)
		<-release
	})
	begin := time.Now()
	_, err := exchange(ctx, []byte("request"))
	if !IsStartupUnavailable(err) || !errors.Is(err, context.DeadlineExceeded) || time.Since(begin) > 2*time.Second {
		t.Fatalf("a helper that never became ready: %v after %v", err, time.Since(begin))
	}
}

// A helper that is starved is not given more time than the page has: extensions are whole steps, and when the page has
// less than a step left the helper is refused, with the words of a helper starved to the cap, though its own cap is four
// times longer. Here the first expiry (300ms) is given a step (the page has 500ms more), the second (600ms) is not (200ms
// is less than a step).
func TestRequestScopeIsTheStarvedHelpersCapToo(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	useScheduler(t, &fakeScheduler{state: 'R', wait: 0.9})
	release := make(chan struct{})
	defer close(release)
	ctx := withScriptedBudget(t, context.Background(), requestScopeOf(800*time.Millisecond), blockedWorker(t, release))
	begin := time.Now()
	_, err := exchange(ctx, []byte("request"))
	waited := time.Since(begin)
	if !IsCheckTooSlow(err) || waited < 550*time.Millisecond || waited > 790*time.Millisecond {
		t.Fatalf("a starved helper in a page bounded at 800ms: %v after %v (its own cap is 1.2s)", err, waited)
	}
}

// A blocked helper is still the mount's at its own first budget: the bound does not change a refusal that came first.
func TestRequestScopeDoesNotChangeABlockedHelpersWords(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	release := make(chan struct{})
	defer close(release)
	ctx := withScriptedBudget(t, context.Background(), requestScopeOf(5*time.Second), blockedWorker(t, release))
	begin := time.Now()
	_, err := exchange(ctx, []byte("request"))
	if !IsLocationUnavailable(err) || time.Since(begin) > time.Second {
		t.Fatalf("%v after %v", err, time.Since(begin))
	}
}

// A helper paused for a compile that never ends is ended at the bound, in the compile's words, though the helper said it
// needed ten seconds.
func TestRequestScopeEndsAPausedHelperAtItsBound(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	ctx := withScriptedBudget(t, context.Background(), requestScopeOf(400*time.Millisecond), func(w *scriptedWorker) {
		w.sendHeader(t)
		w.readRequest(t)
		w.sendReady(t)
		w.sendPause(t, 10*time.Second)
		<-release
	})
	begin := time.Now()
	_, err := exchange(ctx, []byte("request"))
	if !IsCompileUnfinished(err) || time.Since(begin) < 350*time.Millisecond || time.Since(begin) > 2*time.Second {
		t.Fatalf("a paused helper in a page bounded at 400ms: %v after %v", err, time.Since(begin))
	}
}

// A scope with no bound is unchanged (a command), and a scope that is a scope already is not rebounded.
func TestWithRequestScopeOnlyBoundsNewScopes(t *testing.T) {
	if _, bounded := ScopeLeft(WithScope(context.Background())); bounded {
		t.Fatal("a plain scope has a bound")
	}
	ctx := WithRequestScope(context.Background(), time.Minute)
	if left, bounded := ScopeLeft(ctx); !bounded || left <= 59*time.Second || left > time.Minute {
		t.Fatalf("request scope: %v %v", left, bounded)
	}
	if again := WithRequestScope(ctx, time.Second); again != ctx {
		t.Fatal("a scope was bounded again")
	}
	if _, bounded := ScopeLeft(WithRequestScope(WithScope(context.Background()), time.Second)); bounded {
		t.Fatal("a plain scope was given a bound")
	}
}

// The whole of it through a real HTTP server: with a write deadline of 1.5 s, a page at capacity whose scope is
// bounded a second short of it is answered with the capacity words, and the same page unbounded has its connection
// closed with no response, which is what the dashboard did.
func TestPageAtCapacityIsAnsweredBeforeTheWriteDeadline(t *testing.T) {
	useLocationTimeout(t, 300*time.Millisecond)
	fullPool(t)
	const writeDeadline = 1500 * time.Millisecond
	serve := func(bound time.Duration) *httptest.Server {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, closeSession := WithHelperSession(r.Context())
			defer closeSession()
			b := scopeOf(3 * time.Second) // the wait for a slot would take 3 s
			if bound > 0 {
				b.until = time.Now().Add(bound)
			}
			ctx = context.WithValue(ctx, budgetKey{}, b)
			_, err := exchange(ctx, nil)
			w.WriteHeader(http.StatusServiceUnavailable)
			if err != nil {
				_, _ = io.WriteString(w, err.Error())
			}
		}))
		srv.Config.WriteTimeout = writeDeadline
		srv.Start()
		t.Cleanup(srv.Close)
		return srv
	}
	client := &http.Client{Timeout: 10 * time.Second}
	bounded := serve(writeDeadline - 500*time.Millisecond)
	begin := time.Now()
	resp, err := client.Get(bounded.URL)
	if err != nil {
		t.Fatalf("a page bounded below the write deadline got no response: %v after %v", err, time.Since(begin))
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), "2 filesystem helpers are still alive") || time.Since(begin) > writeDeadline {
		t.Fatalf("the answer: %d %q after %v", resp.StatusCode, body, time.Since(begin))
	}
	unbounded := serve(0)
	if resp, err := client.Get(unbounded.URL); err == nil {
		resp.Body.Close()
		t.Fatalf("a page with no bound was answered (%d): the control no longer shows the defect", resp.StatusCode)
	}
}
