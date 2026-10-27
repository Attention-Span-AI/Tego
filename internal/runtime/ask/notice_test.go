// SPDX-License-Identifier: Apache-2.0

package ask

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/askproto"
)

// TestBrokerListMarksACutRule (G11): a listed request whose rule is longer than askproto.MaxSummaryRule says it was
// cut (rule_truncated), as a cut target does, so a reader of `tego ask --json` never takes the prefix for the rule.
func TestBrokerListMarksACutRule(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule string
		cut  bool
	}{
		{"short", "net.ask[0]", false},
		{"exactly the bound", strings.Repeat("r", askproto.MaxSummaryRule), false},
		{"longer", "fs.ask[\"" + strings.Repeat("d/", 60) + "\"]", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, dir := testBroker(t, nil)
			req := testRequest()
			req.Rule = tc.rule
			done := make(chan struct{})
			go func() { defer close(done); _, _ = b.Request(context.Background(), req) }()
			got := waitAsk(t, dir)
			if got.RuleTruncated != tc.cut || len(got.Rule) > askproto.MaxSummaryRule || !strings.HasPrefix(tc.rule, got.Rule) {
				t.Errorf("listed rule %q truncated %v, want a prefix of %q truncated %v", got.Rule, got.RuleTruncated, tc.rule, tc.cut)
			}
			if _, err := AnswerFor(context.Background(), dir, os.Getpid(), got.AskID, false, false); err != nil {
				t.Fatal(err)
			}
			<-done
		})
	}
}

// TestBrokerPendingIsToldOnceAPersonCanAnswer: Options.Pending hears of a held request once it is listed, so a notice
// sent from it names an ask `tego ask` already shows; it hears nothing of a request a standing answer decides, which
// nobody is asked about.
func TestBrokerPendingIsToldOnceAPersonCanAnswer(t *testing.T) {
	var mu sync.Mutex
	var told []Request
	var listedWhenTold []bool
	var dir string
	// toldOnce is closed once Pending has listed: the answer below waits for it, or a fast answer could take the
	// request off the list before Pending reads it, and listed-when-told would be false for the test's own reason.
	toldOnce := make(chan struct{})
	var once sync.Once
	b, d := testBroker(t, func(o *Options) {
		o.Timeout = 10 * time.Second
		o.Pending = func(r Request) {
			items, err := ListFor(context.Background(), dir, os.Getpid())
			mu.Lock()
			defer mu.Unlock()
			told = append(told, r)
			listedWhenTold = append(listedWhenTold, err == nil && len(items) == 1 && items[0].AskID == r.AskID)
			once.Do(func() { close(toldOnce) })
		}
	})
	dir = d
	first := make(chan Decision, 1)
	go func() { d, _ := b.Request(context.Background(), testRequest()); first <- d }()
	id := waitAsk(t, dir).AskID
	select {
	case <-toldOnce:
	case <-time.After(5 * time.Second):
		t.Fatal("Pending was not told of a listed request")
	}
	if _, err := AnswerFor(context.Background(), dir, os.Getpid(), id, true, true); err != nil {
		t.Fatal(err)
	}
	if d := <-first; !d.Approved {
		t.Fatalf("first request: %+v", d)
	}
	// The same operation, rule and target again: the standing approval answers it, and no person is asked.
	if d, err := b.Request(context.Background(), testRequest()); err != nil || !d.Approved {
		t.Fatalf("standing request: %+v %v", d, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(told) != 1 || told[0].AskID != id || !listedWhenTold[0] {
		t.Fatalf("Pending was told %+v (listed then: %v), want once, of %s, already listed", told, listedWhenTold, id)
	}
}
