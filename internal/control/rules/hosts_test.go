// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// hostResolver resolves every name but those in bad (no such host) and counts the lookups it is asked for. With hold
// set, a lookup waits until hold is closed, whatever its context says.
type hostResolver struct {
	bad  map[string]bool
	hold chan struct{}

	mu    sync.Mutex
	asked []string
}

func (r *hostResolver) LookupNetIP(ctx context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	r.asked = append(r.asked, host)
	r.mu.Unlock()
	if r.hold != nil {
		<-r.hold
		return nil, ctx.Err()
	}
	if r.bad[host] {
		return nil, &net.DNSError{Err: "no such host", Name: host, Server: "127.0.0.53:53", IsNotFound: true}
	}
	return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
}

func (r *hostResolver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.asked)
}

// typoHost is a host name with a typo, which the tests' resolver does not resolve.
const typoHost = "api.exmple.com"

var typoWarning = []UnresolvedHost{{Host: typoHost, Why: "no such host"}}

// TestChangePreviewWarnsUnresolvedHost: a host name the Change rules form adds that does not resolve here is the
// preview's warning, never a refusal: the change is saved with the preview's base and ack, and the save looks no host
// up. A host that resolves, and one removed, say nothing.
func TestChangePreviewWarnsUnresolvedHost(t *testing.T) {
	f := newFixture(t)
	r := &hostResolver{bad: map[string]bool{typoHost: true}}
	f.s.Resolver = r
	ctx := context.Background()
	c := f.ref(t, f.contract)
	req := ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"add", "net.allow", typoHost + ":443"}}}
	p, err := f.s.PlanChange(ctx, req)
	if err != nil || p.Err != "" {
		t.Fatalf("plan: %+v %v", p, err)
	}
	if !slices.Equal(p.Unresolved, typoWarning) {
		t.Errorf("Unresolved = %+v, want %+v", p.Unresolved, typoWarning)
	}
	asked := r.count()
	req.Ack = p.Ack
	if _, err := f.s.ApplyChange(ctx, req); err != nil {
		t.Fatalf("a host that does not resolve refused the write: %v", err)
	}
	if !strings.Contains(f.text(t), typoHost+":443") {
		t.Errorf("not written:\n%s", f.text(t))
	}
	if n := r.count(); n != asked {
		t.Errorf("the save looked hosts up again: %d lookups, %d at the preview", n, asked)
	}
	c = f.ref(t, f.contract)
	for _, e := range []Edit{{"add", "net.ask", "api.example.org:443"}, {"remove", "net.allow", "api.example.com:443"}} {
		p, err := f.s.PlanChange(ctx, ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{e}})
		if err != nil || p.Err != "" || p.Unresolved != nil {
			t.Errorf("%v: Unresolved %+v, Err %q, %v", e, p.Unresolved, p.Err, err)
		}
	}
}

// TestChangePreviewHostBudget: a resolver that never answers holds the preview no longer than the host budget, and
// the host is said to have given no answer in it.
func TestChangePreviewHostBudget(t *testing.T) {
	f := newFixture(t)
	r := &hostResolver{hold: make(chan struct{})}
	t.Cleanup(func() { close(r.hold) })
	f.s.Resolver, f.s.hostBudget = r, 50*time.Millisecond
	c := f.ref(t, f.contract)
	start := time.Now()
	p, err := f.s.PlanChange(context.Background(), ChangeReq{Ref: c.Ref, Base: c.Base,
		Edits: []Edit{{"add", "net.allow", "slow.example.com:443"}}})
	if elapsed := time.Since(start); elapsed > f.s.hostBudget+time.Second {
		t.Errorf("the preview took %s; the host budget is %s", elapsed, f.s.hostBudget)
	}
	if err != nil || p.Err != "" {
		t.Fatalf("plan: %+v %v", p, err)
	}
	if want := []UnresolvedHost{{Host: "slow.example.com", Why: "no answer within 50ms"}}; !slices.Equal(p.Unresolved, want) {
		t.Errorf("Unresolved = %+v, want %+v", p.Unresolved, want)
	}
}

// TestRawPreviewWarnsUnresolvedHost: a free edit's Check warns of a host name its text adds that does not resolve here,
// and the text is still saved, with no lookup at the save.
func TestRawPreviewWarnsUnresolvedHost(t *testing.T) {
	f := newFixture(t)
	r := &hostResolver{bad: map[string]bool{typoHost: true}}
	f.s.Resolver = r
	ctx := context.Background()
	c := f.ref(t, f.contract)
	text := strings.Replace(baseText, `allow: ["api.example.com:443"]`, `allow: ["api.example.com:443", "`+typoHost+`:443"]`, 1)
	req := RawReq{Ref: c.Ref, Base: c.Base, Text: []byte(text)}
	p, err := f.s.PlanRaw(ctx, req)
	if err != nil || p.Err != "" {
		t.Fatalf("check: %+v %v", p, err)
	}
	if !slices.Equal(p.Unresolved, typoWarning) {
		t.Errorf("Unresolved = %+v, want %+v", p.Unresolved, typoWarning)
	}
	asked := r.count()
	req.Ack = p.Ack
	if _, err := f.s.ApplyRaw(ctx, req); err != nil {
		t.Fatalf("a host that does not resolve refused the save: %v", err)
	}
	if got := f.text(t); got != text {
		t.Errorf("saved:\n%s", got)
	}
	if n := r.count(); n != asked {
		t.Errorf("the save looked hosts up again: %d lookups, %d at the check", n, asked)
	}
}

// TestActPreviewWarnsUnresolvedHost: "Allow next time" on a refused connection to a host that does not resolve here
// warns on the event page's preview, and its confirm writes the rule without looking the host up again.
func TestActPreviewWarnsUnresolvedHost(t *testing.T) {
	f := newFixture(t)
	const run = "r-aaaa-0005-rules"
	f.writeRun(t, run, f.contract, 4, ledgertest.Event(t, record.KindRefused,
		record.RefusedPayload{Op: "connect", Target: typoHost + ":443"}, func(e *record.Event) {
			e.Rule, e.Reason = "unmatched", record.ReasonNetNotAllowed
		}))
	r := &hostResolver{bad: map[string]bool{typoHost: true}}
	f.s.Resolver = r
	ctx := context.Background()
	p, err := f.s.ActOn(ctx, ActReq{Run: run, Seq: 3, Action: "allow"})
	if err != nil || p.PickErr != "" || p.Diff == "" {
		t.Fatalf("preview: %+v %v", p, err)
	}
	if !slices.Equal(p.Unresolved, typoWarning) {
		t.Errorf("Unresolved = %+v, want %+v", p.Unresolved, typoWarning)
	}
	asked := r.count()
	w, err := f.s.ActOn(ctx, ActReq{Run: run, Seq: 3, Action: "allow", Write: true, Base: p.Base, Ack: p.Ack})
	if err != nil || !w.Saved {
		t.Fatalf("a host that does not resolve refused the confirm: %+v %v", w, err)
	}
	if !strings.Contains(f.text(t), typoHost+":443") {
		t.Errorf("not written:\n%s", f.text(t))
	}
	if n := r.count(); n != asked || w.Unresolved != nil {
		t.Errorf("the confirm looked hosts up again: %d lookups, %d at the preview; %+v", n, asked, w.Unresolved)
	}
}
