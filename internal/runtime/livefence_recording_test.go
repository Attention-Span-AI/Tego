// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/control/web"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestFenceRestoreRecordingReachesRunPage: a fence entry that was lifted and then restored keeps its host's later
// refusals out of the routine fold, proven on a recording the product made (the hand-written lines of the dashboard's
// own tests stay as extra cases: TestRestoredFenceRefusalOutsideRoutineFold and ledgerview's signal tests).
//
// What is the product's here: the run_start's fence and record minor (runLiveFence, launchMinor; its other fields are
// this test's) written by the ledger's writer; the fence seeded
// and put in force by the supervisor's start (startLiveBlocks); the lift written by the calls `tego lift` and the
// dashboard both make (liveblock.LiftKey, liveblock.Update, Overlay.Lift); the restore asked by the dashboard's own
// function (runact.Restore, which reads the run's lock and its recorded run_start before it writes Overlay.Restore);
// each change read and applied by the supervisor's poll (pollLiveBlocks), which stores the Set and queues the
// live-rule-lifted and live-rule-restored lines; those lines appended by the ledger's writer; and the recording
// read by the classifier (ledgerview.Signal) and by the run page served over a loopback connection.
//
// What is not exercised: the kernel. No cgroup, BPF program or seccomp filter is installed (the listener is
// fenceRunner's stand-in, the seam the lift tests use), so the connection that went through while the entry was lifted
// and the two refusals after the restore are queued by this test, with the fields the supervisor writes, on the lane
// the product's own lines take. The dashboard's lift function (runact.Lift) is not called either: it refuses a caller
// whose cgroup it cannot judge, which is every caller inside a container, and its seam for that is its package's own.
//
// This file is one of the tests allowed to import the dashboard (.golangci.yml engine-never-imports-control): the
// behaviour it checks spans both binaries.
func TestFenceRestoreRecordingReachesRunPage(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	r := fenceRunner(t)
	r.id = "r-aaaaaaaa-0000000000003-record"
	r.dir = filepath.Join(root, string(r.id))
	r.rt.FS = []agent.FSRule{{Path: r.dir, Resolved: r.dir, Kind: agent.FSDenyRead, BuiltIn: true}}
	run := string(r.id)

	w, err := ledger.Open(r.dir, record.RunRef{ID: run, Agent: "fenced"},
		ledger.WithAnchor(ledger.NewFileChainAnchor(filepath.Join(t.TempDir(), "chain.log"))))
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = w.Abandon()
		}
	})
	mode, fence := runLiveFence(r.rt)
	if err := w.WriteRunStart(record.RunStartPayload{Tier: "cgroup", Capture: "off", ContractHash: strings.Repeat("a", 64),
		Command: []string{"agent"}, Cwd: "/w/proj", Kernel: "6", StopGrace: "1s", RecordMinor: launchMinor,
		LiveMode: mode, LiveFence: fence}); err != nil {
		t.Fatal(err)
	}
	b, err := r.startLiveBlocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	refusedNow := func() bool {
		_, refused := b.Load().MatchInet(fenceDest, "", nil)
		return refused
	}
	if !refusedNow() {
		t.Fatal("the fence does not refuse its destination at the run's start")
	}

	// The lift, as `tego lift` and the dashboard write it, then the supervisor's poll.
	key, err := liveblock.LiftKey(r.dir, run)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := liveblock.Update(ctx, r.dir, run, func(o *liveblock.Overlay) (bool, error) {
		_, err := o.Lift(liveblock.KindNet, fenceNet, liveblock.By("cli"), time.Now(), time.Time{}, key)
		return err == nil, err
	}); err != nil {
		t.Fatal(err)
	}
	r.pollLiveBlocks(ctx, b)
	if refusedNow() {
		t.Fatal("the lift did not loosen the fence in force")
	}
	// The kernel's part, queued by hand: the connection that went through while the entry was lifted.
	r.queue.Emit(ledgertest.Event(t, record.KindNet, record.NetPayload{Proto: "tcp", Dst: fenceNet, Op: "connect"}, func(e *record.Event) {
		e.Source, e.Rule = record.SourceSeccomp, liveblock.FenceRule(liveblock.KindNet, fenceNet)
		e.Verdict, e.Authority = record.VerdictAllow, record.AuthorityRule
		e.Attr = &record.Attribution{Confidence: "unattributed", Method: "none"}
	}))

	// The restore, asked by the dashboard's own function, then the supervisor's poll.
	asked, err := runact.Restore(ctx, root, run, string(liveblock.KindNet), fenceNet, "dashboard")
	if err != nil {
		t.Fatalf("the dashboard's restore was refused: %v", err)
	}
	if asked.Word != runact.WordRestoreAsked || asked.Rule != liveblock.FenceRule(liveblock.KindNet, fenceNet) {
		t.Fatalf("the dashboard's restore asked %+v", asked)
	}
	r.pollLiveBlocks(ctx, b)
	if !refusedNow() {
		t.Error("the restore did not put the fence entry back in force")
	}
	// The kernel's part again: a refused connection to the restored host on another port, and one routine refusal
	// (a terminal the run holds no rule for), so the page has a routine fold to keep the host out of.
	host := fenceDest.Addr().String()
	r.queue.Emit(ledgertest.Event(t, record.KindRefused, record.RefusedPayload{Op: "net", Target: host + ":8443"}, func(e *record.Event) {
		e.Rule, e.Reason = "unmatched", record.ReasonNetNotAllowed
	}))
	r.queue.Emit(ledgertest.Event(t, record.KindRefused, record.RefusedPayload{Op: "open", Target: "/dev/tty"}, func(e *record.Event) {
		e.Rule, e.Reason = "held-unsupported", record.ReasonFSGate
	}))

	// The recording: every queued line through the ledger's writer, the product's two changes among them.
	r.queue.Close()
	var changes []string
	for ev := range r.queue.C() {
		if ev.Kind == record.KindGap {
			if p := ledgertest.Decode[record.GapPayload](t, ev); p.LiveBlock != nil {
				changes = append(changes, p.Why+" "+p.LiveBlock.Rule)
			}
		}
		if err := w.Append(ev); err != nil {
			t.Fatal(err)
		}
	}
	rule := liveblock.FenceRule(liveblock.KindNet, fenceNet)
	if want := []string{record.GapLiveRuleLifted + " " + rule, record.GapLiveRuleRestored + " " + rule}; !slices.Equal(changes, want) {
		t.Errorf("the product recorded the changes %q, want %q", changes, want)
	}
	if err := w.Close(record.RunEndPayload{Reason: "exit"}); err != nil {
		t.Fatal(err)
	}
	closed = true

	// The classifier, on that recording.
	loaded, err := ledgerview.LoadRun(root, run)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, g := range ledgerview.Signal(loaded, ledgerview.Sensitive{Cwd: loaded.Cwd}).Groups {
		if g.Subject == host {
			found = true
			if g.Background {
				t.Errorf("the classifier folds the restored host's refusal as routine (%s)", g.Why)
			}
		}
	}
	if !found {
		t.Errorf("the classifier has no group for the restored host %s", host)
	}

	// The run page, on that recording, over a loopback connection the dashboard's own peer check accepts.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := web.New(web.Config{Ledger: root, Port: ln.Addr().(*net.TCPAddr).Port, Token: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, stop := context.WithCancel(ctx)
	served := make(chan error, 1)
	go func() { served <- web.Serve(serveCtx, ln, server) }()
	defer func() {
		stop()
		if err := <-served; err != nil {
			t.Errorf("the dashboard's server: %v", err)
		}
	}()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	page := func(url string) (int, string) {
		resp, err := client.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(body)
	}
	if code, body := page(server.URL()); code != http.StatusOK {
		t.Fatalf("signing in: %d %s", code, body)
	}
	code, body := page("http://" + ln.Addr().String() + "/runs/" + run + "/refusals")
	start := strings.Index(body, `id="h-rf"`)
	if code != http.StatusOK || start < 0 {
		t.Fatalf("the run's refusals page: %d %s", code, body)
	}
	refusals := body[start:]
	at, routine := strings.Index(refusals, host), strings.Index(refusals, `id="bg"`)
	if at < 0 || routine < 0 || at > routine {
		t.Errorf("the restored host is at %d and the routine fold at %d: the page folds its refusal as routine", at, routine)
	}
}

// TestNameBlockRecordsItsAddressesForTheRunPage (ADR 0157): a person blocks a host by name, the launcher resolves it and
// writes the gap line, and the dashboard's classifier, reading that recording, knows the address the run reached under a
// CIDR entry is the blocked host: its group is neither folded as routine nor "name unknown". The line passes the ledger
// Writer's own validation at the revision the run's run_start declares (launchMinor), and a recording whose block line
// names no address (what a launcher of an older build wrote) still reads "name unknown".
func TestNameBlockRecordsItsAddressesForTheRunPage(t *testing.T) {
	const host, addr = "api.example.test", "2001:db8::7"
	for _, c := range []struct {
		name    string
		answers []netip.Addr
		known   bool
	}{
		{"the lookup answered", []netip.Addr{netip.MustParseAddr(addr)}, true},
		{"the lookup answered nothing", nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var now liveblock.Clock
			r, _ := blockHostRunner(t, host, &now, func() ([]netip.Addr, error) {
				if len(c.answers) == 0 {
					return nil, errors.New("no such host")
				}
				return c.answers, nil
			})
			root := t.TempDir()
			r.id = "r-aaaaaaaa-0000000000004-record"
			r.dir = filepath.Join(root, string(r.id))
			run := string(r.id)
			w, err := ledger.Open(r.dir, record.RunRef{ID: run, Agent: "blocked"},
				ledger.WithAnchor(ledger.NewFileChainAnchor(filepath.Join(t.TempDir(), "chain.log"))))
			if err != nil {
				t.Fatal(err)
			}
			closed := false
			t.Cleanup(func() {
				if !closed {
					_ = w.Abandon()
				}
			})
			if err := w.WriteRunStart(record.RunStartPayload{Tier: "landlock", Capture: "off", ContractHash: strings.Repeat("a", 64),
				Command: []string{"agent"}, Cwd: "/w/proj", Kernel: "6", StopGrace: "1s", RecordMinor: launchMinor}); err != nil {
				t.Fatal(err)
			}
			b := &liveBlocks{}
			changeBlock(t, r, true, liveblock.KindNet, host)
			r.pollLiveBlocks(context.Background(), b)
			// The run's part: an address reached under a CIDR entry (a line that names no host), then the refused try.
			r.queue.Emit(ledgertest.Event(t, record.KindNet, record.NetPayload{Proto: "tcp", Dst: "[" + addr + "]:443", Op: "connect"}, func(e *record.Event) {
				e.Source, e.Rule = record.SourceSeccomp, "net[tcp://2001:db8::/32:443]"
				e.Verdict, e.Authority = record.VerdictAllow, record.AuthorityRule
				e.Attr = &record.Attribution{Confidence: "unattributed", Method: "none"}
			}))
			r.queue.Emit(ledgertest.Event(t, record.KindRefused, record.RefusedPayload{Op: "net", Target: "[" + addr + "]:8443"}, func(e *record.Event) {
				e.Rule, e.Reason = "unmatched", record.ReasonNetNotAllowed
			}))
			r.queue.Close()
			for ev := range r.queue.C() {
				if err := w.Append(ev); err != nil {
					t.Fatalf("the ledger refused a line the launcher queued: %v", err)
				}
			}
			if err := w.Close(record.RunEndPayload{Reason: "exit"}); err != nil {
				t.Fatal(err)
			}
			closed = true

			loaded, err := ledgerview.LoadRun(root, run)
			if err != nil {
				t.Fatal(err)
			}
			var g *ledgerview.Group
			sig := ledgerview.Signal(loaded, ledgerview.Sensitive{Cwd: loaded.Cwd})
			for i := range sig.Groups {
				if sig.Groups[i].Rule == "unmatched" {
					g = &sig.Groups[i]
				}
			}
			if g == nil {
				t.Fatalf("no refusal group: %+v", sig.Groups)
			}
			if g.Background {
				t.Errorf("the refused try at a blocked host's address is folded as routine (%s)", g.Why)
			}
			if c.known && (g.BlockName != host || g.NameUnknown != "") {
				t.Errorf("BlockName %q NameUnknown %q: want the block's name and no unknown", g.BlockName, g.NameUnknown)
			}
			if !c.known && (g.BlockName != "" || g.NameUnknown == "") {
				t.Errorf("BlockName %q NameUnknown %q: want the name unknown", g.BlockName, g.NameUnknown)
			}
		})
	}
}
