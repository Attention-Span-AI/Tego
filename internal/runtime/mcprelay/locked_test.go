// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/mcptools"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/policy/mcptool"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The rule of C208 (ADR 0125, ADR 0126 Amendment 2026-11-21): a Locked run is never looser than its contract while it
// runs, and the relay, which applies the overlay, holds to it whoever wrote the overlay. The writers refuse a loosening
// (mcpact, `tego mcp`); this is the consumer's half, for a file written some other way.

func lockedRules() Server {
	return Server{Name: "files", Command: filesCmd,
		Rules: mcptool.Rules{Deny: []string{"delete_file", "delete_dir"}, Ask: []string{"write_file"}}}
}

// writeSwitches writes the overlay's switches into dir the way a same-user process outside the run could.
func writeSwitches(t *testing.T, dir string, sw ...[3]string) {
	t.Helper()
	for _, s := range sw {
		if _, err := mcptools.Update(context.Background(), dir, "r-test", func(o *mcptools.Overlay) (bool, error) {
			return o.Set(s[0], s[1], s[2], "uid:1 pid:2 not-tego-writer", time.Now())
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// startIn is a started service over a run directory that already holds an overlay.
func startIn(t *testing.T, dir string, adjustable bool, servers ...Server) (*Service, *sink) {
	t.Helper()
	opts := Options{Servers: servers, Exe: "/usr/bin/tego", Poll: 20 * time.Millisecond, Adjustable: adjustable,
		admit:     func(net.Conn, int, uint64) (admission, error) { return admission{pid: os.Getpid()}, nil },
		stillShim: func(admission) bool { return true }}
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	sk := &sink{}
	if err := s.Start(context.Background(), source.RunRef{ID: "r-test", Agent: "a", Dir: dir, CgroupID: 1}, sk); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	return s, sk
}

// changes are the mcp-tool-changed lines as "decision by".
func changes(t *testing.T, sk *sink) []string {
	t.Helper()
	var out []string
	for _, e := range sk.of(record.KindGap) {
		var p record.GapPayload
		if err := e.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if p.Why == record.GapMCPToolChanged && p.MCPTool != nil {
			out = append(out, p.MCPTool.Tool+" "+p.MCPTool.Decision+" "+p.MCPTool.By)
		}
	}
	return out
}

func TestLockedRunHoldsLooseningSwitchesOutOfForce(t *testing.T) {
	s, sk, dir := startLocked(t, lockedRules())
	var asked []string
	var mu sync.Mutex
	s.ConfigureMCPAsk(func(_ context.Context, r ask.Request) (ask.Decision, error) {
		mu.Lock()
		asked = append(asked, r.Target)
		mu.Unlock()
		return ask.Decision{Reason: ask.ReasonDenied}, nil
	})
	writeSwitches(t, dir,
		[3]string{"files", "delete_file", "allow"}, // deny -> allow: looser
		[3]string{"files", "write_file", "allow"},  // ask -> allow: looser
		[3]string{"files", "delete_dir", "ask"},    // deny -> ask: looser
		[3]string{"files", "read_file", "deny"},    // allow -> deny: tighter
		[3]string{"files", "note_file", "ask"},     // allow -> ask: tighter
	)
	sh, _ := dial(t, s, "files", filesCmd)
	for i, c := range []struct{ tool, rule string }{
		{"delete_file", "mcp[files].tools.deny[delete_file]"},
		{"delete_dir", "mcp[files].tools.deny[delete_dir]"},
		{"read_file", "mcp[files].live[read_file]"},
	} {
		sh.client(toolCall(i+1, c.tool))
		f := sh.read()
		if f.ToServer != nil || !strings.Contains(string(f.ToClient), c.rule) {
			t.Fatalf("%s: to the server %q, to the client %q, want the rule %s", c.tool, f.ToServer, f.ToClient, c.rule)
		}
	}
	// An ask the person is asked about stays an ask: the switch to allow was not in force.
	sh.client(toolCall(4, "write_file"))
	if f := sh.read(); !strings.Contains(string(f.ToClient), "ask-denied") {
		t.Fatalf("write_file: %+v", f)
	}
	sh.client(toolCall(5, "note_file"))
	if f := sh.read(); !strings.Contains(string(f.ToClient), "ask-denied") {
		t.Fatalf("note_file, tightened to ask: %+v", f)
	}
	mu.Lock()
	if strings.Join(asked, ",") != "files write_file,files note_file" {
		t.Fatalf("asked %v", asked)
	}
	mu.Unlock()
	// Each loosening is a line that says the contract decides; each tightening is the line of what is in force.
	got := changes(t, sk)
	want := []string{
		"delete_file reset uid:1 pid:2 not-tego-writer" + HeldByLocked,
		"write_file reset uid:1 pid:2 not-tego-writer" + HeldByLocked,
		"delete_dir reset uid:1 pid:2 not-tego-writer" + HeldByLocked,
		"read_file deny uid:1 pid:2 not-tego-writer",
		"note_file ask uid:1 pid:2 not-tego-writer",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("change lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The record revision does not move: every line the relay wrote, the held ones included, is one this revision reads.
	for _, ev := range append(sk.of(record.KindGap), sk.of(record.KindMCP)...) {
		if b, err := ev.MarshalLineAt(record.Minor); err != nil {
			t.Errorf("%s line not valid at %d: %v (%s)", ev.Kind, record.Minor, err, b)
		}
	}
}

// TestAdjustableRunTakesTheSameSwitches is the contrast: the same overlay on an Adjustable run is in force.
func TestAdjustableRunTakesTheSameSwitches(t *testing.T) {
	s, sk, dir := start(t, nil, lockedRules())
	writeSwitches(t, dir, [3]string{"files", "delete_file", "allow"})
	sh, _ := dial(t, s, "files", filesCmd)
	sh.client(toolCall(1, "delete_file"))
	if f := sh.read(); f.ToServer == nil {
		t.Fatalf("an Adjustable run refused a live allow: %s", f.ToClient)
	}
	if got := changes(t, sk); len(got) != 1 || !strings.HasPrefix(got[0], "delete_file allow ") || strings.Contains(got[0], "Locked") {
		t.Fatalf("change lines %v", got)
	}
}

// TestRelayWithoutAModeIsLocked: the zero value of Options is a Locked run, so a caller that does not say never gets the
// Adjustable behaviour.
func TestRelayWithoutAModeIsLocked(t *testing.T) {
	dir := t.TempDir()
	writeSwitches(t, dir, [3]string{"files", "delete_file", "allow"})
	s, err := New(Options{Servers: []Server{lockedRules()}, Exe: "/usr/bin/tego"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	if s.Adjustable() {
		t.Fatal("a relay built without a mode is Adjustable")
	}
	if err := s.Start(context.Background(), source.RunRef{ID: "r-test", Dir: dir, CgroupID: 1}, &sink{}); err != nil {
		t.Fatal(err)
	}
	if got := s.decide("files", "delete_file"); got.Decision != mcptool.Deny {
		t.Fatalf("decided %+v", got)
	}
}

// TestLockedRunStartsWithTheSwitchesThatAreThere: a loosening switch already in the overlay when the relay starts is held
// out of force and has its line, as one read later does.
func TestLockedRunStartsWithTheSwitchesThatAreThere(t *testing.T) {
	dir := t.TempDir()
	writeSwitches(t, dir, [3]string{"files", "delete_file", "allow"}, [3]string{"files", "read_file", "deny"})
	s, sk := startIn(t, dir, false, lockedRules())
	if got := s.decide("files", "delete_file"); got.Decision != mcptool.Deny {
		t.Fatalf("decided %+v", got)
	}
	if got := s.decide("files", "read_file"); got.Decision != mcptool.Deny || got.Rule != "mcp[files].live[read_file]" {
		t.Fatalf("a tightening switch that was there at the start: %+v", got)
	}
	got := changes(t, sk)
	if len(got) != 1 || got[0] != "delete_file reset uid:1 pid:2 not-tego-writer"+HeldByLocked {
		t.Fatalf("change lines %v: the held switch has one, the tightening (which is in force) is not a change of the run", got)
	}
	// An Adjustable run says nothing of the switches it starts with.
	_, sk2 := startIn(t, dir, true, lockedRules())
	if got := changes(t, sk2); len(got) != 0 {
		t.Fatalf("an Adjustable run wrote %v at its start", got)
	}
}

// TestLockedRunWithAnUnreadableOverlayKeepsItsContract: an overlay the relay cannot read leaves the contract (and the
// switches it read before) in force; it never reads as an Adjustable run's open door.
func TestLockedRunWithAnUnreadableOverlayKeepsItsContract(t *testing.T) {
	for _, garbage := range []string{"not json", `{"version":99}`, strings.Repeat("x", 1<<10)} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, mcptools.FileName), []byte(garbage), 0o600); err != nil {
			t.Fatal(err)
		}
		var log bytes.Buffer
		s, err := New(Options{Servers: []Server{lockedRules()}, Exe: "/usr/bin/tego", Poll: time.Hour, Logger: slog.New(slog.NewTextHandler(&log, nil))})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Start(context.Background(), source.RunRef{ID: "r-test", Dir: dir, CgroupID: 1}, &sink{}); err != nil {
			t.Fatal(err)
		}
		if got := s.decide("files", "delete_file"); got.Decision != mcptool.Deny || got.Rule != "mcp[files].tools.deny[delete_file]" {
			t.Fatalf("with %q in the overlay: %+v", garbage, got)
		}
		if got := s.decide("files", "read_file"); got.Decision != mcptool.Allow {
			t.Fatalf("with %q in the overlay, an allowed tool: %+v", garbage, got)
		}
		_ = s.Stop()
	}
}

// TestLockedRunSwitchLandingMidBatch: a loosening that lands while a batch's asked member waits is not in force for the
// batch's other members or for the next call, and the held member is decided again as a call is.
func TestLockedRunSwitchLandingMidBatch(t *testing.T) {
	s, sk, dir := startLocked(t, lockedRules())
	s.ConfigureMCPAsk(func(ctx context.Context, _ ask.Request) (ask.Decision, error) {
		writeSwitches(t, dir, [3]string{"files", "delete_file", "allow"}, [3]string{"files", "write_file", "allow"})
		return ask.Decision{Approved: true}, nil
	})
	sh, _ := dial(t, s, "files", filesCmd)
	sh.client(batchOf(toolCall(1, "write_file"), toolCall(2, "delete_file")))
	toClient, toServer := sh.frames(2)
	// delete_file was refused when its member was decided, and the approved write_file went on as the person approved it.
	if len(toClient) != 1 || len(toServer) != 1 || strings.Join(toolsOf(t, toServer[0]), ",") != "tools/call:write_file" {
		t.Fatalf("to the client %q, to the server %q", toClient, toServer)
	}
	if id, rule, _, _, _ := answered(t, members(t, toClient[0])[0]); id != "2" || rule != "mcp[files].tools.deny[delete_file]" {
		t.Fatalf("answer %s", toClient[0])
	}
	sh.client(toolCall(3, "delete_file"))
	if f := sh.read(); f.ToServer != nil {
		t.Fatalf("delete_file passed after the switch landed: %+v", f)
	}
	if got := changes(t, sk); len(got) != 2 {
		t.Fatalf("change lines %v", got)
	}
}

func TestLockedRunOverHTTP(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc((&recorder{}).handler))
	t.Cleanup(up.Close)
	s, sk, dir := startLocked(t, Server{Name: "web", URL: up.URL + "/mcp", Rules: webRules()})
	s.https[0].admitConn = func(netip.AddrPort, netip.AddrPort, uint64) error { return nil }
	s.https[0].holderPID = os.Getpid
	writeSwitches(t, dir, [3]string{"web", "delete_file", "allow"})
	relay := s.httpURLs()["web"]
	code, body, _ := postJSON(t, relay, toolCall(1, "delete_file"))
	if code != 200 || !strings.Contains(body, "mcp[web].tools.deny[delete_file]") {
		t.Fatalf("status %d: %s", code, body)
	}
	code, body, _ = postJSON(t, relay, batchOf(toolCall(2, "delete_file"), toolCall(3, "read_file")))
	if code != 200 || !strings.Contains(body, "mcp[web].tools.deny[delete_file]") || !strings.Contains(body, `"id":3,"result"`) {
		t.Fatalf("status %d: %s", code, body)
	}
	// The list still hides it, as it did before the switch.
	if got := changes(t, sk); len(got) != 1 || !strings.Contains(got[0], "Locked") {
		t.Fatalf("change lines %v", got)
	}
}
