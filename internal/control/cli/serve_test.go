// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/handoff"
	"github.com/attention-span-ai/tego/internal/runlock"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestServeUsesOneMachineSnapshot(t *testing.T) {
	first, second := config.Builtin(), config.Builtin()
	first.Home, second.Home = filepath.Join(t.TempDir(), "first-home"), filepath.Join(t.TempDir(), "second-home")
	for _, home := range []string{first.Home, second.Home} {
		if err := os.Mkdir(home, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	first.LedgerRoot.Value, second.LedgerRoot.Value = t.TempDir(), t.TempDir()
	oldLoader, oldAnchor := loadMachineSnapshot, anchorPath
	var loads atomic.Int32
	loadMachineSnapshot = func(config.Sources, string, int, config.TrustMode) (*config.Machine, []config.Diagnostic, error) {
		if loads.Add(1) == 1 {
			return first, nil, nil
		}
		return second, nil, nil
	}
	anchorPath = machineAnchorPath
	t.Cleanup(func() { loadMachineSnapshot, anchorPath = oldLoader, oldAnchor })
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var so, se syncBuffer
	done := make(chan int, 1)
	go func() { done <- cmdServe().Run(ctx, []string{"--addr", "127.0.0.1:0"}, &so, &se) }()
	for end := time.Now().Add(5 * time.Second); !strings.Contains(se.String(), "chains:") && time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve: %d %s", code, se.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}
	if loads.Load() != 1 || !strings.Contains(se.String(), "ledger: "+first.LedgerRoot.Value) ||
		!strings.Contains(se.String(), filepath.Join(first.Home, ".tego", "chain.log")) || strings.Contains(se.String(), second.Home) {
		t.Fatalf("startup mixed machine snapshots: loads=%d %s", loads.Load(), se.String())
	}
	s := ruleService(t.TempDir(), "/chain.log", first, false)
	if s.Machine != first || !slices.Contains(s.Refuse, first.LedgerRoot.Value) || slices.Contains(s.Refuse, second.LedgerRoot.Value) || loads.Load() != 1 {
		t.Fatalf("rule service reloaded or mixed its snapshot: loads=%d roots=%v", loads.Load(), s.Refuse)
	}
}

// TestServeSummarySaysWhatItStarts: serve starts the dashboard and nothing else (ADR 0100's control service is not
// built), so the line both binaries' usage gives it names the dashboard and promises no control service.
func TestServeSummarySaysWhatItStarts(t *testing.T) {
	c, ok := Lookup("serve")
	if !ok {
		t.Fatal("tego-control has no serve")
	}
	if !strings.Contains(c.Summary, "dashboard") || strings.Contains(c.Summary, "control service") {
		t.Errorf("serve's summary %q: want the dashboard it starts, and no control service", c.Summary)
	}
}

// TestServeListensOnLoopbackOnly: --addr takes a loopback IP, 127.0.0.0/8 (localhost read as 127.0.0.1) or ::1, and
// refuses every other address: the wildcards, a LAN or link-local address, a v4-mapped wildcard, a scoped ::1, a name.
func TestServeListensOnLoopbackOnly(t *testing.T) {
	for in, want := range map[string]string{"127.0.0.1:8484": "127.0.0.1:8484", "localhost:0": "127.0.0.1:0", "127.0.0.2:80": "127.0.0.2:80",
		"[::1]:8484": "[::1]:8484", "[0:0:0:0:0:0:0:1]:0": "[::1]:0", "[::ffff:127.0.0.1]:80": "127.0.0.1:80"} {
		if got, err := loopbackAddr(in); err != nil || got != want {
			t.Errorf("loopbackAddr(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"0.0.0.0:8484", ":8484", "192.168.1.5:8484", "example.com:80", "[::]:8484", "[::ffff:0.0.0.0]:8484",
		"[fe80::1]:8484", "[::1%lo]:8484", "127.0.0.1", "[::1]"} {
		if got, err := loopbackAddr(in); err == nil {
			t.Errorf("loopbackAddr(%q) = %q, want a refusal", in, got)
		}
	}
}

// TestServeListensOnIPv6Loopback: --addr [::1]:0 listens on ::1 and prints a link to it, and the serving user's own
// client gets in over it: the peer check finds the client's socket in /proc/net/tcp6 (a request with no token gets
// 401, not 403), and the sign-in's governed check finds the socket's cgroup over sock_diag in AF_INET6 (303 with the
// session cookie). Before, serve refused [::1] though both checks read IPv6.
func TestServeListensOnIPv6Loopback(t *testing.T) {
	probe, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback here: %v", err)
	}
	_ = probe.Close()
	old := anchorPath
	anchorPath = func(*config.Machine, bool) (string, error) { return filepath.Join(t.TempDir(), "chain.log"), nil }
	t.Cleanup(func() { anchorPath = old })
	t.Setenv("TEGO_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // the severity file serve reads, kept out of the real ~/.config

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var so, se syncBuffer
	done := make(chan int, 1)
	go func() { done <- cmdServe().Run(ctx, []string{"--addr", "[::1]:0", "--ledger", t.TempDir()}, &so, &se) }()
	for end := time.Now().Add(5 * time.Second); !strings.Contains(se.String(), "chains:") && time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
	}
	link := strings.TrimSpace(strings.TrimPrefix(so.String(), "Tego dashboard: "))
	origin, _, ok := strings.Cut(link, "/?t=")
	if !ok || !strings.HasPrefix(origin, "http://[::1]:") {
		cancel()
		t.Fatalf("stdout %q, stderr %q: want the link to [::1]", so.String(), se.String())
	}
	noFollow := &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, c := range []struct {
		url  string
		want int
	}{{origin + "/", http.StatusUnauthorized}, {link, http.StatusSeeOther}} {
		resp, err := noFollow.Get(c.url)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != c.want || c.want == http.StatusSeeOther && len(resp.Cookies()) != 1 {
			t.Errorf("GET %s over [::1]: %d %v %s, want %d", c.url, resp.StatusCode, resp.Cookies(), body, c.want)
		}
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("serve exited %d: %s", code, se.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}
}

// TestServeSaysWhatItServes: after the URL line, which stays the only stdout line, serve names the ledger
// root, where it came from and how many runs it holds, and the chain anchor, so a dashboard showing another ledger
// is seen at start.
func TestServeSaysWhatItServes(t *testing.T) {
	ledger := t.TempDir()
	for _, d := range []string{"r-1-a-b", "r-2-c-d", "r-3-e-f", ".rule-changes"} {
		if err := os.Mkdir(filepath.Join(ledger, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	anchor := filepath.Join(t.TempDir(), "chain.log")
	old := anchorPath
	anchorPath = func(*config.Machine, bool) (string, error) { return anchor, nil }
	t.Cleanup(func() { anchorPath = old })
	t.Setenv("TEGO_CONFIG", "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var so, se syncBuffer
	done := make(chan int, 1)
	go func() { done <- cmdServe().Run(ctx, []string{"--addr", "127.0.0.1:0", "--ledger", ledger}, &so, &se) }()
	for end := time.Now().Add(5 * time.Second); !strings.Contains(se.String(), "chains:") && time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exited %d: %s", code, se.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}
	lines := strings.Split(strings.TrimSpace(so.String()), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "Tego dashboard: http://127.0.0.1:") {
		t.Errorf("stdout %q: want the URL line alone", so.String())
	}
	// The dashboard records the program it runs by the sum of its own bytes: what a later tego compares (D1).
	self, err := handoff.SelfSum()
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := handoff.RecordedProgram([]byte(se.String())); !ok || got != self {
		t.Errorf("stderr records program %q (%v), want this program's sum %s:\n%s", got, ok, self, se.String())
	}
	for _, want := range []string{"  ledger: " + ledger + " (from --ledger), 3 runs\n", "  chains: checked against " + anchor + "\n"} {
		if !strings.Contains(se.String(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, se.String())
		}
	}
}

// TestServeFactsNameASkippedConfig: startup names the actual selected ledger and the unknown
// config cause, including when --ledger supplies the root.
// a missing anchor says the runs show unverified; a config that is read is named as the origin of ledger_root.
func TestServeFactsNameASkippedConfig(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.yaml")
	t.Setenv("TEGO_CONFIG", missing)
	mr := loadMachineReport(config.TrustWarn)
	if mr.err != nil || mr.m == nil || mr.m.BaselineKnown() {
		t.Fatal("bad config lost degraded snapshot", mr.err)
	}
	var b strings.Builder
	writeServeFacts(&b, serveFacts{root: "/srv/ledger", flagLedger: true, machine: mr, anchorErr: errors.New("no home")})
	out := b.String()
	for _, want := range []string{
		"  ledger: /srv/ledger (from --ledger), 0 runs (the folder does not exist yet)\n",
		"  chains: no anchor found (no home); runs show as unverified\n",
		"  config: " + missing,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}

	// With neither, the origin is the built-in default, or the invoking user's own ~/.tego/config.yaml where it sets
	// ledger_root.
	t.Setenv("TEGO_CONFIG", "")
	b.Reset()
	writeServeFacts(&b, serveFacts{root: "/srv/ledger", machine: loadMachineReport(config.TrustWarn), anchor: "/a/chain.log"})
	if out := b.String(); !strings.HasPrefix(out, "  ledger: /srv/ledger (from ") || strings.Contains(out, "(from --ledger)") ||
		strings.Contains(out, "(from TEGO_CONFIG") {
		t.Errorf("no --ledger and no TEGO_CONFIG:\n%s", out)
	}

	// A config that is read names itself as the origin.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "tego.yaml")
	if err := os.WriteFile(cfg, []byte("version: 0\nledger_root: "+filepath.Join(dir, "l")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	mr = loadMachineReport(config.TrustWarn)
	b.Reset()
	writeServeFacts(&b, serveFacts{root: filepath.Join(dir, "l"), machine: mr, anchor: "/a/chain.log"})
	if out := b.String(); !strings.Contains(out, "(from TEGO_CONFIG "+cfg+")") {
		t.Errorf("a read TEGO_CONFIG:\n%s", out)
	}
}

// TestServeStartsDegradedWithASkippedConfig: read pages and stop remain available after any
// layer failure. The startup facts state the actual ledger and UNKNOWN baseline with the cause.
func TestServeStartsDegradedWithASkippedConfig(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(bad, []byte("version: 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bad, 0o666); err != nil {
		t.Fatal(err)
	}
	old := anchorPath
	anchorPath = func(*config.Machine, bool) (string, error) { return filepath.Join(dir, "chain.log"), nil }
	t.Cleanup(func() { anchorPath = old })
	for _, path := range []string{bad, filepath.Join(dir, "missing.yaml")} {
		t.Setenv("TEGO_CONFIG", path)
		ctx, cancel := context.WithCancel(t.Context())
		var so, se syncBuffer
		done := make(chan int, 1)
		go func() { done <- cmdServe().Run(ctx, []string{"--addr", "127.0.0.1:0"}, &so, &se) }()
		for end := time.Now().Add(5 * time.Second); !strings.Contains(se.String(), "chains:") && time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		}
		cancel()
		if code := <-done; code != 0 || !strings.HasPrefix(so.String(), "Tego dashboard: ") || !strings.Contains(se.String(), "baseline UNKNOWN") || !strings.Contains(se.String(), path) {
			t.Fatalf("%s: %d %q %q", path, code, so.String(), se.String())
		}
	}
}

func TestServeDoesNotNameOtherLayerFailureAsEnvSkip(t *testing.T) {
	r := machineReport{m: config.Builtin(), diags: []config.Diagnostic{{Code: config.CodeBaselineUnknown, Message: "baseline UNKNOWN: etc layer could not be read: wrong owner"}}}
	var out strings.Builder
	writeServeFacts(&out, serveFacts{root: "/srv/ledger", machine: r})
	if !strings.Contains(out.String(), "etc layer") || strings.Contains(out.String(), "TEGO_CONFIG") {
		t.Fatal(out.String())
	}
}

// syncBuffer is a bytes.Buffer safe for the serve goroutine to write while the test reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestServeHoldsTheDashboardLockWhileItServes: the dashboard is non-dumpable, so the scan cannot read its program file;
// it holds the dashboard's lock (runlock.HoldDashboard) from the moment it serves, so the scan can name it, and frees it
// when it stops.
func TestServeHoldsTheDashboardLockWhileItServes(t *testing.T) {
	m := config.Builtin()
	m.Home = filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(m.Home, 0o700); err != nil {
		t.Fatal(err)
	}
	m.LedgerRoot.Value = t.TempDir()
	oldLoader, oldAnchor, oldHome := loadMachineSnapshot, anchorPath, dashboardLockHome
	loadMachineSnapshot = func(config.Sources, string, int, config.TrustMode) (*config.Machine, []config.Diagnostic, error) {
		return m, nil, nil
	}
	anchorPath = machineAnchorPath
	dashboardLockHome = machineLockHome // the package's TestMain keeps none; the product's rule is the machine's home
	t.Cleanup(func() { loadMachineSnapshot, anchorPath, dashboardLockHome = oldLoader, oldAnchor, oldHome })
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var so, se syncBuffer
	done := make(chan int, 1)
	go func() { done <- cmdServe().Run(ctx, []string{"--addr", "127.0.0.1:0"}, &so, &se) }()
	for end := time.Now().Add(5 * time.Second); !strings.Contains(se.String(), "chains:") && time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
	}
	if pid, ok := runlock.DashboardPID(m.Home); !ok || pid != os.Getpid() {
		cancel()
		t.Fatalf("while serving, DashboardPID = %d, %v; want this process %d (stderr %q)", pid, ok, os.Getpid(), se.String())
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve: %d %s", code, se.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}
	if pid, ok := runlock.DashboardPID(m.Home); ok {
		t.Fatalf("after serve stopped DashboardPID = %d, true; want none", pid)
	}
}
