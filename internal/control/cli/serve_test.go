// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestServeListensOnLoopbackOnly: --addr takes 127.0.0.1 (or localhost) and refuses every other address.
func TestServeListensOnLoopbackOnly(t *testing.T) {
	for in, want := range map[string]string{"127.0.0.1:8484": "127.0.0.1:8484", "localhost:0": "127.0.0.1:0", "127.0.0.2:80": "127.0.0.2:80"} {
		if got, err := loopbackAddr(in); err != nil || got != want {
			t.Errorf("loopbackAddr(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"0.0.0.0:8484", ":8484", "192.168.1.5:8484", "example.com:80", "[::]:8484", "[::1]:8484", "127.0.0.1"} {
		if got, err := loopbackAddr(in); err == nil {
			t.Errorf("loopbackAddr(%q) = %q, want a refusal", in, got)
		}
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
	anchorPath = func() (string, error) { return anchor, nil }
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
	for _, want := range []string{"  ledger: " + ledger + " (from --ledger), 3 runs\n", "  chains: checked against " + anchor + "\n"} {
		if !strings.Contains(se.String(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, se.String())
		}
	}
}

// TestServeFactsNameASkippedConfig: a TEGO_CONFIG that tego skipped is a warning naming the file, why and the
// ledger served instead; a missing anchor says the runs show unverified; the origin of ledger_root is named.
func TestServeFactsNameASkippedConfig(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.yaml")
	t.Setenv("TEGO_CONFIG", missing)
	mr := loadMachineReport()
	if mr.err != nil {
		t.Fatal(mr.err)
	}
	var b strings.Builder
	writeServeFacts(&b, serveFacts{root: "/srv/ledger", machine: mr, anchorErr: errors.New("no home")})
	out := b.String()
	for _, want := range []string{
		// the origin is the built-in default, or the invoking user's own ~/.tego/config.yaml where it sets ledger_root
		"  ledger: /srv/ledger (from ", "), 0 runs (the folder does not exist yet)\n",
		"  chains: no anchor found (no home); runs show as unverified\n",
		"  config: " + missing,
		"warning: tego-control serve: TEGO_CONFIG " + missing + " was skipped (",
		"); serving /srv/ledger\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}

	// With --ledger the skipped config changes nothing served, so there is no warning (its diagnostic still prints).
	b.Reset()
	writeServeFacts(&b, serveFacts{root: "/srv/ledger", flagLedger: true, machine: mr, anchor: "/a/chain.log"})
	if out := b.String(); strings.Contains(out, "warning:") || !strings.Contains(out, "(from --ledger)") {
		t.Errorf("--ledger with a skipped config:\n%s", out)
	}

	// A config that is read names itself as the origin, and no skip warning is printed.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "tego.yaml")
	if err := os.WriteFile(cfg, []byte("version: 0\nledger_root: "+filepath.Join(dir, "l")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	mr = loadMachineReport()
	b.Reset()
	writeServeFacts(&b, serveFacts{root: filepath.Join(dir, "l"), machine: mr, anchor: "/a/chain.log"})
	if out := b.String(); !strings.Contains(out, "(from TEGO_CONFIG "+cfg+")") || strings.Contains(out, "warning:") {
		t.Errorf("a read TEGO_CONFIG:\n%s", out)
	}
}

// TestServeRefusesASkippedConfig (CO-P5): a TEGO_CONFIG that tego skipped (untrusted, or missing) and no --ledger make
// serve exit 125 with the layer's reason code and the fix, before it listens, rather than serve the default ledger;
// with --ledger the ledger is named outright and serve starts.
func TestServeRefusesASkippedConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	untrusted := filepath.Join(dir, "tego.yaml")
	if err := os.WriteFile(untrusted, []byte("version: 0\nledger_root: "+filepath.Join(dir, "l")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(untrusted, 0o664); err != nil {
		t.Fatal(err)
	}
	for cfg, code := range map[string]string{untrusted: "[config-untrusted]", filepath.Join(dir, "nope.yaml"): "[config-invalid]"} {
		t.Setenv("TEGO_CONFIG", cfg)
		var so, se syncBuffer
		got := cmdServe().Run(t.Context(), []string{"--addr", "127.0.0.1:0"}, &so, &se)
		errs := se.String()
		if got != exits[codeIO] || so.String() != "" || !strings.Contains(errs, code) ||
			!strings.Contains(errs, "TEGO_CONFIG "+cfg+" was skipped (") || !strings.Contains(errs, "--ledger DIR") {
			t.Errorf("%s: exit %d stdout %q stderr %q, want 125 %s naming the file and the fix", cfg, got, so.String(), errs, code)
		}
	}

	// --ledger names the ledger, so the skipped config changes nothing served: serve starts.
	t.Setenv("TEGO_CONFIG", untrusted)
	old := anchorPath
	anchorPath = func() (string, error) { return filepath.Join(dir, "chain.log"), nil }
	t.Cleanup(func() { anchorPath = old })
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var so, se syncBuffer
	done := make(chan int, 1)
	go func() { done <- cmdServe().Run(ctx, []string{"--addr", "127.0.0.1:0", "--ledger", dir}, &so, &se) }()
	for end := time.Now().Add(5 * time.Second); !strings.Contains(se.String(), "chains:") && time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
	}
	cancel()
	if code := <-done; code != 0 || !strings.HasPrefix(so.String(), "Tego dashboard: ") {
		t.Errorf("--ledger with a skipped config: exit %d stdout %q stderr %q", code, so.String(), se.String())
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
