// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/askclient"
	"github.com/attention-span-ai/tego/pkg/spec/askproto"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func TestLocalRolesCLIPolicyChangedRefusal(t *testing.T) {
	const runID = "r-3f9c2a1b-0dllq06ts7400-k7m2pq"
	const id = "q-0123456789abcdef0123456789abcdef"
	root := gcRoot(t)
	dir := newCLIRunIn(t, root, runID)
	calls := policyChangedCLIServer(t, dir, id)
	for _, name := range []string{"deny", "approve"} {
		code, out, errs := run(t, name, runID, id)
		assertCLIPolicyChanged(t, name, code, out, errs)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("broker calls = %d, want both full CLI commands", got)
	}
}

func TestLocalRolesCLIConfigRefusalPrecedesBroker(t *testing.T) {
	const runID = "r-3f9c2a1b-0dllq06ts7400-k7m2pq"
	const id = "q-0123456789abcdef0123456789abcdef"
	root := gcRoot(t)
	dir := newCLIRunIn(t, root, runID)
	calls := policyChangedCLIServer(t, dir, id)
	system := filepath.Join(t.TempDir(), "system.yaml")
	if err := os.WriteFile(system, []byte("local_roles: owner_only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The real system-layer walk refuses this unprivileged fixture's placement.
	// This proves Main's load-before-contact order; the config package proves the
	// precise 0600 readability check with modeled root placement. Actual root CLI
	// execution against /etc/tego/config.yaml is owed in a guest.
	previous := machineSources
	machineSources = func(int, bool) (config.Sources, string, []config.Diagnostic) {
		return config.Sources{Etc: system, EnvFile: os.Getenv(config.EnvConfigVar)}, root, nil
	}
	t.Cleanup(func() { machineSources = previous })

	code, out, errs := run(t, "approve", runID, id)
	if code != identity.ExitLauncher || out != "" {
		t.Fatalf("approve code=%d out=%q errors=%q", code, out, errs)
	}
	for _, want := range []string{"machine config untrusted:", "[config-untrusted]", "system layer"} {
		if !strings.Contains(errs, want) {
			t.Errorf("approve error %q lacks strict config refusal %q", errs, want)
		}
	}
	if strings.Contains(errs, "the approval policy file changed since this run started") || strings.Contains(errs, "tego stop <run>") {
		t.Errorf("config-load refusal was described as broker policy drift: %q", errs)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("approve contacted the broker %d times before refusing invalid system config", got)
	}

	code, out, errs = run(t, "deny", runID, id)
	assertCLIPolicyChanged(t, "deny", code, out, errs)
	if !strings.Contains(errs, "baseline UNKNOWN") {
		t.Errorf("deny omitted the degraded system-config warning: %q", errs)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("broker calls = %d, want only the warning-load deny", got)
	}
}

func assertCLIPolicyChanged(t *testing.T, name string, code int, out, errs string) {
	t.Helper()
	if code != identity.ExitLauncher || out != "" {
		t.Fatalf("%s code=%d out=%q errors=%q", name, code, out, errs)
	}
	for _, want := range []string{"the approval policy file changed since this run started", "tego stop <run>", "relaunch with the same ledger configuration"} {
		if !strings.Contains(errs, want) {
			t.Errorf("%s error %q lacks recovery %q", name, errs, want)
		}
	}
}

// policyChangedCLIServer keeps the launcher's actual flock and transport checks.
// It supplies only the broker response; runtime tests prove the pinned policy
// mismatch itself. Counting accepted connections distinguishes local load failure
// from a broker refusal with the same exit code.
func policyChangedCLIServer(t *testing.T, dir, id string) *atomic.Int32 {
	t.Helper()
	socketDir, socketPath, err := askclient.OpenSocketDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socketDir.Close() })
	ln, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: socketPath, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	done := make(chan error, 1)
	t.Cleanup(func() {
		_ = ln.Close()
		if err := <-done; err != nil {
			t.Errorf("policy-change broker fixture: %v", err)
		}
	})
	go func() {
		for {
			c, err := ln.AcceptUnix()
			if errors.Is(err, net.ErrClosed) {
				done <- nil
				return
			}
			if err != nil {
				done <- err
				return
			}
			calls.Add(1)
			err = func() error {
				defer func() { _ = c.Close() }()
				if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					return err
				}
				if _, err := c.Write([]byte(`{"ready":"0123456789abcdef0123456789abcdef"}`)); err != nil {
					return err
				}
				packet := make([]byte, askproto.MaxPacket)
				n, err := c.Read(packet)
				if err != nil {
					return err
				}
				cmd, err := askproto.DecodeCommand(packet[:n])
				if err != nil || cmd.Action != askproto.ActionAnswer || cmd.AskID != id {
					return fmt.Errorf("CLI sent an invalid answer: %+v, %w", cmd, err)
				}
				raw, err := json.Marshal(askproto.Response{Error: "policy changed", Code: "approval-policy-changed"})
				if err != nil {
					return err
				}
				_, err = c.Write(raw)
				return err
			}()
			if err != nil {
				done <- err
				return
			}
		}
	}()
	return &calls
}
