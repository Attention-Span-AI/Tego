// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// notSecure / isSecure / failedAuxv stand in for config.DetectSecureExec, whose answer is fixed at
// exec for this process and so can never be driven from a test any other way.
func notSecure() (bool, error)  { return false, nil }
func isSecure() (bool, error)   { return true, nil }
func failedAuxv() (bool, error) { return false, errors.New("open /proc/self/auxv: no such file") }

// TestLedgerRootIgnoresHomeUnderATSecure is spec/config/v0's Trust rule applied where it was missing:
// "when the process runs with AT_SECURE set (the file-capability copy), $TEGO_CONFIG and $HOME are
// ignored" (identity-config.md R21). Machine.Home is empty exactly in E9 — a containerized or
// directory-backed uid with no passwd entry — and the built-in ledger_root is still "~/.tego/runs",
// so before this the capability-bearing launcher would let $HOME choose where the hash-chained audit
// ledger is written and where `gc` later deletes.
//
// Also pins runtime-launch.md E37: a ~/ ledger_root under AT_SECURE is an error, not $HOME.
func TestLedgerRootIgnoresHomeUnderATSecure(t *testing.T) {
	m := config.Builtin()
	m.Home = "" // E9: getpwuid found nothing

	attacker := func() (string, error) { return "/tmp/attacker", nil }
	_, err := ledgerRoot(m, isSecure, attacker)
	if !errors.Is(err, ErrLedgerRootHome) {
		t.Fatalf("err = %v, want ErrLedgerRootHome", err)
	}
	if strings.Contains(err.Error(), "/tmp/attacker") {
		t.Fatalf("the refusal quotes the $HOME it refused to use: %v", err)
	}

	// An unreadable auxv is the one input that could hide AT_SECURE, so it fails closed too
	// (config.DetectSecureExec: "a process that cannot read its own auxv must not resolve $HOME").
	if _, err := ledgerRoot(m, failedAuxv, attacker); !errors.Is(err, ErrLedgerRootHome) {
		t.Fatalf("err = %v, want ErrLedgerRootHome when AT_SECURE cannot be read", err)
	}
}

// TestLedgerRootKeepsHomeWhenNotSecure pins the other side: an ordinary unprivileged run in a
// container with no passwd entry is an honest case, and $HOME stays its answer.
func TestLedgerRootKeepsHomeWhenNotSecure(t *testing.T) {
	m := config.Builtin()
	m.Home = ""
	got, err := ledgerRoot(m, notSecure, func() (string, error) { return "/home/container", nil })
	if err != nil {
		t.Fatalf("ledgerRoot: %v", err)
	}
	if want := filepath.Join("/home/container", ".tego", "runs"); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestLedgerRootPrefersThePasswdHome: when config.Resolve did name a home, neither $HOME nor
// AT_SECURE is consulted at all — the passwd answer is the only one R21 allows.
func TestLedgerRootPrefersThePasswdHome(t *testing.T) {
	m := config.Builtin()
	m.Home = "/home/u"
	noEnv := func() (string, error) { return "", errors.New("$HOME must not be read") }
	for _, secure := range []func() (bool, error){notSecure, isSecure, failedAuxv} {
		got, err := ledgerRoot(m, secure, noEnv)
		if err != nil {
			t.Fatalf("ledgerRoot: %v", err)
		}
		if want := filepath.Join("/home/u", ".tego", "runs"); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

// TestLedgerRootAbsoluteNeedsNoHome: an absolute ledger_root never reaches the home logic, so a
// machine with no passwd entry can still run by setting one.
func TestLedgerRootAbsoluteNeedsNoHome(t *testing.T) {
	m := config.Builtin()
	m.Home = ""
	m.LedgerRoot = config.Setting[string]{Value: "/var/lib/tego/runs"}
	noEnv := func() (string, error) { return "", errors.New("$HOME must not be read") }
	got, err := ledgerRoot(m, isSecure, noEnv)
	if err != nil {
		t.Fatalf("ledgerRoot: %v", err)
	}
	if got != "/var/lib/tego/runs" {
		t.Fatalf("got %q", got)
	}
}
