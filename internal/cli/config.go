// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"

	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// loadMachine resolves the machine config once per invocation (R24): the invoking uid after the
// SUDO_UID rule, AT_SECURE detection, the layer files (machineSources), then config.LoadSources with the
// caller's trust mode (TrustAbort for run, and for gc, which deletes by the config's retention and ledger root;
// TrustWarn for compile, doctor and the rest).
func loadMachine(mode config.TrustMode) (*config.Machine, []config.Diagnostic, error) {
	uid, _ := config.InvokingUID()
	secure, err := config.DetectSecureExec()
	if err != nil {
		return nil, nil, fmt.Errorf("detect secure exec: %w", err)
	}
	src, home, diags := machineSources(uid, secure)
	m, more, err := config.LoadSources(src, home, uid, mode)
	if err == nil && m != nil && machineTestHook != nil {
		machineTestHook(m)
	}
	if err == nil && m != nil && machineGuard != nil {
		err = machineGuard(m)
	}
	return m, append(diags, more...), err
}

// machineGuard refuses a loaded machine config in a binary built with -tags tegotesthooks whose ledger root, or
// whose chain anchor or own-log home, would reach the invoking user's own ~/.tego (isolation_testhook.go,
// identity-config.md R27); nil in a product build.
var machineGuard func(*config.Machine) error

// machineTestHook adjusts the loaded machine config in a binary built with -tags tegotesthooks
// (machine_testhook.go); nil in a product build.
var machineTestHook func(*config.Machine)

// machineSources discovers the machine config's layer files and the invoking user's home (config.Resolve:
// the passwd home, never $HOME). It is a variable so this package's tests can put the per-user layer and the
// home that ~/ expands against, the built-in ledger_root's among them, in a temporary directory
// (anchor_test.go's TestMain): setting $HOME in a test isolates nothing. Nothing in a product build reassigns
// it.
var machineSources = config.Resolve

// ledgerRootOf resolves the machine's ledger root for every command (tegoruntime.LedgerRoot); a variable so
// this package's TestMain can refuse a ledger root inside the invoking user's real ~/.tego.
var ledgerRootOf = tegoruntime.LedgerRoot

// writeConfigDiagnostics prints config warnings one per line in the shared format.
func writeConfigDiagnostics(w io.Writer, ds []config.Diagnostic) {
	for _, d := range ds {
		fmt.Fprintln(w, record.Printable(d.String()))
	}
}
