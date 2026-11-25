// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"

	"github.com/attention-span-ai/tego/internal/platform/lsmlist"
	"github.com/attention-span-ai/tego/internal/platform/tomoyo"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// loadMachine resolves one fresh machine snapshot (R24): the invoking uid after the
// SUDO_UID rule, AT_SECURE detection, the layer files (machineSources), then config.LoadSources with the
// caller's trust mode: decisions about rules use TrustAbort; observation and stop use TrustWarn
// and retain an explicitly UNKNOWN baseline on a failed layer (ADR 0144).
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
	if err == nil && m != nil {
		// tomoyo.facts_dir (the administrator's /etc layer only) names where a held open reads TOMOYO's facts. It is set
		// once here for every command; an unusable value refuses every fact (the setter says why) and is never read
		// from the kernel's path instead.
		_ = tomoyo.SetFactsDir(m.TOMOYO.FactsDir.Value) // the refusal is the error SetFactsDir keeps for each fact
		// lsm.list_file (the same layer) names the file a held open reads the security-module list from when the kernel's
		// own two ways fail (ADR 0041, 2026-11-25); an unusable value refuses and is never read as "no file".
		_ = lsmlist.SetFile(m.LSM.ListFile.Value) // the refusal is the error SetFile keeps for each read
	}
	return m, append(diags, more...), err
}

// machineGuard refuses a loaded machine config in a binary built with -tags tegotesthooks whose ledger root, or
// whose chain anchor or own-log home, would reach the invoking user's own ~/.tego (isolation_testhook.go); nil in
// a product build.
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
