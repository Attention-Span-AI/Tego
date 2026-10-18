// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/internal/realtego"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// ErrTestLedgerRoot is what a binary built with tegotesthooks answers when its machine config puts the ledger
// root (the built-in ~/.tego/runs included), or the chain anchor or own-log home its variables name, inside the
// invoking user's own ~/.tego.
var ErrTestLedgerRoot = errors.New("this binary is built with tegotesthooks and must not reach the invoking user's own ~/.tego")

func init() {
	if secure, err := config.DetectSecureExec(); err != nil || secure {
		return
	}
	machineGuard = func(m *config.Machine) error {
		return testIsolationError(m, realtego.Dirs(), os.Getenv(EnvTestChainAnchor), os.Getenv(EnvTestOwnLogHome))
	}
}

// testIsolationError is machineGuard over explicit ~/.tego directories: dirs are the directories the test build
// must stay out of (realtego.Dirs), anchor and ownLogHome the values of its two variables. The ledger root is
// what every command that reads or sweeps the ledger resolves (`run`'s and `gc`'s sweeps end and anchor every
// orphan in it, `gc` also expires its runs), so a config without a ledger_root of its own, whose root is the
// built-in ~/.tego/runs, is refused as the harness that forgot to write one.
func testIsolationError(m *config.Machine, dirs []string, anchor, ownLogHome string) error {
	// hit names the directory of dirs that p is, or lies in; "" when none.
	hit := func(p string) string {
		for _, d := range dirs {
			if realtego.Under(p, []string{d}) {
				return d
			}
		}
		return ""
	}
	// The root is resolved as the commands resolve it (internal/runtime LedgerRoot): a "~/" root against the passwd
	// home, or, when the passwd database names none (Machine.Home ""), against $HOME, which is the $HOME/.tego
	// realtego.Dirs then names. A "~/" root that resolves to nothing cannot be checked and is
	// refused; any other root that does not resolve is refused by the commands themselves before they write.
	root := m.LedgerRoot.Value
	if strings.HasPrefix(root, "~/") {
		r, err := tegoruntime.LedgerRoot(m)
		if err != nil {
			return fmt.Errorf("%w: ledger_root %s names no directory this build can check (%v): a test harness writes a "+
				"machine config naming a ledger_root of its own (ledger_root: <dir>/ledger in the file TEGO_CONFIG names)",
				ErrTestLedgerRoot, root, err)
		}
		root = r
	}
	if d := hit(root); filepath.IsAbs(root) && d != "" {
		return fmt.Errorf("%w: ledger_root %s is inside %s: a test harness writes a machine config naming a ledger_root of "+
			"its own (ledger_root: <dir>/ledger in the file TEGO_CONFIG names)", ErrTestLedgerRoot, root, d)
	}
	if d := hit(anchor); anchor != "" && d != "" {
		return fmt.Errorf("%w: %s=%s is inside %s", ErrTestLedgerRoot, EnvTestChainAnchor, anchor, d)
	}
	// The own log is <home>/.tego/tego.log.
	if d := hit(filepath.Join(ownLogHome, ".tego")); ownLogHome != "" && d != "" {
		return fmt.Errorf("%w: %s=%s keeps tego.log inside %s", ErrTestLedgerRoot, EnvTestOwnLogHome, ownLogHome, d)
	}
	return nil
}
