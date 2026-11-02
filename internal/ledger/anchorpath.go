// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// StateDir is the per-user directory under a home that holds chain.log: ~/.tego (P0-DESIGN §3.3).
const StateDir = ".tego"

// AnchorPath is where an account's runs append their heads (P0-DESIGN §3.3, spec/record/v1, record-ledger.md §3):
// ~/.tego/chain.log under home, the account's passwd home, whatever ledger_root says, and for an account with no home
// (no passwd entry, or a passwd home that does not exist, like the /nonexistent of a service account) the chain.log
// beside its ledger root, which root resolves and is called for only then. It is the one rule: tego's launcher and its
// `events --verify` take it through internal/runtime's AnchorPath, and the dashboard (tego-control serve, which may
// not link the engine) calls it itself, so the dashboard checks a run against the file the run was anchored in.
//
// The home anchor is not derived from ledger_root. On the documented server setting (ledger_root: /var/lib/tego/runs)
// that derivation put every user's anchor in one shared /var/lib/tego/chain.log, which each of them would have to be
// able to write (and therefore rewrite, for anyone) or else every run would end in ErrAnchorWrite. One user's anchors
// in that user's own 0700 directory are the root of trust a run directory is checked against, and nobody else's run
// can move them. An account with no home has no such directory, and the ledger root's parent is the one place its
// runs already write. Home creation is never attempted: a root launcher creating /nonexistent for a service account
// would be a change to the machine nobody asked for.
func AnchorPath(home string, root func() (string, error)) (string, error) {
	return AnchorPathWith(home, HomeExists, root)
}

// AnchorPathWith is AnchorPath with the probe that says whether home exists named: the orphan sweep asks it about
// another account's home, and tests about homes that are not on this machine.
func AnchorPathWith(home string, exists func(string) bool, root func() (string, error)) (string, error) {
	if home != "" && filepath.IsAbs(home) && exists(home) {
		return filepath.Join(home, StateDir, ChainLogFile), nil
	}
	r, err := root()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(filepath.Clean(r)), ChainLogFile), nil
}

// HomeExists reports whether home is an existing directory, as AnchorPath asks it. Only a definite "no" counts: a
// home that cannot be stat'ed for another reason is kept, and opening its anchor then fails where it can be reported
// (ProbeAnchor), rather than moving the anchor because of a transient error.
func HomeExists(home string) bool {
	st, err := os.Stat(home)
	if err != nil {
		return !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR)
	}
	return st.IsDir()
}
