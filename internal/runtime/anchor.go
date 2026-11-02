// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// ErrAnchorHome is a chain anchor with nowhere to live: the invoking user has no home to hold
// ~/.tego/chain.log, and the ledger root it would otherwise sit beside cannot be resolved either — a
// "~/" ledger_root with no passwd home under AT_SECURE, the same condition that refuses the ledger root
// itself (runtime-launch.md case 37). Only home resolution is decided here; whether the file can be
// opened is ledger.ProbeAnchor's question.
var ErrAnchorHome = errors.New("runtime: the chain anchor needs a home the passwd database does not name")

// StateDir is the per-user directory under the invoking user's home that holds chain.log: ~/.tego
// (P0-DESIGN §3.3), ledger.StateDir.
const StateDir = ledger.StateDir

// AnchorPath is where this machine's runs append their heads (P0-DESIGN §3.3, spec/record/v1,
// docs/p0/record-ledger.md §3): ledger.AnchorPath, the one rule tego and the dashboard share, over the
// invoking user's passwd home and the machine's ledger root. That is ~/.tego/chain.log of the invoking
// user, whatever ledger_root says, and for an account with no home — no passwd entry, or a passwd home
// that does not exist, like the /nonexistent of a service account — the chain.log beside the ledger root.
//
// Whenever a file is named at all, it depends only on the passwd entry, whether that home exists, and
// the ledger root, so the file-capability launcher, the plain binary and `events --verify` name the
// same file for one account. The one case AT_SECURE decides is whether there is a file: with no passwd
// home and a "~/" ledger_root, the ledger root itself comes from $HOME for the plain binary, which then
// anchors beside it, while the AT_SECURE copy, which never reads $HOME, gets ErrAnchorHome
// (runtime-launch.md case 37). The home is the passwd entry of the invoking uid, never $HOME
// (identity-config.md R21); the ledger root is resolved exactly as LedgerRoot resolves it.
func AnchorPath(m *config.Machine) (string, error) {
	return anchorPath(m, config.DetectSecureExec, os.UserHomeDir, ledger.HomeExists)
}

// anchorPath is AnchorPath over explicit AT_SECURE, $HOME and directory probes, for tests.
func anchorPath(m *config.Machine, secureExec func() (bool, error), envHome func() (string, error),
	dirExists func(string) bool) (string, error) {
	if m == nil {
		return "", fmt.Errorf("%w: no machine config", ErrDeps)
	}
	return ledger.AnchorPathWith(m.Home, dirExists, func() (string, error) {
		root, err := ledgerRoot(m, secureExec, envHome)
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrAnchorHome, err)
		}
		return root, nil
	})
}

// WithSweepAnchor makes the runs a sweep ends append their heads to the chain anchor their launcher
// would have used: own (the sweeper's AnchorPath) for the sweeper's own runs, and for a run directory
// another account owns — a shared ledger root swept by root — that account's anchor under AnchorPath's
// rule (sweepAnchor). Without it the ledger's default beside the ledger root is used.
func WithSweepAnchor(own string) SweepOption {
	return func(o *sweepOptions) { o.anchor = own }
}

// sweepAnchor is the chain anchor a sweep appends each orphan's head to. The run's owner is read from
// the filesystem, not from the ledger: its run directory's uid, or, when root owns the directory (a
// root launcher that died before handing it over), its ledger root's uid. A run whose owner is the
// sweeper, root, or cannot be read is anchored in own. Anyone else's goes to their ~/.tego/chain.log,
// or, with no home, beside this ledger root — where that account's own launcher, and its own `events
// --verify`, look for it.
type sweepAnchor struct {
	root   string               // the declared ledger root, used for the no-home anchor fallback
	bound  sys.Lender           // the held root ownership is read under, when the pass has bound it
	own    string               // the sweeper's AnchorPath
	self   int                  // the sweeper's invoking uid
	homeOf func(uid int) string // the passwd home of uid, "" when there is none
	// uidOf is ownerUIDAt: the owner of name under the directory at lends, or of the path name with at nil.
	uidOf func(at sys.Lender, name string) (int, bool)
	isDir func(path string) bool
}

// newSweepAnchor is the anchor Sweep hands the writer that ends an orphan under root.
func newSweepAnchor(root, own string) *sweepAnchor {
	uid, _ := config.InvokingUID()
	return &sweepAnchor{root: root, own: own, self: uid, homeOf: passwdHome, uidOf: ownerUIDAt, isDir: ledger.HomeExists}
}

// boundTo returns this anchor with ownership reads made under root, the held root a pass lends
// (ledger.WithBoundWriterOptions). Its declared root still chooses the no-home fallback.
func (a *sweepAnchor) boundTo(root sys.Lender) *sweepAnchor {
	bound := *a
	bound.bound = root
	return &bound
}

// Append records the run's head in its owner's anchor.
func (a *sweepAnchor) Append(run, head string) error {
	return ledger.NewFileChainAnchor(a.pathFor(run)).Append(run, head)
}

// Head reads the run's head from its owner's anchor.
func (a *sweepAnchor) Head(run string) (string, bool, error) {
	return ledger.NewFileChainAnchor(a.pathFor(run)).Head(run)
}

// pathFor is the anchor file of run.
func (a *sweepAnchor) pathFor(run string) string {
	at, dir, root := a.bound, run, "."
	if at == nil {
		dir, root = filepath.Join(a.root, run), a.root
	}
	uid, ok := a.uidOf(at, dir)
	if ok && uid == 0 {
		uid, ok = a.uidOf(at, root)
	}
	if !ok || uid == 0 || uid == a.self {
		return a.own
	}
	// That account's anchor under ledger.AnchorPath's rule, its home judged by a.isDir; the ledger root is the
	// declared one, which needs no resolving, so the rule cannot fail here.
	p, _ := ledger.AnchorPathWith(a.homeOf(uid), a.isDir, func() (string, error) { return a.root, nil })
	return p
}

// ownerUID is the uid that owns path, not following a final symlink.
func ownerUID(path string) (int, bool) {
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return 0, false
	}
	return int(st.Uid), true
}

// ownerUIDAt is ownerUID for name in the directory at lends ("." is that directory itself), or for the path
// name when at is nil.
func ownerUIDAt(at sys.Lender, name string) (int, bool) {
	if at == nil {
		return ownerUID(name)
	}
	var st unix.Stat_t
	if err := at.Borrow(func(n int) error { return unix.Fstatat(n, name, &st, unix.AT_SYMLINK_NOFOLLOW) }); err != nil {
		return 0, false
	}
	return int(st.Uid), true
}

// passwdHome is uid's home from the passwd database, as config.Resolve reads the invoking user's (never $HOME).
func passwdHome(uid int) string {
	u, err := config.LookupPasswd(uid)
	if err != nil {
		return ""
	}
	return u.HomeDir
}

// anchorFile is the chain anchor this run appends to: Deps.AnchorPath, else the ledger's default.
func (r *runner) anchorFile() string {
	if r.deps.AnchorPath != "" {
		return r.deps.AnchorPath
	}
	return ledger.DefaultAnchorPath(r.dir)
}
