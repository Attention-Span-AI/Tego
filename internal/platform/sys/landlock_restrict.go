// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// The landlock_restrict_self flags a ChildSpec may carry, as the uapi defines them. The three LOG flags are
// ABI 7 (Linux 6.15): LandlockLogNewExecOn is the one that makes the kernel audit a refusal the agent meets
// after the child stage's execve, which by default it does not (the default logs the process that called
// landlock_restrict_self, until it execs). LandlockNoNewPrivs is ABI 11 and folds step 4's prctl into the
// call; without it the prctl has already set the same bit, so dropping it changes nothing.
const (
	LandlockLogSameExecOff   = uint32(unix.LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF)
	LandlockLogNewExecOn     = uint32(unix.LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON)
	LandlockLogSubdomainsOff = uint32(unix.LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF)
	LandlockNoNewPrivs       = uint32(1 << 4)
)

// LandlockRestrictFlags splits requested into the flags a kernel of Landlock ABI abi accepts and the ones it would
// refuse, so a launcher can record exactly which it asked for and could not have (an audit flag on a kernel
// below ABI 7 is a record the run will not get). LANDLOCK_RESTRICT_SELF_TSYNC and any bit this package does
// not name are always refused: TSYNC would put the domain on the launcher's own threads, which seccomp's
// NEW_LISTENER excludes (enforce-landlock R13).
func LandlockRestrictFlags(requested uint32, abi int) (applied, dropped uint32) {
	var known uint32
	if abi >= 7 {
		known |= LandlockLogSameExecOff | LandlockLogNewExecOn | LandlockLogSubdomainsOff
	}
	if abi >= 11 {
		known |= LandlockNoNewPrivs
	}
	return requested & known, requested &^ known
}

// RestrictSelf applies the caller's Landlock policy with ABI flag fallback and
// verifies NO_NEW_PRIVS when the kernel accepted that flag. It never sets the
// caller's no_new_privs policy on its own.
func RestrictSelf(rulesetFD int, flags uint32) error {
	return restrictSelfWith(LandlockRestrictSelf, LandlockABI, NoNewPrivs, rulesetFD, flags)
}

// restrictSelfWith applies a Landlock ruleset with flags, degrading only what can be degraded without
// changing what the run gets. The flags this kernel's ABI does not know are dropped before the call, the
// same split LandlockRestrictFlags gives the launcher, so an audit flag on an older kernel costs the audit and never
// the confinement. After the call, EINVAL is retried once, without LandlockNoNewPrivs, and only when that
// flag was passed: the R18 ABI<11 fallback, safe because step 4's prctl set the bit. Any other flag the kernel
// refuses fails the stage rather than vanish: the run asked for it, and a silent retry with 0 is how an audit
// flag used to be dropped on ABI 7 to 10 with nothing to say so. An ABI that cannot be read leaves the flags
// as asked, and the kernel's answer decides. A call the kernel accepted with LandlockNoNewPrivs is cross-checked
// with PR_GET_NO_NEW_PRIVS (nnp), and a bit left unset, or unreadable, fails the stage (enforce-landlock I8): the
// flag is then the only thing that set it, and the answer is never assumed. restrict, abi and nnp are the
// syscall seams (sys.LandlockRestrictSelf, sys.LandlockABI and sys.NoNewPrivs in production), so the degrade paths are tested with faked responses in landlock_restrict_test.go
// without a matching kernel. It is the one landlock_restrict_self wrapper in the tree (enforce-landlock
// R18); the enforce/landlock package prepares the ruleset and never applies it.
func restrictSelfWith(restrict func(rulesetFD int, flags uint32) error, abi func() (int, error),
	nnp func() (bool, error), rulesetFD int, flags uint32) error {
	if flags != 0 {
		if v, err := abi(); err == nil {
			flags, _ = LandlockRestrictFlags(flags, v)
		}
	}
	err := restrict(rulesetFD, flags)
	if err != nil && flags&LandlockNoNewPrivs != 0 && errors.Is(err, unix.EINVAL) {
		return restrict(rulesetFD, flags&^LandlockNoNewPrivs)
	}
	if err == nil && flags&LandlockNoNewPrivs != 0 {
		set, perr := nnp()
		switch {
		case perr != nil:
			return fmt.Errorf("after landlock_restrict_self(NO_NEW_PRIVS): %w", perr)
		case !set:
			return errors.New("landlock_restrict_self(NO_NEW_PRIVS) succeeded and no_new_privs is unset")
		}
	}
	return err
}
