// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// TestRestrictSelfFallbackAndNoNewPrivs covers the degrade paths and the audit flag: applyLandlock's degrade paths need
// kernels of several Landlock ABIs, so restrictSelfWith takes the syscall and the ABI probe as
// parameters and is tested against faked answers. Flags the ABI does not know are dropped before the call;
// after it, EINVAL is retried only without LandlockNoNewPrivs (R18), whose bit step 4's prctl already set.
// It used to retry any EINVAL with flags 0, which on ABI 7 to 10 would have dropped an audit flag the kernel
// knows, silently, together with the NO_NEW_PRIVS it meant to drop.
func TestRestrictSelfFallbackAndNoNewPrivs(t *testing.T) {
	logOn, nnp := LandlockLogNewExecOn, LandlockNoNewPrivs
	cases := []struct {
		name      string
		abi       int // 0: the probe fails
		flags     uint32
		errs      []error // the fake's return value per call, in call order; the last value repeats
		wantCalls []uint32
		wantErr   error
		// nnpUnset and nnpErr fake PR_GET_NO_NEW_PRIVS after a call accepted with NO_NEW_PRIVS (I8).
		nnpUnset bool
		nnpErr   error
	}{
		{name: "ABI 11: both flags accepted, no retry", abi: 11, flags: nnp | logOn,
			errs: []error{nil}, wantCalls: []uint32{nnp | logOn}},
		{name: "ABI 11 claimed, NO_NEW_PRIVS refused: retried without it, the audit flag kept", abi: 11, flags: nnp | logOn,
			errs: []error{unix.EINVAL, nil}, wantCalls: []uint32{nnp | logOn, logOn}},
		{name: "ABI 10: NO_NEW_PRIVS dropped before the call, the audit flag passed", abi: 10, flags: nnp | logOn,
			errs: []error{nil}, wantCalls: []uint32{logOn}},
		{name: "ABI 7: an audit flag the kernel refuses fails the stage, never retried with 0", abi: 7, flags: logOn,
			errs: []error{unix.EINVAL, nil}, wantCalls: []uint32{logOn}, wantErr: unix.EINVAL},
		{name: "ABI 6: the audit flag is dropped before the call and the ruleset still applies", abi: 6, flags: logOn,
			errs: []error{nil}, wantCalls: []uint32{0}},
		{name: "ABI 10, only NO_NEW_PRIVS asked: nothing is left to pass", abi: 10, flags: nnp,
			errs: []error{nil}, wantCalls: []uint32{0}},
		{name: "TSYNC is never passed: NEW_LISTENER excludes it", abi: 11, flags: unix.LANDLOCK_RESTRICT_SELF_TSYNC,
			errs: []error{nil}, wantCalls: []uint32{0}},
		{name: "the degraded retry can still fail", abi: 11, flags: nnp,
			errs: []error{unix.EINVAL, unix.EPERM}, wantCalls: []uint32{nnp, 0}, wantErr: unix.EPERM},
		{name: "a non-EINVAL failure is never retried", abi: 11, flags: nnp,
			errs: []error{unix.EPERM}, wantCalls: []uint32{nnp}, wantErr: unix.EPERM},
		{name: "flags already 0: EINVAL has nothing left to degrade to", abi: 11, flags: 0,
			errs: []error{unix.EINVAL}, wantCalls: []uint32{0}, wantErr: unix.EINVAL},
		{name: "an unreadable ABI leaves the flags as asked", abi: 0, flags: nnp | logOn,
			errs: []error{nil}, wantCalls: []uint32{nnp | logOn}},
		// enforce-landlock I8, ported from the deleted landlock.RestrictSelf: a flagged success is cross-checked.
		{name: "I8: accepted with NO_NEW_PRIVS and the bit unset fails", abi: 11, flags: nnp,
			errs: []error{nil}, wantCalls: []uint32{nnp}, nnpUnset: true, wantErr: errAny},
		{name: "I8: accepted with NO_NEW_PRIVS and the bit unreadable fails", abi: 11, flags: nnp,
			errs: []error{nil}, wantCalls: []uint32{nnp}, nnpErr: unix.EPERM, wantErr: unix.EPERM},
		{name: "I8: no NO_NEW_PRIVS flag, no cross-check", abi: 7, flags: logOn,
			errs: []error{nil}, wantCalls: []uint32{logOn}, nnpUnset: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls []uint32
			i := 0
			restrict := func(rulesetFD int, flags uint32) error {
				if rulesetFD != 42 {
					t.Errorf("rulesetFD = %d, want 42", rulesetFD)
				}
				calls = append(calls, flags)
				err := tc.errs[i]
				if i < len(tc.errs)-1 {
					i++
				}
				return err
			}
			abi := func() (int, error) {
				if tc.abi == 0 {
					return 0, unix.ENOSYS
				}
				return tc.abi, nil
			}
			nnpRead := func() (bool, error) { return !tc.nnpUnset && tc.nnpErr == nil, tc.nnpErr }
			err := restrictSelfWith(restrict, abi, nnpRead, 42, tc.flags)
			if tc.wantErr == errAny {
				if err == nil {
					t.Error("err = nil, want a failure")
				}
			} else if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
			if len(calls) != len(tc.wantCalls) {
				t.Fatalf("calls = %v, want %v", calls, tc.wantCalls)
			}
			for i, want := range tc.wantCalls {
				if calls[i] != want {
					t.Errorf("call %d flags = %#x, want %#x", i, calls[i], want)
				}
			}
		})
	}
}

// errAny is a wantErr that accepts any non-nil error.
var errAny = errors.New("any error")

// TestLandlockFlagsNamesWhatAnABIRefuses pins the split a launcher records: what the kernel's ABI takes and
// what the run asked for and will not get (an audit flag below ABI 7 is a record the kernel will not write).
func TestLandlockFlagsNamesWhatAnABIRefuses(t *testing.T) {
	all := LandlockLogSameExecOff | LandlockLogNewExecOn | LandlockLogSubdomainsOff | LandlockNoNewPrivs
	for _, tc := range []struct {
		abi              int
		applied, dropped uint32
	}{
		{6, 0, all},
		{7, all &^ LandlockNoNewPrivs, LandlockNoNewPrivs},
		{10, all &^ LandlockNoNewPrivs, LandlockNoNewPrivs},
		{11, all, 0},
	} {
		applied, dropped := LandlockRestrictFlags(all|unix.LANDLOCK_RESTRICT_SELF_TSYNC, tc.abi)
		if applied != tc.applied || dropped != tc.dropped|unix.LANDLOCK_RESTRICT_SELF_TSYNC {
			t.Errorf("ABI %d: applied %#x dropped %#x, want %#x and %#x", tc.abi, applied, dropped, tc.applied,
				tc.dropped|unix.LANDLOCK_RESTRICT_SELF_TSYNC)
		}
	}
}
