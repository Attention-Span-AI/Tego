// SPDX-License-Identifier: Apache-2.0

package askclient

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/attention-span-ai/tego/internal/runlock"
	"github.com/attention-span-ai/tego/pkg/spec/askproto"
)

// OwnerOnlyError adds the root-terminal remedy when an enabled client cannot
// traverse a live root run's existing private directory. It changes no transport
// permission and never authorizes an answer. Without the setting it returns the
// original error unchanged, including its identity and wire text.
//
// A refusal to prove the launcher (runlock.ErrNotLockHolder, runlock.ErrUnverified) is left as it is even when it wraps a
// permission error: its caller got through the run's directory, so it is not the wrong role, and its own words say why
// the launcher is hidden from it (root without CAP_SYS_PTRACE is told to run where it can read the descriptors, not to be root).
func OwnerOnlyError(err error, ownerOnly bool) error {
	if errors.Is(err, runlock.ErrNotLockHolder) || errors.Is(err, runlock.ErrUnverified) {
		return err
	}
	if ownerOnly && errors.Is(err, fs.ErrPermission) && !errors.Is(err, askproto.ErrApprovalPolicyChanged) {
		return fmt.Errorf("%w: %v", askproto.ErrOwnerOnly, err)
	}
	return err
}
