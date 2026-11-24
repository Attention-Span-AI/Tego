// SPDX-License-Identifier: Apache-2.0

package askclient

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runlock"
	"github.com/attention-span-ai/tego/pkg/spec/askproto"
)

func TestLocalRolesPermissionGuidancePreservesLegacy(t *testing.T) {
	for _, err := range []error{fs.ErrPermission, fs.ErrNotExist, askproto.ErrUnauthorized, nil} {
		if got := OwnerOnlyError(err, false); got != err {
			t.Fatalf("personal error identity changed: %v -> %v", err, got)
		}
	}
	got := OwnerOnlyError(fs.ErrPermission, true)
	if !errors.Is(got, askproto.ErrOwnerOnly) || !strings.Contains(got.Error(), "root from a terminal outside any governed run") {
		t.Fatal(got)
	}
	if got := OwnerOnlyError(fs.ErrNotExist, true); got != fs.ErrNotExist {
		t.Fatal("no filesystem authority refusal was established")
	}
}

func TestLocalRolesPolicyChangedGuidancePreservesRefusal(t *testing.T) {
	_, err := askproto.DecodeResponse([]byte(`{"error":"policy changed","code":"approval-policy-changed"}`))
	for _, cause := range []error{err, errors.Join(err, fs.ErrPermission)} {
		if got := OwnerOnlyError(cause, true); !errors.Is(got, askproto.ErrApprovalPolicyChanged) || errors.Is(got, askproto.ErrOwnerOnly) || !strings.Contains(got.Error(), "tego stop <run>") {
			t.Fatalf("client replaced policy recovery with identity recovery: %v", got)
		}
	}
}

// A refusal to prove the launcher (the lock line's process cannot be shown to hold the lock, or its identity cannot
// be read) is not a refusal to traverse the run's directory: its permission error keeps its own words and is not
// relabelled as the role refusal (review F1).
func TestOwnerOnlyErrorLeavesLauncherProofRefusals(t *testing.T) {
	for _, base := range []error{runlock.ErrNotLockHolder, runlock.ErrUnverified} {
		err := fmt.Errorf("%w: pid 7: %w", base, fs.ErrPermission)
		if got := OwnerOnlyError(err, true); got != err || errors.Is(got, askproto.ErrOwnerOnly) {
			t.Fatalf("%v was relabelled: %v", base, got)
		}
	}
}
