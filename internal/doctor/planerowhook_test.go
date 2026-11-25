// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
)

// planeRetryHook is the hook whose outside leg the retry test makes fail: socket_create is in every kernel's plane, and
// its outside leg is a plain socket(2) of doctor's own that passes.
const planeRetryHook = "socket_create"

// planeRowOfHook is the row of the plane hook named hook (bpf.PlaneHook.Name, the name PlaneRowForceForTest and the
// probe's outside leg use) among one mode's rows. A row is named by planeRowName, the hook's ELF section in the row's
// own mode: "lsm/socket_create" in LSM mode, "fmod_ret/security_socket_create" in fmod_ret mode, so no one suffix
// finds it in both. nil when the rows have no such hook.
func planeRowOfHook(rows []HookResult, hook string) *HookResult {
	for _, h := range bpfobj.PlaneHooks {
		if h.Name != hook {
			continue
		}
		for i := range rows {
			if rows[i].Plane != "" && rows[i].Hook == planeRowName(h, rows[i].Plane) {
				return &rows[i]
			}
		}
	}
	return nil
}

// TestPlaneRowOfHookFindsTheRowOfEitherMode: the row the retry test forces is found by the hook's name in LSM mode
// and in fmod_ret mode, with the row names a real boot of each mode printed (the cold-start guest's two boots); a hook
// whose name is another's suffix is not taken for it, and an absent hook gives nil.
func TestPlaneRowOfHookFindsTheRowOfEitherMode(t *testing.T) {
	for _, tc := range []struct {
		mode bpfobj.PlaneMode
		rows []string
		want string
	}{
		{bpfobj.PlaneLSM, []string{"lsm/file_open", "lsm/socket_bind", "lsm/socket_create", "lsm/key_permission"}, "lsm/socket_create"},
		{bpfobj.PlaneFmodRet, []string{"fmod_ret/security_file_open", "fmod_ret/security_socket_bind", "fmod_ret/security_socket_create", "fmod_ret/security_key_permission"}, "fmod_ret/security_socket_create"},
	} {
		var rows []HookResult
		for _, n := range tc.rows {
			rows = append(rows, HookResult{Hook: n, Plane: tc.mode})
		}
		got := planeRowOfHook(rows, planeRetryHook)
		if got == nil || got.Hook != tc.want {
			t.Errorf("mode %s: found %+v, want the row %q", tc.mode, got, tc.want)
		}
		if planeRowOfHook(rows, "no_such_hook") != nil {
			t.Errorf("mode %s: a hook that does not exist found a row", tc.mode)
		}
		// Every hook of the table is found in its own row of each mode, and by no other.
		var all []HookResult
		for _, h := range bpfobj.PlaneHooks {
			all = append(all, HookResult{Hook: planeRowName(h, tc.mode), Plane: tc.mode})
		}
		for _, h := range bpfobj.PlaneHooks {
			if got := planeRowOfHook(all, h.Name); got == nil || got.Hook != planeRowName(h, tc.mode) {
				t.Errorf("mode %s: hook %s found %+v", tc.mode, h.Name, got)
			}
		}
	}
	if planeRowOfHook([]HookResult{{Hook: "lsm/socket_create", Plane: bpfobj.PlaneFmodRet}}, planeRetryHook) != nil {
		t.Error("an LSM-mode name in an fmod_ret row found a row")
	}
}
