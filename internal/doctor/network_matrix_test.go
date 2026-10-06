// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"strings"
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestMachineMatrixNetworkNeedsMeasuredCoverage(t *testing.T) {
	for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
		t.Run(string(tier), func(t *testing.T) {
			for _, missing := range []string{"", "cgroup/connect4", "cgroup/connect6", "cgroup/sendmsg4", "cgroup/sendmsg6", "cgroup/connect_unix", "cgroup/sendmsg_unix"} {
				t.Run(missing, func(t *testing.T) {
					st := state(nil)
					for i := range st.hooks {
						if st.hooks[i].Hook == missing {
							st.hooks[i].Attached = false
						}
					}
					set, _ := st.machineMatrix(tier)
					tcp := missing != "cgroup/connect4" && missing != "cgroup/connect6"
					udp := tcp && missing != "cgroup/sendmsg4" && missing != "cgroup/sendmsg6"
					unix := missing != "cgroup/connect_unix" && missing != "cgroup/sendmsg_unix"
					if set.Has(backend.CapTCPDestinationKernel) != tcp || set.Has(backend.CapUDPByDestination) != udp || set.Has(backend.CapUnixDestinationKernel) != unix {
						t.Fatalf("missing %q: TCP=%v UDP=%v Unix=%v; want %v %v %v", missing, set.Has(backend.CapTCPDestinationKernel), set.Has(backend.CapUDPByDestination), set.Has(backend.CapUnixDestinationKernel), tcp, udp, unix)
					}
				})
			}
			set, _ := (probeState{}).machineMatrix(tier)
			for _, cap := range []backend.Capability{backend.CapTCPDestinationKernel, backend.CapUDPByDestination, backend.CapUnixDestinationKernel} {
				if set.Has(cap) {
					t.Errorf("unprobed state claims %s", cap)
				}
			}
			st := state(func(st *probeState) {
				for i := range st.hooks {
					st.hooks[i].StandIn = true
				}
			})
			set, _ = st.machineMatrix(tier)
			for _, cap := range []backend.Capability{backend.CapTCPDestinationKernel, backend.CapUDPByDestination, backend.CapUnixDestinationKernel} {
				if set.Has(cap) {
					t.Errorf("minimal stand-in claims %s", cap)
				}
			}
		})
	}
}

// TestMachineMatrixSocketFamiliesNeedBothSocketPrograms: the machine's net.socket_families row is on at tiers cgroup
// and bpflsm only where D7 loaded and attached both cgroup/sock_create and cgroup/setsockopt, the two programs every
// run with a net: section attaches for the bound (ADR 0018 PR 2 and (7)); either one failing, or a stand-in, turns it
// off with a note naming the row.
func TestMachineMatrixSocketFamiliesNeedBothSocketPrograms(t *testing.T) {
	for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
		for _, missing := range []string{"", "cgroup/sock_create", "cgroup/setsockopt"} {
			t.Run(string(tier)+"/"+missing, func(t *testing.T) {
				st := state(nil)
				for i := range st.hooks {
					if st.hooks[i].Hook == missing {
						st.hooks[i].Attached = false
					}
				}
				set, notes := st.machineMatrix(tier)
				if got, want := set.Has(backend.CapSocketFamilies), missing == ""; got != want {
					t.Fatalf("missing %q: net.socket_families %v, want %v (note %q)", missing, got, want,
						notes[backend.CapSocketFamilies])
				}
				if missing != "" && !strings.Contains(notes[backend.CapSocketFamilies], missing) {
					t.Errorf("missing %q: the note %q does not name it", missing, notes[backend.CapSocketFamilies])
				}
			})
		}
	}
}

func TestMachineMatrixUnixFallbackNeedsActualSelectedPlaneHooks(t *testing.T) {
	for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
		for _, mode := range bpfobj.PlaneModes {
			for _, failure := range []string{"", "socket_connect", "socket_sendmsg", "absent", "stand-in", "unprobed", "unselected", "loaded-cgroup-connect"} {
				t.Run(string(tier)+"/"+string(mode)+"/"+failure, func(t *testing.T) {
					st := state(nil)
					for i := range st.hooks {
						if st.hooks[i].Hook == "cgroup/connect_unix" || st.hooks[i].Hook == "cgroup/sendmsg_unix" {
							st.hooks[i].Loaded, st.hooks[i].Attached = false, false
							if failure == "loaded-cgroup-connect" && st.hooks[i].Hook == "cgroup/connect_unix" {
								st.hooks[i].Loaded = true // runtime omits the fallback when this program loaded
							}
						}
					}
					st.plane = passingPlane(string(mode))
					if failure == "unselected" {
						st.plane.Selected = PlaneFanotify
						for i := range st.plane.Modes {
							st.plane.Modes[i].OK = false
						}
					}
					if failure != "unprobed" {
						rows := passingPlaneRows()
						for i := range rows {
							if rows[i].Plane == mode && (rows[i].Function == "security_"+failure || rows[i].Hook == "lsm/"+failure) {
								rows[i].Attached = false
							}
							if failure == "absent" && rows[i].Plane == mode && (rows[i].Hook == "lsm/socket_connect" || rows[i].Hook == "fmod_ret/security_socket_connect") {
								rows[i].Absent, rows[i].Attached = true, false
							}
							if failure == "stand-in" && rows[i].Plane == mode {
								rows[i].StandIn = true
							}
						}
						st.hooks = append(st.hooks, rows...)
					}
					set, _ := st.machineMatrix(tier)
					want := failure == "" && (tier == backend.TierCgroup || mode == bpfobj.PlaneLSM)
					if set.Has(backend.CapUnixDestinationKernel) != want {
						t.Fatalf("Unix kernel=%v want %v (pin=%s)", set.Has(backend.CapUnixDestinationKernel), want, st.plane.Pin)
					}
				})
			}
		}
	}
	// Landlock never turns port/scope rights into full destination enforcement.
	st := state(func(st *probeState) { st.landlockABI = 11; st.plane = passingPlane(config.PlaneAuto) })
	set, _ := st.machineMatrix(backend.TierLandlock)
	if set.Has(backend.CapTCPDestinationKernel) || set.Has(backend.CapUnixDestinationKernel) || set.Has(backend.CapUDPByDestination) {
		t.Fatal("Landlock claims full kernel destination enforcement")
	}
}
