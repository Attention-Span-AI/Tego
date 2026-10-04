// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"maps"
	"slices"
	"testing"

	"golang.org/x/net/bpf"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/landlock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// planeInherited is inherited tier-1 state whose filter the plane can narrow (landlock.Handle.PlaneFilter): the full
// filter is one instruction, the narrowed one two, and asked records the hook set it was asked with.
type planeInherited struct {
	dropped []string
	asked   *map[string]bool
}

var (
	fullFilter  = []bpf.RawInstruction{{Op: 6, K: 0x7fc00000}}
	planeNarrow = []bpf.RawInstruction{{Op: 6, K: 0x7fff0000}, {Op: 6, K: 0x7fff0000}}
)

func (planeInherited) LandlockRuleset() (int, bool)                { return -1, false }
func (planeInherited) SeccompFilter() ([]bpf.RawInstruction, bool) { return fullFilter, true }
func (i planeInherited) PlaneFilter(hooks map[string]bool) ([]bpf.RawInstruction, []string, error) {
	*i.asked = maps.Clone(hooks)
	if len(i.dropped) == 0 {
		return fullFilter, nil, nil
	}
	return planeNarrow, i.dropped, nil
}

// TestPlaneFilterIsTheLoadedHooksAndOnlyOnceUsed is enforce-plane R22/R27's notification half at the tier
// (TIER3-PLAN T16): Prepare asks the inherited filter to leave out what the loaded plane's attached hooks decide,
// by the set the plane reports and no other; SeccompFilter keeps the full filter until the runtime says a recorder
// reads the run (UsePlaneFilter), which returns what is left out; a run on the fanotify listener, and a plane whose
// hooks decide nothing notified, never narrow the filter. DecisionPlane names the mode and whether the plane decides
// execs.
func TestPlaneFilterIsTheLoadedHooksAndOnlyOnceUsed(t *testing.T) {
	t.Parallel()
	hooks := map[string]bool{"file_open": true, "bprm_check": true, "path_rename": true, "path_link": true,
		"path_unlink": true, "path_rmdir": true}
	for _, mode := range ebpfbindings.PlaneModes {
		t.Run(string(mode), func(t *testing.T) {
			var asked map[string]bool
			f, plane := planeFixture(t, mode, func(o *Options) {
				o.Inherit = func(context.Context, *agent.RuleTable, Run) (Inherited, error) {
					return planeInherited{dropped: []string{"rename", "unlinkat"}, asked: &asked}, nil
				}
			})
			plane.attached = hooks
			h, err := f.backend.Prepare(context.Background(), f.table, f.run)
			if err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			if !maps.Equal(asked, hooks) {
				t.Errorf("asked with %v, want the plane's attached hooks %v", asked, hooks)
			}
			if prog, _ := h.SeccompFilter(); !slices.Equal(prog, fullFilter) {
				t.Errorf("before UsePlaneFilter the filter is %v, want the full one", prog)
			}
			if dropped := h.UsePlaneFilter(); !slices.Equal(dropped, []string{"rename", "unlinkat"}) {
				t.Errorf("UsePlaneFilter = %v", dropped)
			}
			if prog, _ := h.SeccompFilter(); !slices.Equal(prog, planeNarrow) {
				t.Errorf("after UsePlaneFilter the filter is %v, want the narrowed one", prog)
			}
			if m, execs := h.DecisionPlane(); m != string(mode) || !execs {
				t.Errorf("DecisionPlane = %s, %v; want %s, true (a compiled explicit exec section decides exec)", m, execs, mode)
			}
			_ = h.Close()
		})
	}
	t.Run("nothing to drop", func(t *testing.T) {
		var asked map[string]bool
		f, plane := planeFixture(t, ebpfbindings.PlaneLSM, func(o *Options) {
			o.Inherit = func(context.Context, *agent.RuleTable, Run) (Inherited, error) {
				return planeInherited{asked: &asked}, nil
			}
		})
		plane.attached = map[string]bool{"bprm_check": true}
		h, err := f.backend.Prepare(context.Background(), f.table, f.run)
		if err != nil {
			t.Fatalf("Prepare: %v", err)
		}
		if dropped := h.UsePlaneFilter(); len(dropped) != 0 {
			t.Errorf("UsePlaneFilter = %v, want nothing", dropped)
		}
		if prog, _ := h.SeccompFilter(); !slices.Equal(prog, fullFilter) {
			t.Errorf("filter %v, want the full one", prog)
		}
		_ = h.Close()
	})
	t.Run("the fanotify listener", func(t *testing.T) {
		var asked map[string]bool
		f := newFixture(t, func(o *Options) {
			o.Inherit = func(context.Context, *agent.RuleTable, Run) (Inherited, error) {
				return planeInherited{dropped: []string{"rename"}, asked: &asked}, nil
			}
		})
		h, err := f.backend.Prepare(context.Background(), f.table, f.run)
		if err != nil {
			t.Fatalf("Prepare: %v", err)
		}
		if asked != nil {
			t.Errorf("a listener run asked the filter to narrow by %v", asked)
		}
		if dropped := h.UsePlaneFilter(); len(dropped) != 0 {
			t.Errorf("UsePlaneFilter = %v, want nothing", dropped)
		}
		if prog, _ := h.SeccompFilter(); !slices.Equal(prog, fullFilter) {
			t.Errorf("filter %v, want the full one", prog)
		}
		if m, execs := h.DecisionPlane(); m != "" || execs {
			t.Errorf("DecisionPlane = %q, %v; want none", m, execs)
		}
		_ = h.Close()
	})
}

// TestPlaneFilterHookNamesAreThePlanesHooks holds the filter's hook names (enforce/landlock, which does not import
// the objects' bindings) to bpf.PlaneHooks: a renamed hook would otherwise keep its notification silently forever.
func TestPlaneFilterHookNamesAreThePlanesHooks(t *testing.T) {
	names := map[string]bool{}
	for _, h := range ebpfbindings.PlaneHooks {
		names[h.Name] = true
	}
	for _, n := range []string{landlock.HookFileOpen, landlock.HookPathUnlink, landlock.HookPathRmdir,
		landlock.HookPathRename, landlock.HookPathLink, landlock.HookPathMknod, landlock.HookPathMkdir,
		landlock.HookPathSymlink, landlock.HookPathTruncate} {
		if !names[n] {
			t.Errorf("the filter's hook %q is no bpf.PlaneHook", n)
		}
	}
}
