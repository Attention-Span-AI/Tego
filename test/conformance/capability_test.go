// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"strings"
	"testing"
)

// TestCapabilityCrossCheck holds the oracle's enforcement predicates to canned compile --json tables and run_start
// lines: agreement passes, and each way the two can disagree fails with its own name.
func TestCapabilityCrossCheck(t *testing.T) {
	rel := func(abs string) string {
		if p, ok := strings.CutPrefix(abs, "/p/"); ok {
			return p
		}
		return ""
	}
	// out is writable: tier landlock cannot hold out/keys (parent writable) but holds secrets; repo/.git/config is a
	// deny_write target beneath the write entry repo.
	m := Model{Write: []string{"out", "repo"}, DenyRead: []string{"secrets", "out/keys"}, DenyWrite: []string{"repo/.git/config"}}
	const agree = `{"fs":[
		{"path":"/p/out","kind":"write","raw":"./out/"},
		{"path":"/p/repo","kind":"write","raw":"./repo/"},
		{"path":"/p/secrets","kind":"deny_read","raw":"./secrets/"},
		{"path":"/p/out/keys","kind":"deny_read","raw":"./out/keys/","unenforced":true},
		{"path":"/home/u/.ssh","kind":"deny_read","builtin":true},
		{"path":"/p/repo/.git/config","kind":"deny_write","builtin":true,"best_effort":true}]}`
	compileCases := []struct {
		name  string
		m     Model
		table string
		want  []string // a prefix per problem, in order; none for agreement
	}{
		{"agreement", m, agree, nil},
		{"compile claims a shadowed deny_read enforced at tier landlock", m,
			strings.Replace(agree, `"raw":"./out/keys/","unenforced":true`, `"raw":"./out/keys/"`, 1), []string{OverClaim}},
		{"compile marks an enforceable deny_read unenforced", m,
			strings.Replace(agree, `"raw":"./secrets/"`, `"raw":"./secrets/","unenforced":true`, 1), []string{Stricter}},
		{"compile claims deny_write enforced below a plane", m,
			strings.Replace(agree, `"builtin":true,"best_effort":true`, `"builtin":true`, 1), []string{OverClaim}},
		{"fs.assurance: kernel the model does not know", m,
			strings.Replace(agree, `"best_effort":true`, `"kernel_plane_required":true`, 1), []string{Unmodeled}},
		{"fs.assurance: kernel on both sides", Model{Write: m.Write, DenyRead: m.DenyRead, DenyWrite: m.DenyWrite, FSAssuranceKernel: true},
			strings.Replace(agree, `"best_effort":true`, `"kernel_plane_required":true`, 1), nil},
		{"a deny_write target the model lacks", Model{Write: m.Write, DenyRead: m.DenyRead}, agree, []string{Unmodeled}},
		{"a deny_read the table lacks", Model{Write: m.Write, DenyRead: append([]string{"more"}, m.DenyRead...), DenyWrite: m.DenyWrite},
			agree, []string{Unmodeled}},
		{"a declared deny_read the model lacks", Model{Write: m.Write, DenyRead: []string{"secrets"}, DenyWrite: m.DenyWrite},
			agree, []string{Unmodeled}},
		// fs.reads (ADR 0069): the unenforced marker stays the ruleset's; reads.landlock says whether the reads are held.
		{"reads held for the shadowed deny_read", m, withReads(agree, "held"), nil},
		{"reads direct for the shadowed deny_read under auto", m, withReads(agree, "direct"), []string{Stricter}},
		{"reads direct under fs.reads: direct", Model{Write: m.Write, DenyRead: m.DenyRead, DenyWrite: m.DenyWrite, Reads: ReadsDirect},
			withReads(agree, "direct"), nil},
		{"reads held under fs.reads: direct", Model{Write: m.Write, DenyRead: m.DenyRead, DenyWrite: m.DenyWrite, Reads: ReadsDirect},
			withReads(agree, "held"), []string{Unmodeled}},
		{"reads held for a nested entry compile found itself", Model{Write: m.Write, DenyRead: []string{"secrets"}, DenyWrite: m.DenyWrite},
			withReads(strings.Replace(agree, `{"path":"/p/out/keys","kind":"deny_read","raw":"./out/keys/","unenforced":true},`, "", 1), "held"), nil},
	}
	for _, tc := range compileCases {
		got, err := CompileCapabilityCrossCheck(tc.m, []byte(tc.table), rel)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		checkProblems(t, "compile: "+tc.name, got, tc.want)
	}
	if _, err := CompileCapabilityCrossCheck(m, []byte("not json"), rel); err == nil {
		t.Error("a table that is not JSON was read")
	}

	start := func(plane string, denyRead bool, bestEffort ...any) map[string]any {
		s := map[string]any{"kind": "run_start", "capabilities": map[string]any{"fs.deny_read": denyRead,
			protectedWriteTargets: plane == "lsm" || plane == "fmod_ret", gateFSOpenCompletion: false,
			createdLater: plane == "lsm" || plane == "fmod_ret"}}
		if plane != "" {
			s["decision_plane"] = plane
		}
		if bestEffort != nil {
			s["best_effort"] = bestEffort
		}
		return s
	}
	flat := Model{Write: []string{"repo"}, DenyRead: []string{"secrets"}, DenyWrite: []string{"repo/.git/config"}}
	direct := m
	direct.Reads = ReadsDirect
	runCases := []struct {
		name  string
		m     Model
		inv   Tier
		plane string
		start map[string]any
		want  []string
	}{
		// fs.reads: auto, the default, holds the reads of a run with a shadowed deny_read (ADR 0069): it is enforced.
		{"landlock: a shadowed deny_read, held", m, TierLandlock, "", start("", true, bestEffortDenyWrite), nil},
		{"landlock: a shadowed deny_read, held, reported false", m, TierLandlock, "", start("", false, bestEffortDenyWrite), []string{Stricter}},
		{"landlock: a shadowed deny_read under fs.reads: direct, reported", direct, TierLandlock, "", start("", false, bestEffortDenyWrite), nil},
		{"landlock: a shadowed deny_read under fs.reads: direct the run claims", direct, TierLandlock, "", start("", true, bestEffortDenyWrite), []string{OverClaim}},
		{"landlock: every deny_read enforceable, reported false", flat, TierLandlock, "", start("", false, bestEffortDenyWrite), []string{Stricter}},
		{"landlock: deny_write not listed best effort", flat, TierLandlock, "", start("", true), []string{OverClaim}},
		{"listener: as the oracle says", m, TierCgroup, "fanotify", start("fanotify", true, bestEffortDenyWrite), nil},
		{"listener: the run decided on a plane", m, TierCgroup, "fanotify", start("fmod_ret", true, bestEffortDenyWrite), []string{"the run's decision_plane"}},
		{"plane: deny_write enforced", m, TierBPFLSM, "lsm", start("lsm", true), nil},
		{"plane: deny_write still best effort", m, TierBPFLSM, "lsm", start("lsm", true, bestEffortDenyWrite), []string{Stricter}},
		{"plane: another best-effort cell is no deny_write", m, TierBPFLSM, "lsm", start("lsm", true, "gate.exec"), nil},
		{"listener: protected write targets claimed", m, TierCgroup, "fanotify", func() map[string]any {
			s := start("fanotify", true, bestEffortDenyWrite)
			s["capabilities"].(map[string]any)[protectedWriteTargets] = true
			return s
		}(), []string{OverClaim}},
		{"plane: protected write targets not said", m, TierBPFLSM, "lsm", func() map[string]any {
			s := start("lsm", true)
			delete(s["capabilities"].(map[string]any), protectedWriteTargets)
			return s
		}(), []string{"the run's capability line does not say " + protectedWriteTargets}},
		{"plane: protected write targets withheld", m, TierBPFLSM, "lsm", func() map[string]any {
			s := start("lsm", true)
			s["capabilities"].(map[string]any)[protectedWriteTargets] = false
			return s
		}(), []string{Stricter}},
		{"no deny_write target, none listed", Model{DenyRead: []string{"secrets"}}, TierLandlock, "", start("", true), nil},
		{"no deny_write target, one listed", Model{DenyRead: []string{"secrets"}}, TierLandlock, "", start("", true, bestEffortDenyWrite), []string{Unmodeled}},
		{"held: the deputy completes the opens", Model{DenyRead: []string{"secrets"}, HeldOpens: true}, TierLandlock, "", func() map[string]any {
			s := start("", true, "gate.fs.read/move")
			s["capabilities"].(map[string]any)[gateFSOpenCompletion] = true
			return s
		}(), nil},
		{"held: the deputy did not start", Model{DenyRead: []string{"secrets"}, HeldOpens: true}, TierLandlock, "", start("", true, "gate.fs.read/open", "gate.fs.write/open"),
			[]string{"the run reports gate.fs_open_completion false", "the run lists gate.fs.read/open", "the run lists gate.fs.write/open"}},
		{"copied: the run claims held completion", Model{DenyRead: []string{"secrets"}}, TierLandlock, "", func() map[string]any {
			s := start("", true)
			s["capabilities"].(map[string]any)[gateFSOpenCompletion] = true
			return s
		}(), []string{OverClaim}},
		{"listener: created_later claimed", m, TierCgroup, "fanotify", func() map[string]any {
			s := start("fanotify", true, bestEffortDenyWrite)
			s["capabilities"].(map[string]any)[createdLater] = true
			return s
		}(), []string{OverClaim}},
		{"landlock: created_later claimed by a run that holds its reads (ADR 0069 D4)", m, TierLandlock, "", func() map[string]any {
			s := start("", true, bestEffortDenyWrite)
			s["capabilities"].(map[string]any)[createdLater] = true
			s["fs_reads"] = map[string]any{"reads": "held", "why": "contract"}
			return s
		}(), nil},
		{"landlock: created_later claimed with reads direct", m, TierLandlock, "", func() map[string]any {
			s := start("", true, bestEffortDenyWrite)
			s["capabilities"].(map[string]any)[createdLater] = true
			s["fs_reads"] = map[string]any{"reads": "direct", "why": "contract"}
			return s
		}(), []string{OverClaim}},
		{"plane: created_later not said", m, TierBPFLSM, "lsm", func() map[string]any {
			s := start("lsm", true)
			delete(s["capabilities"].(map[string]any), createdLater)
			return s
		}(), []string{"the run's capability line does not say " + createdLater}},
		{"plane: the model's name entries, created_later withheld", Model{DenyRead: []string{"secrets"}, Names: builtinNames}, TierBPFLSM, "fmod_ret",
			func() map[string]any {
				s := start("fmod_ret", true)
				s["capabilities"].(map[string]any)[createdLater] = false
				return s
			}(), []string{Stricter}},
		{"plane: no name entry modelled, created_later false", m, TierBPFLSM, "lsm", func() map[string]any {
			s := start("lsm", true)
			s["capabilities"].(map[string]any)[createdLater] = false
			return s
		}(), nil},
		{"no capability line", m, TierCgroup, "fanotify", map[string]any{"decision_plane": "fanotify", "best_effort": []any{bestEffortDenyWrite}},
			[]string{"the run's capability line", "the run's capability line", "the run's capability line", "the run's capability line"}},
		{"no run_start", m, TierCgroup, "fanotify", nil, []string{"the run's ledger has no run_start"}},
	}
	for _, tc := range runCases {
		checkProblems(t, "run: "+tc.name, RunCapabilityCrossCheck(tc.m, tc.inv, tc.plane, tc.start), tc.want)
	}
}

// withReads is a compile --json table with its reads.landlock set.
func withReads(table, landlock string) string {
	return strings.TrimSuffix(table, "}") + `,"reads":{"landlock":"` + landlock + `"}}`
}

func checkProblems(t *testing.T, name string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: problems %q, want one each starting %q", name, got, want)
		return
	}
	for i := range got {
		if !strings.HasPrefix(got[i], want[i]) {
			t.Errorf("%s: problem %q, want it to start %q", name, got[i], want[i])
		}
	}
}
