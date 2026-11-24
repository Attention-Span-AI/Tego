// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"fmt"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// maxLaunchPlaces bounds the other places a launch note names; the rest are counted.
const maxLaunchPlaces = 3

// LaunchNote says, for one rules file's runs (runs, newest first), where the run shown started and where the file's
// other runs did, when they did not all start in one place ("" when they did, or there is one run). A rules file is
// not one contract at one place: a relative entry is placed from the folder a run starts in and an automatic tier
// resolves to the tier the run gets, so the same file gives other rules to a run launched elsewhere. The page shows
// one run's rules and a change is checked as the file's newest run started (rules.CheckContext), so the note names
// that run's place too when it is not the shown run's.
func LaunchNote(runs []*ledgerview.Run, shown *ledgerview.Run) string {
	if shown == nil {
		return ""
	}
	type place struct {
		cwd, tier string
		n         int
	}
	var places []place
	at := map[[2]string]int{}
	for _, r := range runs {
		k := [2]string{r.Cwd, r.Tier}
		i, ok := at[k]
		if !ok {
			i = len(places)
			at[k] = i
			places = append(places, place{cwd: r.Cwd, tier: r.Tier})
		}
		places[i].n++
	}
	if len(places) < 2 {
		return ""
	}
	where := func(cwd, tier string) string {
		if cwd == "" {
			cwd = "a folder the run did not record"
		}
		if tier == "" {
			tier = "unknown"
		}
		return "in " + cwd + " at tier " + tier
	}
	here := [2]string{shown.Cwd, shown.Tier}
	var b strings.Builder
	fmt.Fprintf(&b, "This rules file started runs in more than one place. The run shown started %s", where(shown.Cwd, shown.Tier))
	var others []string
	for _, p := range places {
		if [2]string{p.cwd, p.tier} == here {
			continue
		}
		if len(others) == maxLaunchPlaces {
			others = append(others, fmt.Sprintf("%d more places", len(places)-1-maxLaunchPlaces))
			break
		}
		noun := "runs"
		if p.n == 1 {
			noun = "run"
		}
		others = append(others, fmt.Sprintf("%d %s started %s", p.n, noun, where(p.cwd, p.tier)))
	}
	for _, o := range others {
		b.WriteString("; ")
		b.WriteString(o)
	}
	b.WriteString(". A relative entry is placed from the folder a run starts in and an automatic tier resolves to the tier the run gets, so these rules are the run shown's, not every run's.")
	if len(runs) > 0 && runs[0].ID != shown.ID && [2]string{runs[0].Cwd, runs[0].Tier} != here {
		fmt.Fprintf(&b, " A change to the file is checked as its newest run started, %s.", where(runs[0].Cwd, runs[0].Tier))
	}
	return b.String()
}

// LaunchNoteOf is LaunchNote for the runs of the snapshot that named the rules file ref (refOf gives a run's file ref),
// newest first as the snapshot lists them.
func LaunchNoteOf(snap *ledgerview.Snapshot, ref string, refOf func(contract string) string, shown *ledgerview.Run) string {
	if snap == nil || ref == "" {
		return ""
	}
	return LaunchNote(slices.DeleteFunc(slices.Clone(snap.Runs), func(r *ledgerview.Run) bool { return refOf(r.Contract) != ref }), shown)
}
