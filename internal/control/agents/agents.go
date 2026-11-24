// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/agentid"
	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/scan/result"
	"github.com/attention-span-ai/tego/internal/shellword"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// View is all data required by Agents, its home variant and selected-agent detail.
// Each recorded row describes one named run. Discoveries remain separate and
// remembered omissions are marked only when the latest scan is usable.
type View struct {
	Rows                                               []Row
	Historical, Evidence, OtherPrograms                []Observation
	ScanCoverage                                       string
	ScanStatus, ScanNotice, ScanAge, ScanLabel, Footer string
	// ScanLines and ScanNotLooked are the saved scan's footer in plain words (result.PlainFooter), one line each.
	ScanLines, ScanNotLooked                                        []string
	ScanFinished                                                    time.Time
	InRunObservations                                               int
	DiscoveryNotice                                                 string
	DiscoveryTruncated                                              bool
	RefreshCommand, RefreshInstruction, Privacy, Empty, OverviewURL string
	OtherKnown                                                      bool
	OtherCount                                                      int
	OtherListed                                                     bool
	RefusedToday                                                    Count
	NotKnown                                                        []string
	RecordsPartial                                                  bool
	GuideDone                                                       bool
	Next                                                            guide.Next
}

// Row describes one recorded run or one separate observed program identity.
type Row struct {
	// Observations retain the checked scan detail for the agent detail page.
	Observations                                                       []Observation
	Agent                                                              agentid.Agent
	ID, Name, Stage, URL, Age, Membership, RecordCommand, RecordNotice string
	SeenAt                                                             time.Time
	// WhereAt is the time Membership refers to (a run's start, a scan's finish, a last sighting); the page shows it as
	// a time, never as text inside the sentence.
	WhereAt                   time.Time
	FirstSeen, LastSeen       time.Time
	ScanResult                string
	Remembered, NotSeenLatest bool
	// Refusals is the run's refused-action count, the number its run page shows (ledgerview.Run.Refusals). It is set
	// only for a recorded run found in the record (RefusalsKnown); RefusalsPartial says the count is a lower bound.
	Refusals                       int
	RefusalsKnown, RefusalsPartial bool
}

// Observation retains checked evidence paths and closed fact codes as text only.
type Observation struct {
	// Item contains typed, checked metadata only, including configured names.
	Item                                           result.Item
	ID, Kind, Name, Path, Folder, Membership, Fact string
	SeenAt                                         time.Time
}

// Count is an observed count, never a completeness or absence claim. Since is
// inclusive; Until is exclusive and uses the viewer clock's local calendar day.
type Count struct {
	Value        int
	Since, Until time.Time
	Partial      bool
	Notice       string
}

// Service reads data beneath the HTTP layer. Inputs is the serving user's
// trusted wiring, never request parameters or saved JSON. The dashboard is
// self-only; it must not use another user's home for a shared view.
type Service struct {
	Inputs func(context.Context) guide.Inputs
	Ledger string
}

// Forget removes one remembered discovery, named by its row ID, from the store under the same pinned
// directory, lock and file identity checks that remember uses. It never reads, changes or deletes a run
// record, a saved scan or a contract. See forgetDiscovery for the errors.
func (s Service) Forget(ctx context.Context, id string, now time.Time) error {
	if s.Inputs == nil {
		return ErrForgetUnavailable
	}
	if now.IsZero() {
		now = time.Now()
	}
	in := s.Inputs(ctx)
	return forgetDiscovery(in.Home, uint32(in.UID), id, now)
}

// ownStateWords is the page's caution about Tego's own saved files, in plain words. It states what was shown and what
// was only worked out from the code, and that no per-run caution is computed.
const ownStateWords = "Tego protects the saved scan and the list of remembered programs against ordinary writes by a program it governs. This was shown on a test machine, even when a run was allowed to use the whole home folder. One case is not shown yet: when the record is kept outside the home folder and a run may read the whole home, these files can still be read. That case is worked out from the code, not tested on a real machine. The stages shown for a run do not depend on this list. This list never proves that nothing else is running. A program run by the same user outside Tego can change both the saved scan and the remembered programs, and can make them unreadable by changing their permissions. Tego does not work out a caution for each run about this, so none is shown."

// Load rechecks file identity and freshness and remembers discoveries on each
// request. No process starts and no saved string becomes executable command text.
func (s Service) Load(ctx context.Context, now time.Time) View {
	v := View{Footer: "No saved scan was read. Process, program and settings coverage is unknown.", ScanStatus: "unavailable", ScanNotice: "The scan location is not configured.",
		RefreshCommand: "tego scan", RefreshInstruction: "Run tego scan from the project folder you want to look at, then refresh this page.",
		Privacy: "When Tego lists a setting, it keeps the name and never the value", OverviewURL: "/overview"}
	if now.IsZero() {
		now = time.Now()
	}
	// One read of the record feeds each run row's count and the count for today.
	snap, snapErr := ledgerview.Load(s.Ledger)
	if s.Inputs != nil {
		in := s.Inputs(ctx)
		in.Now = now
		in.Scan = guide.ReadScan(in.Home, in.UID, in.Host.BootID, now)
		// The same adapter and identity rule feed setup and this page. Its bounded
		// guide reuses its run checks, then checks more within its page budget.
		gctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		st := guide.Compute(gctx, in)
		cancel()
		v.Next = st.Next
		v.NotKnown = st.NotKnown
		v.RecordsPartial = st.RecordsPartial
		v.GuideDone = st.Next.Rule == guide.RuleEnforceDone
		r, err := in.Scan.ScanResult()
		if err != nil {
			v.ScanStatus, v.ScanNotice = scanError(err)
		} else {
			v.scan(r, now)
			for _, item := range r.Snapshot.Items {
				if (item.Kind == "process" || item.Kind == "other_program") && item.Process().Membership == "in-run" {
					v.InRunObservations++
				}
			}
			if v.InRunObservations > 0 {
				v.Footer += fmt.Sprintf(" The scan saw %d %s inside a Tego run. %s no row here, because runs are listed from the record.", v.InRunObservations, plural(v.InRunObservations, "program", "programs"), plural(v.InRunObservations, "It gets", "They get"))
			}
		}
		for _, a := range st.Agents {
			row := Row{Agent: a, ID: a.ID, Name: a.Name, Stage: a.Current, URL: "/agents/" + a.ID, SeenAt: a.LastSeen, Age: age(a.LastSeen, now)}
			for _, stage := range a.Stages {
				if stage.ID == a.Current {
					row.Stage = stage.Label
				}
			}
			if a.Current == "observation" {
				row.Stage = "Seen by scan"
			}
			row.Membership = "Scan observation; current run membership is unknown."
			if a.RunID != "" {
				row.Membership = "Recorded run " + a.RunID
				row.WhereAt = a.RunStarted
				if snapErr == nil {
					if run := snap.Find(a.RunID); run != nil {
						row.Refusals, row.RefusalsKnown, row.RefusalsPartial = run.Refusals, true, runIncomplete(run) || snap.RunsCut || snap.LinesCut
					}
				}
			}
			for _, f := range a.Found {
				for _, item := range r.Snapshot.Items {
					if item.ID == f.ID {
						row.Observations = append(row.Observations, observation(item, r.Snapshot.Finished))
					}
					if item.ID == f.ID && item.Kind == "process" {
						if item.Process().Membership == "outside-run" {
							row.Membership, row.WhereAt = "Seen outside Tego", r.Snapshot.Finished
						} else {
							row.Membership, row.WhereAt = "Seen by the scan ("+plainMembership(result.MembershipWords(item.Process(), nil))+")", r.Snapshot.Finished
						}
					}
				}
			}
			row.RecordCommand = watchLine(a.Folder)
			row.RecordNotice = "Fill in the command you start it with. Tego does not reconstruct a launch command from scan evidence."
			if row.RecordCommand == "" {
				row.RecordNotice = "No command is shown: the working folder is unknown or cannot be shown safely. From a known folder, run tego watch with your own command."
			}
			v.Rows = append(v.Rows, row)
		}
		v.remember(in.Home, uint32(in.UID), r, err, now)
	}
	v.Footer = strings.TrimSpace(v.Footer + " " + ownStateWords)
	if v.DiscoveryNotice != "" {
		v.Footer += " " + v.DiscoveryNotice
	}
	v.RefusedToday = refusalsIn(snap, snapErr, now)
	if v.RecordsPartial || s.Inputs == nil {
		v.RefusedToday.Partial = true
		v.RefusedToday.Notice += " Not every run could be checked, so the real number can be higher."
	}
	if len(v.Rows) == 0 {
		v.Empty = "No match among the rules and sources read. This does not establish that no agents exist."
		switch {
		case v.ScanStatus != "fresh":
			v.Empty = "No current agent evidence can be shown. This does not establish that no agents exist."
		case len(v.Evidence) > 0:
			v.Empty = "Only settings, declarations or configured evidence is available. This does not establish that no agents exist."
		case v.ScanCoverage == "partial":
			v.Empty = "Some selected scan sources could not be read. Review scan coverage. This does not establish that no agents exist."
		}
	}
	return v
}

func (v *View) scan(r result.ReadResult, now time.Time) {
	s := r.Snapshot
	v.ScanCoverage = s.Status
	v.ScanStatus = r.Freshness
	v.ScanFinished = s.Finished
	v.ScanAge = age(s.Finished, now)
	v.ScanLabel = "A program run by the same user outside Tego can change this saved scan."
	switch r.Freshness {
	case "fresh":
		v.ScanNotice = "Saved observations, seen at the scan time; they do not say what is running now."
	case "stale":
		v.ScanNotice = "The saved scan is older than five minutes. Its observations are historical."
	case "another-boot":
		v.ScanNotice = "The saved scan is from another boot. Its observations are historical."
	case "future":
		v.ScanNotice = "The saved scan has a future finish time. Its observations are historical."
	default:
		v.ScanNotice = "The saved scan's boot or time could not be checked. Its observations are historical."
	}
	if s.Status == "partial" {
		v.ScanNotice += " Some selected sources could not be read; see scan coverage."
	}
	if s.Status == "failed" {
		v.ScanStatus = "failed"
		v.ScanNotice = "The saved scan reports failure. Its observations are historical."
	}
	// The scan's own footer is operator wording (`tego scan`); this page words the same facts for a person.
	plain := result.PlainFooter(s)
	v.ScanLines, v.ScanNotLooked = plain.Lines, plain.NotLooked
	v.Footer = ""
	v.OtherKnown = r.Freshness == "fresh" && s.Status != "failed"
	v.OtherCount = s.Counts.Other
	v.OtherListed = s.OtherListed
	for _, i := range s.Items {
		if (i.Kind == "process" || i.Kind == "other_program") && i.Process().Membership == "in-run" {
			continue
		}
		o := observation(i, s.Finished)
		if r.Freshness != "fresh" || s.Status == "failed" || slices.Contains(i.Caveats, "historical") {
			v.Historical = append(v.Historical, o)
			continue
		}
		switch i.Kind {
		case "other_program":
			v.OtherPrograms = append(v.OtherPrograms, o)
		case "process", "program": // these are identity rows
		default:
			v.Evidence = append(v.Evidence, o)
		}
	}
}

func observation(i result.Item, at time.Time) Observation {
	o := Observation{Item: i, ID: i.ID, Kind: i.Kind, Name: i.Name, SeenAt: at}
	facts := make([]string, 0, len(i.Evidence))
	for _, e := range i.Evidence {
		facts = append(facts, e.RuleID+": "+e.Fact+" ("+e.SourceID+")")
	}
	o.Fact = strings.Join(facts, ", ")
	if len(i.Caveats) > 0 {
		o.Fact += "; caveats: " + strings.Join(i.Caveats, ", ")
	}
	path := func(p *string) string {
		if p != nil {
			return *p
		}
		return ""
	}
	switch i.Kind {
	case "process", "other_program":
		p := i.Process()
		o.Path, o.Folder = path(p.Exe), path(p.Cwd)
		o.Membership = plainMembership(result.MembershipWords(p, nil))
	case "program", "settings":
		o.Path = path(i.File().Path)
	case "project":
		o.Path = path(i.Project().Path)
	case "mcp_server":
		c := i.Config()
		o.Path = path(c.Path)
		o.Name = c.Server
		o.Fact += "; configured only; client " + c.Client + "; transport " + c.Transport
	case "user_unit", "timer":
		u := i.Unit()
		o.Path = path(u.Path)
		o.Name = u.Name
		o.Fact += "; configured only"
	}
	return o
}

// Repairs are fixed text, never filesystem error strings or saved input. Readers
// leave unsafe paths unchanged; the owner checks links before changing modes.
const scanRepair = " Check the owner, mode and links at ~/.tego/scan and ~/.tego/scan/last.json. Move links or invalid state aside; do not chmod through a link. For your checked directory and regular file with one link, run chmod 700 ~/.tego/scan and chmod 600 ~/.tego/scan/last.json. Then run tego scan from your project folder and refresh this page."

func scanError(err error) (string, string) {
	var notice string
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "missing", "No saved scan. Run tego scan from your project folder."
	case errors.Is(err, result.ErrMode):
		notice = "The saved scan could not be read: scan directory must have mode 0700."
	case errors.Is(err, result.ErrSize):
		notice = "The saved scan could not be read: larger than 1 MiB."
	case errors.Is(err, result.ErrUnsafe):
		notice = "The saved scan could not be read: unsafe owner, mode, links or file type."
	case errors.Is(err, result.ErrChanged):
		notice = "The saved scan could not be read: changed during the read."
	case errors.Is(err, result.ErrInvalid):
		notice = "The saved scan could not be read: invalid or unsupported result."
	default:
		notice = "The saved scan could not be read: unavailable result."
	}
	return "unreadable", notice + scanRepair
}

func watchLine(folder string) string {
	if !filepath.IsAbs(folder) || len(folder) > 4096 || record.Printable(folder) != folder {
		return ""
	}
	return "cd " + shellword.Quote(folder) + " && tego watch -- <the command you start it with>"
}
func age(at, now time.Time) string {
	if at.IsZero() {
		return "Time unknown"
	}
	if at.After(now) {
		return "Future time"
	}
	d := now.Sub(at)
	if d < time.Minute {
		return "Just now"
	}
	n, unit := int(d/time.Minute), "minute"
	if d >= 24*time.Hour {
		n, unit = int(d/(24*time.Hour)), "day"
	} else if d >= time.Hour {
		n, unit = int(d/time.Hour), "hour"
	}
	return fmt.Sprintf("%d %s ago", n, plural(n, unit, unit+"s"))
}

// plural picks the singular form for exactly one and the plural form otherwise.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// plainMembership puts the scan's run-membership phrase in the page's plainer words; other phrases are the
// scan's own.
func plainMembership(w string) string {
	if w == "outside a Tego run" {
		return "not started by Tego"
	}
	return w
}
func refusals(root string, now time.Time) Count {
	snap, err := ledgerview.Load(root)
	return refusalsIn(snap, err, now)
}

// refusalsIn counts today's refusals in one loaded record, the same snapshot the rows' counts come from.
func refusalsIn(snap *ledgerview.Snapshot, err error, now time.Time) Count {
	y, m, d := now.Date()
	since := time.Date(y, m, d, 0, 0, 0, 0, now.Location())
	until := since.AddDate(0, 0, 1)
	c := Count{Since: since, Until: until, Notice: "Counted from the records Tego could read. Runs it could not read are not counted. Each refusal is counted once. At some tiers a refused read is not recorded at all."}
	if err != nil {
		c.Partial = true
		c.Notice = "Tego could not read the ledger, so it cannot count today's refusals."
		return c
	}
	p := snap.Query(ledgerview.Filter{Verdicts: []string{"refused"}, Since: since, Until: until, PageSize: 1})
	c.Value = p.Matched
	c.Partial = snap.RunsCut || snap.LinesCut || snap.Partial
	for _, r := range snap.Runs {
		if runIncomplete(r) {
			c.Partial = true
		}
	}
	if c.Partial {
		c.Notice += " Some records are incomplete or too large to read in full, so the real number can be higher."
	}
	return c
}

// runIncomplete is whether Tego could not read all of a run's record, so a count taken from it is a lower bound.
func runIncomplete(r *ledgerview.Run) bool {
	return r.Cut || r.Bad > 0 || r.ReceiptReadsUnrecorded || r.RefusedReadsUnknown
}
