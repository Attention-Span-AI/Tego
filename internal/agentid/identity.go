// SPDX-License-Identifier: Apache-2.0

package agentid

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The stage identifiers are presentation-independent and ordered by progress.
const (
	FoundStage    = "found"
	RecordedStage = "recorded"
	ContractStage = "contract"
	EnforcedStage = "enforced"
	VerifiedStage = "verified"
)

// Verification is an explicit record-check result supplied by the caller.
// Its zero value never establishes verification.
type Verification uint8

// Verification results distinguish a broken record from one not checked.
const (
	Unchecked Verification = iota
	Verified
	Broken
	CannotVerify
)

// Found is one eligible reported observation, never launchable command text.
// Command is the observed executable path, not an argument vector. The caller
// keeps stale, failed or foreign-recipient scans outside these inputs.
type Found struct {
	ID, Name, Command, Folder, Source, Fact string
	UID                                     uint32
	UIDKnown                                bool
	IdentityUnknown                         bool
	SeenAt                                  time.Time
}

// Run is the recorded identity and independent verification result for a run.
// Command preserves word boundaries; ContractPath is only the explicit
// run_start.contract_source.path, never a name inferred from the agent or folder.
type Run struct {
	ID, Name                           string
	Command                            []string `json:"-"`
	Folder, Source, ContractPath, Tier string
	UID                                uint32
	UIDKnown                           bool
	Ended                              bool
	Verification                       Verification
	VerificationReason                 string
	Started                            time.Time
}

// Contract reports the current compile result of an explicitly addressed file
// in CompileRunID's folder, tier, grants and run-directory context.
type Contract struct {
	Path, CompileRunID string
	Compiles           bool
	Reason             string
}

// Fact states exactly which evidence establishes a stage. CannotTell preserves
// missing or conflicting evidence even when independent evidence establishes it.
type Fact struct {
	Established                     bool
	Text, Source, RunID, CannotTell string
}

// Stage is one labelled step and the fact or uncertainty behind its tick.
type Stage struct {
	ID, Label string
	Fact      Fact
}

// Agent is an immutable resolved row. Command displays only the program word,
// never arguments. It is never used to compare identities or to construct a
// command for execution.
type Agent struct {
	ID, Name, Command, Folder string
	RunID                     string
	RunStarted                time.Time
	SelectionRule             string
	VerificationReason        string
	RelatedRunIDs             []string
	Relationship, NextStep    string
	UID                       uint32
	UIDKnown                  bool
	Found                     []Found
	Runs                      []Run
	ContractPath              string
	Stages                    []Stage
	Current                   string
	LastSeen                  time.Time
}

type group struct {
	key         string
	agent       Agent
	uncertainty string
}

// Resolve relates the caller's bounded, validated facts without performing I/O.
// It keeps observations separate and indexes exact program spellings only for
// optional explanatory words. The output owns its slices, including each
// recorded command.
func Resolve(found []Found, runs []Run, contracts []Contract) []Agent {
	groups := make(map[string]*group, len(runs)+len(found))
	programs := make(map[string][]string)
	for _, input := range runs {
		r := input
		r.Command = slices.Clone(input.Command)
		key := runKey(r)
		g := &group{key: key, agent: Agent{UID: r.UID, UIDKnown: r.UIDKnown, Folder: r.Folder, Runs: []Run{r}}}
		groups[key] = g
		if k, ok := programKey(first(r.Command), r.Folder, r.UID, r.UIDKnown); ok {
			programs[k] = append(programs[k], r.ID)
		}
	}
	for _, f := range found {
		key, eligible := programKey(f.Command, f.Folder, f.UID, f.UIDKnown)
		why := "Cannot tell whether this observation relates to a recorded run: exact absolute program and folder paths and a known uid are needed. The scan keeps no arguments."
		next := "Record this program with Tego using its original launch command and folder; open a run's record to inspect that named run."
		var related []string
		if f.IdentityUnknown {
			eligible = false
			why = "The scan reports unknown process identity; it cannot tell whether this observation relates to a recorded run."
		} else if eligible {
			related = slices.Clone(programs[key])
			if len(related) > 0 {
				slices.Sort(related)
				related = slices.Compact(related)
				why = "This observation may be the same program as recorded run(s) " + strings.Join(related, ", ") + "; the scan keeps no arguments, so it cannot tell. The observation says nothing about those runs."
			} else {
				why = "Cannot tell whether this observation relates to a recorded run: no exact program path, folder and uid match. PATH, relative paths, symlinks and wrappers may spell a launch differently; the scan keeps no arguments."
			}
		}
		// Observations never enter recorded rows. Even matching program paths
		// cannot distinguish a second worker with different arguments (ADR 0145).
		observationKey := encode("found", f.ID, f.Source, f.Command, f.Folder, stringKey(f.UID), strconv.FormatBool(f.UIDKnown))
		if eligible {
			observationKey = encode("found-program", key)
		}
		g := groups[observationKey]
		if g == nil {
			g = &group{key: observationKey, agent: Agent{UID: f.UID, UIDKnown: f.UIDKnown, Folder: f.Folder,
				RelatedRunIDs: related, Relationship: why, NextStep: next}, uncertainty: why}
			groups[observationKey] = g
		}
		g.agent.Found = append(g.agent.Found, f)
	}
	checked := contractChecks(contracts)
	rows := make([]Agent, 0, len(groups))
	for _, g := range groups {
		finish(g, checked)
		rows = append(rows, g.agent)
	}
	slices.SortFunc(rows, func(a, b Agent) int {
		for _, p := range [][2]string{{a.Name, b.Name}, {a.Folder, b.Folder}, {a.Command, b.Command}, {a.ID, b.ID}} {
			if n := strings.Compare(p[0], p[1]); n != 0 {
				return n
			}
		}
		return 0
	})
	return rows
}

func finish(g *group, contracts map[string]*bool) {
	a := &g.agent
	slices.SortFunc(a.Runs, func(a, b Run) int {
		if n := b.Started.Compare(a.Started); n != 0 {
			return n
		}
		return strings.Compare(encode(a.ID, a.Name, a.Source, a.ContractPath, a.Tier, strconv.Itoa(int(a.Verification))), encode(b.ID, b.Name, b.Source, b.ContractPath, b.Tier, strconv.Itoa(int(b.Verification))))
	})
	slices.SortFunc(a.Found, func(a, b Found) int {
		if n := b.SeenAt.Compare(a.SeenAt); n != 0 {
			return n
		}
		return strings.Compare(encode(a.ID, a.Name, a.Source, a.Fact), encode(b.ID, b.Name, b.Source, b.Fact))
	})
	if len(a.Runs) != 0 {
		r := a.Runs[0]
		a.Name, a.Command, a.LastSeen = r.Name, first(r.Command), r.Started
		a.RunID, a.RunStarted = r.ID, r.Started
		a.SelectionRule = "Each recorded run has its own row; all stage facts describe only this named run."
		a.VerificationReason = verificationReason(r)
		a.NextStep = "Open this run's record to inspect its check and evidence."
		if r.Verification != Verified {
			a.NextStep = "Check this named run's record before relying on its contract or enforcing tier."
		}
	}
	if len(a.Found) != 0 {
		f := a.Found[0]
		if f.Name != "" {
			a.Name = f.Name
		}
		if a.Command == "" {
			a.Command = f.Command
		}
		if f.SeenAt.After(a.LastSeen) {
			a.LastSeen = f.SeenAt
		}
	}
	if a.Name == "" {
		a.Name = a.Command
	}
	if a.Name == "" {
		a.Name = "Agent identity unknown"
	}
	sum := sha256.Sum256([]byte(g.key))
	a.ID = "agent-" + hex.EncodeToString(sum[:])
	a.Stages = []Stage{
		{ID: FoundStage, Label: "Found", Fact: Fact{CannotTell: "No eligible scan observation establishes this stage."}},
		{ID: RecordedStage, Label: "Recorded", Fact: Fact{CannotTell: "No exact identity relation establishes a recorded run."}},
		{ID: ContractStage, Label: "Contract", Fact: Fact{CannotTell: "No recorded contract source and matching current compile establish this agent's contract."}},
		{ID: EnforcedStage, Label: "Enforced", Fact: Fact{CannotTell: "No recorded enforcing tier establishes this stage."}},
		{ID: VerifiedStage, Label: "Verified", Fact: Fact{CannotTell: "No ended enforcing run has an affirmative record verification result."}},
	}
	if len(a.Found) > 0 {
		f := a.Found[0]
		text := f.Fact
		if text == "" {
			text = "The saved scan reports this program observation."
		}
		a.Stages[0].Fact = Fact{Text: text, Source: foundSource(f), CannotTell: "A scan observation establishes no stage of a recorded run."}
		a.Current = "observation"
	}
	if g.uncertainty != "" {
		a.Stages[1].Fact.CannotTell = g.uncertainty
	}
	for _, r := range a.Runs {
		source := runSource(r)
		a.Stages[1].Fact = Fact{Established: true, Text: "Run " + r.ID + " has a recorded run_start.", Source: source, RunID: r.ID}
		if r.Verification != Verified {
			a.Stages[1].Fact.Text = "Run " + r.ID + " recorded, not checked: " + a.VerificationReason
			a.Stages[1].Fact.CannotTell = a.VerificationReason
		}
		if (!r.UIDKnown || r.Folder == "" || len(r.Command) == 0 || first(r.Command) == "") && r.Verification == Verified {
			a.Stages[1].Fact.CannotTell = "The record does not supply the command, folder and known uid needed to relate this run to another observation."
		}
		if r.Verification != Verified {
			for i := 2; i < len(a.Stages); i++ {
				a.Stages[i].Fact.CannotTell = "Recorded, not checked: " + a.VerificationReason
			}
			continue
		}
		if !a.Stages[2].Fact.Established && r.ContractPath != "" {
			compiles, present := contracts[encode(r.ContractPath, r.ID)]
			switch {
			case !present:
				a.Stages[2].Fact.CannotTell = "The record names a contract file, but no current compile result in this run's context establishes it."
			case compiles == nil:
				a.Stages[2].Fact.CannotTell = "The current compile results for the recorded contract path and run context conflict."
			case !*compiles:
				a.Stages[2].Fact.CannotTell = "The recorded contract file does not compile now."
			default:
				a.ContractPath = r.ContractPath
				a.Stages[2].Fact = Fact{Established: true, Text: "Run " + r.ID + " names this contract file; it compiles now in that run's context.", Source: r.ContractPath, RunID: r.ID}
			}
		}
		if enforcing(r.Tier) {
			if !a.Stages[3].Fact.Established {
				a.Stages[3].Fact = Fact{Established: true, Text: "Run " + r.ID + " records enforcing tier " + r.Tier + ".", Source: source, RunID: r.ID}
			}
			if r.Ended && r.Verification == Verified && !a.Stages[4].Fact.Established {
				a.Stages[4].Fact = Fact{Established: true, Text: "Run " + r.ID + " ended at an enforcing tier and its record checks out.", Source: source, RunID: r.ID}
			}
		}
	}
	for _, s := range a.Stages {
		if s.Fact.Established {
			a.Current = s.ID
		}
	}
}

func contractChecks(contracts []Contract) map[string]*bool {
	out := make(map[string]*bool, len(contracts))
	for _, c := range contracts {
		if c.CompileRunID == "" {
			continue
		}
		key := encode(c.Path, c.CompileRunID)
		if prior, exists := out[key]; exists {
			if prior == nil || *prior != c.Compiles {
				out[key] = nil
			}
			continue
		}
		value := c.Compiles
		out[key] = &value
	}
	return out
}

func runKey(r Run) string {
	words := []string{"run", r.ID, r.Source, r.Folder, stringKey(r.UID), strconv.FormatBool(r.UIDKnown)}
	return encode(append(words, r.Command...)...)
}

func programKey(command, folder string, uid uint32, uidKnown bool) (string, bool) {
	if !uidKnown || !absolute(command) || !absolute(folder) {
		return "", false
	}
	return encode(command, folder, stringKey(uid)), true
}

func verificationReason(r Run) string {
	if r.VerificationReason != "" {
		return r.VerificationReason
	}
	switch r.Verification {
	case Verified:
		return "This run's record checks out."
	case Broken:
		return "This run's record does not check out."
	case Unchecked:
		return "This run's record has not been checked yet."
	case CannotVerify:
		return "This run's record could not be checked; inspect its record and verification anchor."
	default:
		return "This run's record has not been checked yet."
	}
}

func absolute(value string) bool {
	return strings.HasPrefix(value, "/") && path.Clean(value) == value && !strings.HasSuffix(value, " (deleted)")
}

func enforcing(tier string) bool {
	return tier == "landlock" || tier == "cgroup" || tier == "bpflsm"
}

func first(words []string) string {
	if len(words) == 0 {
		return ""
	}
	return words[0]
}

func foundSource(f Found) string {
	if f.Source != "" {
		return f.Source
	}
	return "saved scan item " + f.ID
}

func runSource(r Run) string {
	if r.Source != "" {
		return r.Source
	}
	return "run_start:" + r.ID
}

func stringKey(value uint32) string { return strconv.FormatUint(uint64(value), 10) }

// Length prefixes preserve argument boundaries, including empty words and NULs.
func encode(words ...string) string {
	var b strings.Builder
	for _, w := range words {
		b.WriteString(strconv.Itoa(len(w)))
		b.WriteByte(':')
		b.WriteString(w)
	}
	return b.String()
}
