// SPDX-License-Identifier: Apache-2.0

package guide

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/agentid"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/scan/result"
)

// ScanResult returns the checked, untrusted observation file and its read error.
// It grants no authority to launch a command or establish a run's enforcement.
func (s *ScanState) ScanResult() (result.ReadResult, error) { return s.read, s.err }

// agentRows projects the bounded snapshot checks shared by setup and Agents.
// Runs past the budget remain recorded, not checked, with a next step.
func (f *facts) agentRows() []agentid.Agent {
	var found []agentid.Found
	if scan := f.in.Scan; scan != nil {
		r, err := scan.ScanResult()
		if err == nil && r.Freshness == "fresh" && r.Snapshot.Status != "failed" {
			found = ScanAgents(r.Snapshot, uint32(f.in.UID), filepath.Join(f.in.Home, ".tego", "scan", "last.json"))
		}
	}
	var runs []agentid.Run
	if f.runs != nil {
		for _, r := range f.runs.all {
			p := r.start
			v := agentid.Unchecked
			why := "not checked yet: page verification budget reached; run tego events " + r.id + " --verify"
			if checked, ok := f.verdicts[r.id]; ok {
				switch checked.v {
				case ledger.Verified:
					v, why = agentid.Verified, ""
				case ledger.Unverified:
					v, why = agentid.Broken, "the record does not match its hashes and anchor"
				case ledger.NoVerdict:
					v, why = agentid.CannotVerify, "the record could not be checked against its anchor"
					if checked.err != nil {
						why = errText(checked.err)
					}
				default:
					v, why = agentid.CannotVerify, "the record could not be checked against its anchor"
					if checked.err != nil {
						why = errText(checked.err)
					}
				}
			}
			a := agentid.Run{ID: r.id, Command: p.Command, Folder: p.Cwd, Source: r.dir, Tier: p.Tier,
				Ended: r.state == ledger.StateEnded, Verification: v, VerificationReason: why}
			if p.LauncherUID != nil {
				a.UID, a.UIDKnown = *p.LauncherUID, true
			}
			if p.ContractSource != nil {
				a.ContractPath = p.ContractSource.Path
			}
			// Run ids order records; no scan time is substituted for a missing start.
			a.Started = r.started
			if len(p.Command) > 0 {
				a.Name = p.Command[0]
			}
			runs = append(runs, a)
		}
	}
	var contracts []agentid.Contract
	if f.contracts != nil {
		for _, c := range f.contracts.all {
			why := ""
			if c.err != nil {
				why = "the contract could not be compiled now"
			}
			runID := ""
			if c.linked != nil {
				runID = c.linked.id
			}
			contracts = append(contracts, agentid.Contract{Path: c.path, CompileRunID: runID, Compiles: c.err == nil, Reason: why})
		}
	}
	return agentid.Resolve(found, runs, contracts)
}

// ScanAgents projects scan evidence without inferring a working folder from a
// program or settings path. Only own-uid process and program observations count
// as found. Settings, declarations and configured services remain separate.
func ScanAgents(s result.Snapshot, uid uint32, source string) []agentid.Found {
	if s.As.Recipient != uid || s.Status == "failed" {
		return nil
	}
	var out []agentid.Found
	for _, i := range s.Items {
		if slices.Contains(i.Caveats, "historical") {
			continue
		}
		a := agentid.Found{ID: i.ID, Name: i.Name, UID: uid, UIDKnown: true, Source: source, SeenAt: s.Finished}
		facts := make([]string, 0, len(i.Evidence))
		for _, e := range i.Evidence {
			facts = append(facts, e.RuleID+": "+e.Fact+" ("+e.SourceID+")")
		}
		a.IdentityUnknown = slices.Contains(i.Caveats, "identity-unknown")
		a.Fact = "reported by scan at " + s.Finished.Format(time.RFC3339) + ": " + strings.Join(facts, ", ") + "; any program running as you can change it"
		if len(i.Caveats) > 0 {
			a.Fact += "; caveats: " + strings.Join(i.Caveats, ", ")
		}
		switch i.Kind {
		case "process":
			p := i.Process()
			if p.UID != uid || p.Membership == "in-run" {
				continue
			}
			if p.Exe != nil {
				a.Command = *p.Exe
			}
			if p.Cwd != nil {
				a.Folder = *p.Cwd
			}
			a.Fact += fmt.Sprintf("; pid %d", p.PID)
		case "program":
			if s.As.Recipient != uid {
				continue
			}
			if p := i.File().Path; p != nil {
				a.Command = *p
			}
			a.Fact += "; installed candidate only; working folder unknown"
		default:
			continue
		}
		out = append(out, a)
	}
	return out
}
