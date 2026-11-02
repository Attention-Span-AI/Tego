// SPDX-License-Identifier: Apache-2.0

package web

import "net/http"

// glossaryTerm is one word the dashboard uses, what it means, and the page that shows it ("" for none).
type glossaryTerm struct {
	ID, Term, Means, Where string
}

// glossaryTerms are the dashboard's words, one per idea, in the order a person meets them.
var glossaryTerms = []glossaryTerm{
	{"agent", "Agent", "The program tego governs: Claude Code, Codex or any command. tego does not make agents.", "/runs"},
	{"policy", "Policy", "What an agent may read, change, run and connect to. One file, reused across runs.", "/rules"},
	{"preset", "Preset", "A ready-made part of a policy you tick, such as Keep secrets out. Change it anytime.", "/rules/new"},
	{"run", "Run", "One session of an agent under tego, from start to exit.", "/runs"},
	{"project", "Project", "The folder a run works in.", ""},
	{"channel", "Channel", "What an action touches: Files, Programs or Network.", "/detections"},
	{"blocked", "Blocked", "tego stopped the action. The agent got an error and kept working.", "/detections"},
	{"ask-first", "Ask first", "The action waits until a person allows or denies it.", "/approvals"},
	{"detection", "Detection", "A blocked action worth a look, with its severity. Secrets that left come first.", "/detections"},
	{"severity", "Severity", "High, Medium or Low, from where the action happened and what it was. Never from how often.", "/detections"},
	{"high", "High", "A secret, a connection the policy does not allow, a program that reaches out, or a change to a file that runs code later: a startup file, or an agent's settings.", "/detections?sev=high"},
	{"medium", "Medium", "Another program, a change outside the project or in an agent's folder, or another agent's files.", "/detections?sev=medium"},
	{"low", "Low", "The agent reading its own files or writing its own caches, and system information.", "/detections?sev=low"},
	{"routine", "Routine", "System lookups and probes every program makes. Counted, never listed.", "/logs?verdict=refused"},
	{"investigate", "Investigate", "One detection in four parts: what, how it got there, what else, what now.", ""},
	{"protection", "Protection level", "How strongly this machine enforces: Basic (no admin rights), Strong or Strongest (root). The terminal, the docs and policy files call these tier 1 (landlock), tier 2 (cgroup) and tier 3 (bpflsm).", "/machine"},
	{"record", "Record", "The actions Tego saw in each run, written so that any edit shows. A gap says where it may have missed some.", "/logs"},
	{"verified", "Verified", "The record checks out: no line changed after it was written. It does not say the record is whole: a run whose supervisor died may have lost its last lines, and shows a gap. Not anchored means the run did not end, so its last lines have nothing to check against.", ""},
	{"receipt", "Receipt", "One run on one screen: time, files changed, what was blocked and asked.", ""},
}

// glossary answers /glossary.
func (s *Server) glossary(w http.ResponseWriter, _ *http.Request) {
	snap, ok := s.load(w)
	if !ok {
		return
	}
	s.render(w, http.StatusOK, "glossary", s.chromeOf(snap, "Glossary", ""), glossaryTerms)
}
