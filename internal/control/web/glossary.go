// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"slices"
	"strings"
)

// glossaryTerm is one word the dashboard uses, what it means, and the page that shows it ("" for none). Was is the
// anchor the term had under its older word ("policy", "blocked"), kept so an old /glossary#<word> link still lands on
// it.
type glossaryTerm struct {
	ID, Term, Means, Where string
	Was                    string
}

// layerTerm is a word a layer adds to the Glossary: it stands after the core term whose ID is After (at the end when no
// core term has it).
type layerTerm struct {
	After string
	Term  glossaryTerm
}

// glossaryTerms are the dashboard's words, one per idea, in the order a person meets them. A layer's words are not here:
// a build without the layer says nothing of its pages (allGlossaryTerms).
var glossaryTerms = []glossaryTerm{
	{"basic", "Basic protection", "File and program restrictions without administrator rights. Tego's supervisor checks connections; network checks may be best effort.", "/machine", ""},
	{"watched", "Watched run", "Tego records actions and refuses nothing.", "/runs", ""},
	{"passed-through", "Passed through", "The action happened without a refusal verdict. It does not mean the action was safe.", "/logs", ""},
	{"fence", "Live fence", "Access listed before an Adjustable run starts. Tego's live layer refuses it until a person grants or lifts it. A time limit stops new access only.", "/rules", ""},
	{"mcp", "MCP tools", "Tools an agent calls through a server. Tego's relay can decide each call when the contract declares tool rules.", "/mcp", ""},
	{"model-route", "Model route", "Where a model request is sent. A reroute sends the request and its headers to a backend named in the contract.", "/routes", ""},
	{"agent", "Agent", "Any program Tego governs: an AI agent of any kind, a script, any command. Tego does not make agents.", "/runs", ""},
	{"contract", "Contract", "What an agent may read, change, run and connect to: one file, reused across runs, the file tego run takes.", "/rules", "policy"},
	{"preset", "Preset", "A ready-made part of a contract you tick, such as Keep secrets out. Change it anytime.", "/rules/new", ""},
	{"run", "Run", "One session of an agent under tego, from start to exit.", "/runs", ""},
	{"project", "Project", "The folder a run works in.", "", ""},
	{"channel", "Channel", "What an action touches: Files, Programs or Network.", "/detections", ""},
	{"refused", "Refused", "Tego stopped the action. The agent got an error and kept working. The record, the receipt and tego run's summary say refused too. This dashboard said blocked before.", "/detections", "blocked"},
	{"ask-first", "Ask first", "The action waits until a person allows or denies it.", "/approvals", ""},
	{"detection", "Detection", "A refused action worth a look, with its severity. Secrets that left come first.", "/detections", ""},
	{"severity", "Severity", "High, Medium or Low, from where the action happened and what it was. Never from how often.", "/detections", ""},
	{"high", "High", "A secret, a connection the contract does not allow, a program that reaches out, or a change to a file that runs code later: a startup file, or an agent's settings.", "/detections?sev=high", ""},
	{"medium", "Medium", "Another program, a change outside the project or in an agent's folder, or another agent's files.", "/detections?sev=medium", ""},
	{"low", "Low", "The agent reading its own files or writing its own caches, and system information.", "/detections?sev=low", ""},
	{"routine", "Routine", "System lookups and probes every program makes. Counted, never listed.", "/logs?verdict=refused", ""},
	{"investigate", "Investigate", "One detection in four parts: what, how it got there, what else, what now.", "", ""},
	{"protection", "Protection level", "How strongly this machine enforces: Basic (no admin rights), Plus or Max (root). The terminal, the docs and contract files call these tier 1 (landlock), tier 2 (cgroup) and tier 3 (bpflsm).", "/machine", ""},
	{"record", "Record", "The actions Tego saw in each run, checked against saved hashes and an anchor. This detects changes by the agent; it does not stop the machine owner rewriting the record and its anchor. A gap says where it may have missed some.", "/logs", ""},
	{"verified", "Verified", "The saved record matches its hashes and anchor. This says nothing about whether the actions were safe. It does not say the record is whole: a run whose supervisor died may have lost its last lines, and shows a gap. Not anchored means the run did not end, so its last lines have nothing to check against.", "", ""},
	{"receipt", "Receipt", "One run on one screen: time, files written, what was refused and asked.", "", ""},
}

// allGlossaryTerms are the core's words and each layer's, a layer's after the core term it names.
func allGlossaryTerms() []glossaryTerm {
	out := slices.Clone(glossaryTerms)
	for _, l := range layers {
		for _, lt := range l.Glossary {
			at := slices.IndexFunc(out, func(t glossaryTerm) bool { return t.ID == lt.After })
			if at < 0 {
				out = append(out, lt.Term)
				continue
			}
			out = slices.Insert(out, at+1, lt.Term)
		}
	}
	return out
}

// glossary answers /glossary.
func (s *Server) glossary(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.load(w)
	if !ok {
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	all := allGlossaryTerms()
	terms := all
	if q != "" {
		terms = nil
		for _, term := range all {
			if strings.Contains(strings.ToLower(term.Term+" "+term.Means), strings.ToLower(q)) {
				terms = append(terms, term)
			}
		}
	}
	s.render(w, http.StatusOK, "glossary", s.chromeOf(snap, "Glossary", ""), struct {
		Terms []glossaryTerm
		Query string
	}{terms, q})
}

// more is the phone shell's native destination for secondary navigation and theme.
func (s *Server) more(w http.ResponseWriter, _ *http.Request) {
	snap, ok := s.load(w)
	if !ok {
		return
	}
	s.render(w, http.StatusOK, "more", s.chromeOf(snap, "More", "more"), nil)
}
