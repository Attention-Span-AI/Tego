// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"os"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/linewords"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The words the dashboard uses for a held request and for the person who acted on one, in one place so the ask
// banner, the Approvals card, the run page and the line an answer leaves all say the same thing.

// askVerb is what an ask asks to do, as a verb phrase: "read", "write to", "connect to". A held file open is a write
// under fs.ask (write-only, SEMANTICS §6) and a read under fs.ask_read; hold names a request whose ask line carries
// no operation.
func askVerb(op, rule, hold string) string {
	switch op {
	case "read":
		return "read"
	case "write", "create", "truncate", "append":
		return "write to"
	case "open":
		switch {
		case strings.HasPrefix(rule, "fs.ask_read["):
			return "read"
		case strings.HasPrefix(rule, "fs.ask["):
			return "write to"
		}
		return "open"
	case "connect":
		return "connect to"
	case "send", "first_write":
		return "send data to"
	case "request":
		return "send a request to"
	case "exec":
		return "run"
	case "mcp_tool":
		// A tools/call Tego's MCP relay holds (ADR 0126 §4); its target is "<server> <tool>".
		return "call the MCP tool"
	case "":
		if hold != "" {
			return "go on with a held " + hold
		}
		return "go on"
	}
	return op
}

// askNoun is askVerb as a noun phrase, for "Denied: read of ~/.ssh/id_rsa".
func askNoun(op, rule, hold string) string {
	switch v := askVerb(op, rule, hold); v {
	case "read":
		return "read of"
	case "write to":
		return "write to"
	case "open":
		return "open of"
	case "connect to":
		return "connection to"
	case "send data to":
		return "data sent to"
	case "send a request to":
		return "request to"
	case "run":
		return "running"
	case "call the MCP tool":
		return "call of the MCP tool"
	default:
		return v
	}
}

var homeDir = sync.OnceValue(func() string {
	h, err := os.UserHomeDir()
	if err != nil || h == "/" {
		return ""
	}
	return strings.TrimSuffix(h, "/")
})

// tilde shortens a path under the dashboard user's home to ~/…, as a person reads it.
func tilde(p string) string {
	if h := homeDir(); h != "" && strings.HasPrefix(p, h+"/") {
		return "~" + p[len(h):]
	}
	return p
}

var (
	userMu    sync.Mutex
	userNames = map[string]string{}
)

// userName is the login name of uid, or "" when the machine does not know it. Lookups are kept: the same few uids
// answer every request.
func userName(uid string) string {
	userMu.Lock()
	defer userMu.Unlock()
	if n, ok := userNames[uid]; ok {
		return n
	}
	n := ""
	if u, err := user.LookupId(uid); err == nil {
		n = u.Username
	}
	userNames[uid] = n
	return n
}

// who is a ledger principal in words. The ledger names the person who answered, stopped or blocked as
// "uid:1000 pid:1754516", optionally followed by where they acted ("dashboard") or " always"; a person reads
// "somebody, from the dashboard". A standing answer ("standing:q-…") was given by an earlier answer, and a principal
// with no uid is shown as written.
func who(by string) string {
	if by == "" {
		return ""
	}
	if strings.HasPrefix(by, "standing:") {
		return "an earlier answer for the rest of this run"
	}
	f := strings.Fields(by)
	name, rest := "", []string{}
	for _, w := range f {
		switch {
		case strings.HasPrefix(w, "uid:"):
			uid := strings.TrimPrefix(w, "uid:")
			if _, err := strconv.Atoi(uid); err == nil {
				if name = userName(uid); name == "" {
					name = "user " + uid
				}
			}
		case strings.HasPrefix(w, "pid:"), w == "always":
		default:
			rest = append(rest, w)
		}
	}
	if name == "" {
		return by
	}
	switch strings.Join(rest, " ") {
	case "":
		return name
	case "dashboard":
		return name + ", from the dashboard"
	case "cli", "terminal":
		return name + ", from a terminal"
	default:
		return name + " (" + strings.Join(rest, " ") + ")"
	}
}

// askObject is what an ask is about, for the card's question "Let codex read this file?".
func askObject(op, rule, hold string) string {
	switch {
	case strings.HasPrefix(rule, "fs.") || op == "read" || op == "write" || op == "open" || op == "create":
		return "this file"
	case op == "exec":
		return "this program"
	case op == "mcp_tool":
		return "named below"
	case op == "connect" || op == "send" || op == "first_write" || op == "request" || hold == "connect" || hold == "net":
		return "this address"
	}
	return "this"
}

// answered is one answer line as Approvals lists it under "Answered recently".
type answered struct {
	Run, Agent, AskID string
	Op, Rule, Target  string
	// Word is what became of the request ("allowed once by somebody after 4 s"), Approved whether it went through.
	Word     string
	Approved bool
	// TimedOut is a request nobody answered in time (answer_reason ask-timeout): Tego refused it, no person denied
	// it, so its chip reads "Timed out", not "Denied".
	TimedOut bool
	// Withdrawn is a request the broker took back because a live block landed while the person was deciding
	// (linewords.WithdrawnBy): no person denied it, so its chip reads "Withdrawn", not "Denied".
	Withdrawn bool
	TS        time.Time
}

// answersOf is the newest n answers people gave, newest first. An answer line repeats the ask's operation, target
// and rule, so each row says what was asked without reading the ask.
func answersOf(snap *ledgerview.Snapshot, n int) []answered {
	var out []answered
	for _, r := range snap.Runs {
		if r.Kinds["answer"] == 0 {
			continue // the summary says it has none: its lines are not read (the read model may have let them go)
		}
		evs := r.AllEvents()
		for i := range evs {
			e := &evs[i]
			if e.Kind != "answer" {
				continue
			}
			var p struct {
				Approved *bool   `json:"approved"`
				By       string  `json:"by"`
				After    float64 `json:"after_s"`
				Reason   string  `json:"answer_reason"`
				Op       string  `json:"op"`
				Target   string  `json:"target"`
				Rule     string  `json:"ask_rule"`
			}
			// A standing answer is Tego repeating a person's "for this run" answer: the person's own is listed.
			if json.Unmarshal([]byte(e.Raw), &p) != nil || p.Approved == nil || strings.HasPrefix(p.By, "standing:") {
				continue
			}
			out = append(out, answered{Run: r.ID, Agent: r.Agent, AskID: e.AskID, Op: p.Op, Rule: p.Rule, Target: p.Target,
				Word: answerPhrase(*p.Approved, p.Reason, p.By, p.After), Approved: *p.Approved,
				TimedOut:  !*p.Approved && p.Reason == string(record.ReasonAskTimeout),
				Withdrawn: !*p.Approved && p.By == linewords.WithdrawnBy, TS: e.TS})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TS.After(out[j].TS) })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// hlAsks is the run page's Highlights Approvals card cut for reading: Head is the asks a person answers or answered
// (a waiting one first), up to n; More the rest of those; Repeats the asks Tego answered at once from a person's
// earlier "for this run" answer, which a long run repeats hundreds of times and the card folds under one line.
type hlAsks struct {
	Head, More, Repeats []ledgerview.Approval
}

// splitAsks cuts apps (in ledger order) into hlAsks.
func splitAsks(apps []ledgerview.Approval, n int) hlAsks {
	var out hlAsks
	var people []ledgerview.Approval
	for _, a := range apps {
		switch {
		case a.State == "pending":
			people = append([]ledgerview.Approval{a}, people...)
		case strings.HasPrefix(a.By, "standing:"):
			out.Repeats = append(out.Repeats, a)
		default:
			people = append(people, a)
		}
	}
	if len(people) > n {
		out.Head, out.More = people[:n], people[n:]
	} else {
		out.Head = people
	}
	return out
}

// harnessWait is how long an agent's own client waits on a held request before it gives up: Codex's, about 30 s.
// Other agents' limits are not known here; past the same 30 s the card stops saying they may still be waiting.
const harnessWait = 30 * time.Second

// askMeta is what the banner, Overview's Waiting on you and the ask card know about a waiting request's run: its
// harness (whose wait the note names), its home (a path reads ~/.config/telemetry/token, as Highlights shows it)
// and how long Tego holds the request before it refuses it (the run's ask.timeout; 0 when its copy was not read).
type askMeta struct {
	Harness, Home string
	// Cwd is the run's working directory: a file of the project reads ./confidential/plan.md.
	Cwd     string
	Timeout time.Duration
}

// askMetas is the askMeta of each run that has one of asks waiting.
func (s *Server) askMetas(snap *ledgerview.Snapshot, asks []ledgerview.Ask) map[string]askMeta {
	out := make(map[string]askMeta, len(asks))
	for _, a := range asks {
		if _, ok := out[a.Run]; ok {
			continue
		}
		m := askMeta{Timeout: rulesview.RunLists(s.cfg.Ledger, a.Run).AskTimeout}
		if r := snap.Find(a.Run); r != nil {
			m.Harness, m.Home, m.Cwd = r.Harness, ledgerview.RunHome(r), r.Cwd
		}
		out[a.Run] = m
	}
	return out
}

// metaOf is the card's run argument: an askMeta, or a bare harness name (a caller that knows only that).
func metaOf(v any) askMeta {
	switch m := v.(type) {
	case askMeta:
		return m
	case string:
		return askMeta{Harness: m}
	}
	return askMeta{}
}

// askWait is the note on how long a waiting request is held, as of the page's time. While the agent's own client
// may still wait (harnessWait after the ask) Text is giveUp's and Late the words live.js puts in its place at LateAt;
// past it Text is those words already and Late is "".
type askWait struct {
	Text, Late string
	LateAt     time.Time
}

// waitOf is the askWait of a request asked at asked, read at now.
func waitOf(m askMeta, asked, now time.Time) askWait {
	late := lateWords(m)
	at := asked.Add(harnessWait)
	if !now.Before(at) {
		return askWait{Text: late}
	}
	return askWait{Text: giveUp(m.Harness), Late: late, LateAt: at}
}

// lateWords is the note once the agent has likely stopped waiting: "Codex has likely given up; Tego refuses it at
// 5 m". Before it, the card said "Codex gives up at about 30 s" minutes after the fact.
func lateWords(m askMeta) string {
	refuses := "Tego refuses it when its time runs out"
	if m.Timeout > 0 {
		refuses = "Tego refuses it at " + minutes(m.Timeout)
	}
	if m.Harness == "codex" {
		return "Codex has likely given up; " + refuses
	}
	return "some agents give up after about 30 s; " + refuses
}

// minutes is a timeout as a person reads it: "5 m" for whole minutes, human's form otherwise.
func minutes(d time.Duration) string {
	if d >= time.Minute && d%time.Minute == 0 {
		return strconv.Itoa(int(d/time.Minute)) + " m"
	}
	return human(d)
}
