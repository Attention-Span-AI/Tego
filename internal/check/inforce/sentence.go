// SPDX-License-Identifier: Apache-2.0

package inforce

import (
	"path"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/internal/check/livestatus"
)

// The copy. Sentences have no subject (the page's heading names the agent), say what happens in everyday words, and
// name no engine part: a reader who has never seen a contract should understand each line.

// groupCopy is each group's heading and lede.
var groupCopy = map[string][2]string{
	GroupRead:        {"Can read", "Files the agent can open and read."},
	GroupChange:      {"Can change", "Files and folders the agent can create, edit or delete."},
	GroupAsk:         {"Asks you first", "The agent waits until you answer on the dashboard."},
	GroupNeverRead:   {"Never reads", "Files the agent can never open, whatever it tries."},
	GroupNeverChange: {"Never changes", "Files the agent can never edit or delete, even inside a folder it can change."},
	GroupPrograms:    {"Programs", "The programs the agent can start."},
	GroupNetwork:     {"Network", "Where the agent can connect."},
	GroupEnv:         {"Settings it gets", "Environment variables the agent starts with, by name. Values are never shown here."},
	GroupLimits:      {"Limits", "When the run is stopped or slowed down."},
	GroupLive:        {"Blocked live now", "Blocks you added while the agent runs. They end with the run."},
	GroupAlwaysOn:    {"Always on", "Protections every run gets, written in no rules file."},
}

// How a rule is enforced, or why not in full.
const (
	textKernel       = "Enforced by the operating system"
	textTegoConnect  = "Enforced: tego checks each connection"
	textTegoRead     = "Enforced: tego checks each read"
	textHeld         = "Enforced: tego holds the action until you answer"
	textBestEffort   = "Best effort: tego refuses it, but a program built to race tego could get past"
	textShadowed     = "Not enforced for this run: it lies inside a folder the agent can change"
	textObserve      = "Not enforced: this run only watches"
	textAskReadTier  = "Refused without asking: this run cannot pause a read to ask you"
	textEnvRemoved   = "Enforced: other variables are removed before the agent starts"
	textLive         = "Refused by tego until the run ends"
	textTegoCommands = "Best effort: tego checks the words of each command it starts"

	textExecAskReserved     = "Always refused: asking before a program runs is not supported yet"
	textExecAskReservedBest = "Always refused, best effort: asking before a program runs is not supported yet, and tego checks the words of each command it starts"
)

// liveGroupCopy is the live group's heading, lede and footer for its rules' states: "Blocked live now" while at
// least one block refuses something, "Marked live now" when every block is a mark on a watched run, which records
// and refuses nothing, "Live blocks, none refusing now" when every block is unblocked for a while or past its time
// limit, and "Blocking live" when the blocks wait for the run to put them in force. The heading never claims more
// than its rows do.
func liveGroupCopy(rules []Rule) (title, lede, foot string) {
	refuses, marks, waits := false, true, false
	for _, r := range rules {
		if r.Live.Refuses() {
			refuses = true
		}
		if r.Live == livestatus.Waiting {
			waits = true
		}
		if r.Live != livestatus.RecordedOnly {
			marks = false
		}
	}
	switch {
	case refuses:
		c := groupCopy[GroupLive]
		return c[0], c[1], "A live block refuses more than the rules file, never less, and ends with the run. Removing one gives back only what it took."
	case marks:
		return "Marked live now", "Marks you added while the agent is watched. They record what matches and refuse nothing. They end with the run.",
			"A mark refuses nothing: it records what matches and ends with the run. Removing one stops the recording."
	case !waits:
		// Every block is unblocked for a while or past its time limit (ADR 0125 decision 4): none refuses now.
		return "Live blocks, none refusing now", "Blocks you added while the agent runs. Each is unblocked for a while or past its time limit, so none refuses anything now.",
			"A block unblocked for a while refuses again at its time limit; one past its limit refuses nothing and leaves the run's list."
	}
	return "Blocking live", "Blocks you added while the agent runs. The run puts each one in force in about a second. They end with the run.",
		"A block refuses nothing until the run puts it in force. From then on it refuses more than the rules file, never less, and ends with the run."
}

// isDir reports whether a declared path names a folder: contract paths end a directory in "/".
func isDir(entry string) bool { return strings.HasSuffix(entry, "/") }

// isGlob reports whether a declared path is a pattern.
func isGlob(entry string) bool { return strings.ContainsAny(entry, "*?[") }

// short is a path for display: the home directory as ~, everything else as written.
func short(p, home string) string {
	if home != "" && home != "/" {
		if p == home {
			return "~"
		}
		if rest, ok := strings.CutPrefix(p, home+"/"); ok {
			return "~/" + rest
		}
	}
	return p
}

// pathSentence says a path rule: verb is what the rule lets or refuses ("Can change", "Can never read",
// "Asks you before it reads").
func pathSentence(verb, entry, home string) (sentence, target string) {
	target = short(entry, home)
	switch {
	case isGlob(entry):
		return verb + " files matching " + target, target
	case isDir(entry):
		return verb + " files in " + target, target
	}
	return verb + " " + target, target
}

// programSentence says an exec rule. A program given by its full path is said by its name ("Can run python3.12");
// the full path stays in the target, which the page shows as the title.
func programSentence(verb, entry, home string) (sentence, target string) {
	target = short(entry, home)
	if isDir(entry) {
		return verb + " programs in " + target, target
	}
	name := target
	if first, rest, words := strings.Cut(strings.TrimSpace(entry), " "); strings.Contains(first, "/") && !isGlob(first) {
		name = path.Base(first)
		if words {
			name += " " + rest
		}
	}
	return verb + " " + name, target
}

// netTarget says a net entry as a place: "chatgpt.com on port 443", "the local socket /run/x.sock".
func netTarget(entry string) string {
	if p, ok := strings.CutPrefix(entry, "unix:"); ok {
		if strings.HasPrefix(p, "@") {
			return "the local socket named " + p
		}
		return "the local socket " + p
	}
	udp := false
	e := entry
	if r, ok := strings.CutPrefix(e, "udp://"); ok {
		e, udp = r, true
	} else if r, ok := strings.CutPrefix(e, "tcp://"); ok {
		e = r
	}
	suffix := ""
	if udp {
		suffix = " (UDP)"
	}
	if strings.Contains(e, "/") {
		return "addresses in " + e + suffix
	}
	host, port := splitHostPort(e)
	if port == "" {
		return host + " on any port" + suffix
	}
	return host + " on port " + port + suffix
}

// splitHostPort splits host:port, [v6]:port and a bare v6 address; port is "" when there is none.
func splitHostPort(e string) (host, port string) {
	if strings.HasPrefix(e, "[") {
		if i := strings.Index(e, "]"); i > 0 {
			host = e[1:i]
			if p, ok := strings.CutPrefix(e[i+1:], ":"); ok {
				port = p
			}
			return host, port
		}
	}
	if strings.Count(e, ":") == 1 {
		i := strings.LastIndex(e, ":")
		if _, err := strconv.Atoi(e[i+1:]); err == nil {
			return e[:i], e[i+1:]
		}
	}
	return e, ""
}

// limitSentence says one limits key.
func limitSentence(key, value string) string {
	switch key {
	case "wall":
		return "Is stopped after " + human(value)
	case "tokens":
		return "Is stopped after " + value + " model tokens"
	case "cost_usd":
		return "Is stopped after $" + value + " of model use"
	case "memory":
		return "Can use at most " + human(value) + " of memory"
	case "memory_high":
		return "Is slowed down above " + human(value) + " of memory"
	case "pids":
		return "Can run at most " + value + " processes at once"
	case "cpu":
		return "Can use at most " + value + " CPU cores"
	case "cpu_weight":
		return "Gets a CPU share of " + value + " (100 is normal)"
	case "stall_after":
		return "Is stopped when nothing happens for " + human(value)
	case "repeats":
		return "Is stopped when it repeats the same step " + value + " times in a row"
	}
	return key + ": " + value
}

// human says a duration or a size the way people do: 2h as "2 hours", 4GiB as "4 GiB". A value it does not know
// stays as written.
func human(v string) string {
	for _, u := range []struct{ suffix, one, many string }{
		{"ms", "millisecond", "milliseconds"}, {"d", "day", "days"}, {"h", "hour", "hours"},
		{"m", "minute", "minutes"}, {"s", "second", "seconds"},
	} {
		if n, ok := strings.CutSuffix(v, u.suffix); ok {
			if _, err := strconv.Atoi(n); err == nil {
				if n == "1" {
					return n + " " + u.one
				}
				return n + " " + u.many
			}
		}
	}
	for _, u := range []string{"TiB", "GiB", "MiB", "KiB", "TB", "GB", "MB", "KB", "B"} {
		if n, ok := strings.CutSuffix(v, u); ok {
			if _, err := strconv.Atoi(n); err == nil {
				return n + " " + u
			}
		}
	}
	return v
}

// liveSentence says a live block.
func liveSentence(kind, value string) string {
	switch kind {
	case "exec":
		if isDir(value) {
			return "Blocked now: cannot run programs in " + value
		}
		return "Blocked now: cannot run " + value
	case "net":
		return "Blocked now: cannot connect to " + liveNetTarget(value)
	case "path":
		return "Blocked now: cannot open or change " + value
	case "read":
		return "Blocked now: cannot read " + value
	case "write":
		return "Blocked now: cannot change " + value + " (reads still go through)"
	}
	return "Blocked now: " + kind + " " + value
}

// liveSentenceIn says a live block in its state now (livestatus): "Blocked now" only while it refuses, "Marked now"
// on a watched run, which records what it names and refuses nothing, and a path block that refuses changes only says
// so.
func liveSentenceIn(kind, value string, state livestatus.State) string {
	s := liveSentence(kind, value)
	switch state {
	case livestatus.RecordedOnly:
		return "Marked now (recorded, not refused): " + strings.TrimPrefix(s, "Blocked now: ")
	case livestatus.Waiting:
		return "Blocking: " + strings.TrimPrefix(s, "Blocked now: ")
	case livestatus.Ended:
		return "Was blocked: " + strings.TrimPrefix(s, "Blocked now: ")
	case livestatus.Dormant:
		return "Unblocked for a while (refuses nothing until its time limit): " + strings.TrimPrefix(s, "Blocked now: ")
	case livestatus.Expired:
		return "Ended by its time limit: " + strings.TrimPrefix(s, "Blocked now: ")
	case livestatus.Partial:
		if kind == "path" {
			return "Blocked now: cannot change " + value + " (reads still go through)"
		}
	case livestatus.InForce:
	}
	return s
}

// liveNetTarget is a live net block's value as a place; it has no scheme, and no port means every port.
func liveNetTarget(v string) string {
	if strings.HasPrefix(v, "/") || strings.HasPrefix(v, "@") {
		return netTarget("unix:" + v)
	}
	return netTarget(v)
}
