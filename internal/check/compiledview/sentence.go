// SPDX-License-Identifier: Apache-2.0

package compiledview

import (
	"path"
	"strconv"
	"strings"
)

// The copy. Sentences have no subject (the page's heading names the agent), say what happens in everyday words, and
// name no engine part: a reader who has never seen a contract should understand each line.

// GroupCopy is each group's heading and lede.
var GroupCopy = map[string][2]string{
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
	TextKernel       = "Enforced by the operating system"
	TextTegoConnect  = "Enforced: tego checks each connection"
	TextTegoRequest  = "Enforced: tego checks each request before it leaves"
	TextGate         = "Enforced: tego scores each action before it happens"
	TextTegoRead     = "Enforced: tego checks each read"
	TextHeld         = "Enforced: tego holds the action until you answer"
	TextBestEffort   = "Best effort: tego refuses it, but a program built to race tego could get past"
	TextHeldBest     = "Best effort: tego holds the action until you answer, but a program built to race tego could get past"
	TextShadowed     = "Not enforced for this run: it lies inside a folder the agent can change"
	TextObserve      = "Not enforced: this run only watches"
	TextAskReadTier  = "Refused without asking: this run cannot pause a read to ask you"
	TextEnvRemoved   = "Enforced: other variables are removed before the agent starts"
	TextLive         = "Refused by tego until the run ends"
	TextTegoCommands = "Best effort: tego checks the words of each command it starts"
	TextDatagram     = "Best effort: tego checks each datagram's address, but sends one it allows by the agent's own call, which a program built to race tego could redirect"
	// TextDatagramRoot is the root tier's residual: its kernel program for a unix datagram's name needs Linux 6.7 or
	// later, and no decision plane decides this run (ADR 0113).
	TextDatagramRoot = "Best effort below Linux 6.7: the kernel checks a unix datagram's address only from 6.7, or where a decision plane runs, and below that tego checks a copy of it, which a program built to race tego could redirect"

	TextExecAskReserved     = "Always refused: asking before a program runs is not supported yet"
	TextExecAskReservedBest = "Always refused, best effort: asking before a program runs is not supported yet, and tego checks the words of each command it starts"
)

// IsDir reports whether a declared path names a folder: contract paths end a directory in "/".
func IsDir(entry string) bool { return strings.HasSuffix(entry, "/") }

// isGlob reports whether a declared path is a pattern.
func isGlob(entry string) bool { return strings.ContainsAny(entry, "*?[") }

// Short is a path for display: the home directory as ~, everything else as written.
func Short(p, home string) string {
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

// PathSentence says a path rule: verb is what the rule lets or refuses ("Can change", "Can never read",
// "Asks you before it reads").
func PathSentence(verb, entry, home string) (sentence, target string) {
	target = Short(entry, home)
	switch {
	case isGlob(entry):
		return verb + " files matching " + target, target
	case IsDir(entry):
		return verb + " files in " + target, target
	}
	return verb + " " + target, target
}

// ProgramSentence says an exec rule. A program given by its full path is said by its name ("Can run python3.12");
// the full path stays in the target, which the page shows as the title. The entry's words are read as compile reads
// them (withWords): a quoted path with a space is one word ('/opt/My Tools/run' says "Can run run"), and a tab
// separates words as a space does.
func ProgramSentence(verb, entry, home string) (sentence, target string) {
	target = Short(entry, home)
	if !withWords(entry) {
		w := programWord(entry)
		switch {
		case IsDir(w):
			return verb + " programs in " + Short(w, home), target
		case strings.Contains(w, "/") && !isGlob(w):
			return verb + " " + path.Base(w), target
		}
		return verb + " " + Short(w, home), target
	}
	name := target
	trimmed := strings.TrimSpace(entry)
	if i := strings.IndexAny(trimmed, " \t"); i > 0 {
		if first := trimmed[:i]; strings.Contains(first, "/") && !isGlob(first) {
			name = path.Base(first) + " " + strings.TrimLeft(trimmed[i:], " \t")
		}
	}
	return verb + " " + name, target
}

// NetTarget says a net entry as a place: "chatgpt.com on port 443", "the local socket /run/x.sock".
func NetTarget(entry string) string {
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

// LimitSentence says one limits key.
func LimitSentence(key, value string) string {
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

// limitAmount says one limits key's value as an amount, for a sentence that names two of them: "2 hours", "4 GiB",
// "$5", "5000 model tokens".
func limitAmount(key, value string) string {
	switch key {
	case "wall", "stall_after", "memory", "memory_high":
		return human(value)
	case "tokens":
		return value + " model tokens"
	case "cost_usd":
		return "$" + value
	case "pids":
		return value + " processes"
	case "cpu":
		return value + " CPU cores"
	case "cpu_weight":
		return "a CPU share of " + value
	case "repeats":
		return value + " repeats"
	}
	return value
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
