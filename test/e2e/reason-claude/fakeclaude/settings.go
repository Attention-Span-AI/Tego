// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// DocsVersion is the Claude Code release whose documentation this program is dated against (hooks reference, CLI
// reference and headless page as read on 2026-10-24). A payload or exit-code rule that changes in a later release is
// a change here, with its golden, and nowhere else.
const DocsVersion = "2.1.310"

// MaxSettingsBytes is the CLI reference's limit for a --settings file: "a regular file no larger than 2 MiB".
const MaxSettingsBytes = 2 << 20

// DefaultHookTimeout is the command hook's default when a hook sets none (hooks reference: 600 seconds).
const DefaultHookTimeout = 600

// The events fakeclaude fires. Settings may register others (PreToolUse and the rest are real events); they are
// accepted, reported on stderr as never fired, and not run.
const (
	EvSessionStart       = "SessionStart"
	EvPostToolUse        = "PostToolUse"
	EvPostToolUseFailure = "PostToolUseFailure"
	EvPostToolBatch      = "PostToolBatch"
	EvStop               = "Stop"
)

var modeledEvents = map[string]bool{
	EvSessionStart: true, EvPostToolUse: true, EvPostToolUseFailure: true, EvPostToolBatch: true, EvStop: true,
}

// Settings is the part of a Claude Code settings file that fakeclaude reads: the hooks.
type Settings struct {
	DisableAllHooks bool                   `json:"disableAllHooks"`
	Hooks           map[string][]HookGroup `json:"hooks"`
	// Warnings are things the file asks for that fakeclaude does not do, one line each, for stderr.
	Warnings []string `json:"-"`
}

// A HookGroup is one entry of an event's array: a matcher and the hooks it selects.
type HookGroup struct {
	Matcher string     `json:"matcher"`
	Hooks   []HookSpec `json:"hooks"`
}

// A HookSpec is one command hook. With Args set (even empty) Command is spawned directly, no shell (exec form);
// without, Command goes to bash -c (shell form).
type HookSpec struct {
	Type          string    `json:"type"`
	Command       string    `json:"command"`
	Args          *[]string `json:"args"`
	Timeout       *float64  `json:"timeout"`
	Async         bool      `json:"async"`
	Shell         string    `json:"shell"`
	If            string    `json:"if"`
	AsyncRewake   bool      `json:"asyncRewake"`
	OnFailure     string    `json:"onFailure"`
	StatusMessage string    `json:"statusMessage"`
}

// TimeoutSeconds is the hook's timeout.
func (h HookSpec) TimeoutSeconds() float64 {
	if h.Timeout != nil {
		return *h.Timeout
	}
	return DefaultHookTimeout
}

// Display is the command as a person would read it in a transcript line.
func (h HookSpec) Display() string {
	if h.Args == nil {
		return h.Command
	}
	return strings.Join(append([]string{h.Command}, *h.Args...), " ")
}

func (h HookSpec) key() string {
	b, _ := json.Marshal([]any{h.Command, h.Args, h.Shell})
	return string(b)
}

// LoadSettings reads the value of a --settings flag: a path to a settings file, or inline JSON. Claude Code takes the
// argument whole, so a value that starts with { is JSON and anything else is a path, which must name a regular file
// of at most 2 MiB (a directory, a FIFO or a device is refused before it is read: the file is opened without blocking
// and judged from the descriptor, so a name swapped for a FIFO after a check cannot hang the run).
func LoadSettings(arg string) (*Settings, error) {
	trimmed := strings.TrimSpace(arg)
	if trimmed == "" {
		return nil, errors.New("--settings needs a file path or inline JSON")
	}
	var data []byte
	if strings.HasPrefix(trimmed, "{") {
		data = []byte(trimmed)
	} else {
		var err error
		data, err = readRegular(arg, MaxSettingsBytes)
		switch {
		case errors.Is(err, errNotRegular):
			return nil, fmt.Errorf("settings file %s is not a regular file", arg)
		case errors.Is(err, errTooBig):
			return nil, fmt.Errorf("settings file %s is over the 2 MiB limit", arg)
		case err != nil:
			return nil, fmt.Errorf("settings file: %w", err)
		}
	}
	return ParseSettings(data)
}

// ParseSettings decodes settings JSON and checks every hook fakeclaude would run. A hook it cannot run faithfully
// (a type other than command, an if filter, asyncRewake, onFailure, a PowerShell shell) is an error, not a skip: a
// test that registers one must not pass because the stand-in ignored it.
func ParseSettings(data []byte) (*Settings, error) {
	var s Settings
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("settings: %w", err)
	}
	if dec.More() {
		return nil, errors.New("settings: data after the top-level object")
	}
	events := make([]string, 0, len(s.Hooks))
	for ev := range s.Hooks {
		events = append(events, ev)
	}
	sort.Strings(events)
	for _, ev := range events {
		if !modeledEvents[ev] {
			s.Warnings = append(s.Warnings, fmt.Sprintf("hooks for %s are accepted and never fired (fakeclaude models SessionStart, PostToolUse, PostToolUseFailure, PostToolBatch and Stop)", ev))
			continue
		}
		for gi, g := range s.Hooks[ev] {
			if _, err := g.matcherRE(); err != nil {
				return nil, fmt.Errorf("settings: hooks.%s[%d].matcher %q: %w", ev, gi, g.Matcher, err)
			}
			for hi, h := range g.Hooks {
				if err := h.validate(); err != nil {
					return nil, fmt.Errorf("settings: hooks.%s[%d].hooks[%d]: %w", ev, gi, hi, err)
				}
			}
		}
	}
	return &s, nil
}

func (h HookSpec) validate() error {
	switch {
	case h.Type != "command":
		return fmt.Errorf("type %q is not modeled (only command hooks run)", h.Type)
	case h.Command == "":
		return errors.New("command is empty")
	case h.If != "":
		return errors.New("the if filter is not modeled")
	case h.AsyncRewake:
		return errors.New("asyncRewake is not modeled")
	case h.OnFailure != "":
		return errors.New("onFailure is not modeled")
	case h.Args == nil && h.Shell != "" && h.Shell != "bash":
		return fmt.Errorf("shell %q is not modeled (bash only)", h.Shell)
	case h.Timeout != nil && *h.Timeout <= 0:
		return errors.New("timeout must be positive")
	}
	return nil
}

// exactMatcher is what makes a matcher a list of exact values rather than a regular expression: only letters, digits,
// underscores, hyphens, spaces, commas and | (the 2.1.310 hooks reference).
var exactMatcher = regexp.MustCompile(`^[A-Za-z0-9_\- ,|]*$`)

// matcherRE compiles a group's matcher the way the hooks reference describes it: empty or * matches everything; a
// matcher made only of exact-value characters is one exact string or a list of them separated by | or , with optional
// whitespace around each (so "Write,Edit", "Write, Edit" and "Write | Edit" all name two tools, and "a-b" is matched
// whole, not as a pattern); anything else is a regular expression, unanchored.
func (g HookGroup) matcherRE() (*regexp.Regexp, error) {
	m := g.Matcher
	switch {
	case m == "" || m == "*":
		return regexp.MustCompile(``), nil
	case exactMatcher.MatchString(m):
		var items []string
		for _, it := range strings.FieldsFunc(m, func(r rune) bool { return r == '|' || r == ',' }) {
			if it = strings.TrimSpace(it); it != "" {
				items = append(items, regexp.QuoteMeta(it))
			}
		}
		if len(items) == 0 {
			return regexp.MustCompile(`^$`), nil
		}
		return regexp.Compile(`^(?:` + strings.Join(items, "|") + `)$`)
	}
	return regexp.Compile(m)
}

// HooksFor lists the command hooks to run for an event. subject is the value a matcher is tested against (the tool
// name for the tool events, the source for SessionStart); events with no matcher (PostToolBatch, Stop) ignore the
// groups' matchers. A hook that appears twice with the same command is run once, as Claude Code does.
func (s *Settings) HooksFor(event, subject string) []HookSpec {
	if s == nil || s.DisableAllHooks || !modeledEvents[event] {
		return nil
	}
	useMatcher := event != EvPostToolBatch && event != EvStop
	seen := map[string]bool{}
	var out []HookSpec
	for _, g := range s.Hooks[event] {
		re, err := g.matcherRE()
		if err != nil || (useMatcher && !re.MatchString(subject)) {
			continue
		}
		for _, h := range g.Hooks {
			if seen[h.key()] {
				continue
			}
			seen[h.key()] = true
			out = append(out, h)
		}
	}
	return out
}
