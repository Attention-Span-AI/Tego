// SPDX-License-Identifier: Apache-2.0

package claudecode

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"

	"github.com/attention-span-ai/tego/pkg/spec/harness"
)

// HookTimeout is the timeout, in seconds, of every hook entry the provisioner writes: the hook answers in
// milliseconds and waits at most LockBudget for its lock, so ten seconds is only a bound on a hook that hangs, which
// Claude Code would otherwise wait 600 seconds for (its default for a command hook).
const HookTimeout = 10

// matchAll is the matcher of the tool events' entries: every tool, the built-in ones and MCP's alike.
const matchAll = "*"

// errSettings is a user's settings value the provisioner cannot merge its hook into.
var errSettings = errors.New("claude settings")

// hookCommand is one command hook in exec form: args is set, so Claude Code spawns command directly, with no shell
// that the run's exec rules would also have to admit.
type hookCommand struct {
	Type    string   `json:"type"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Timeout int      `json:"timeout"`
}

// hookGroup is one entry of an event's array in a settings file's hooks: a matcher (absent for the events that take
// none) and its hooks.
type hookGroup struct {
	Matcher string        `json:"matcher,omitempty"`
	Hooks   []hookCommand `json:"hooks"`
}

// hookEvents is every event the hook serves, in the order the settings file lists them.
var hookEvents = []string{EventSessionStart, EventPostToolUse, EventPostToolUseFailure, EventPostToolBatch, EventStop}

// tegoGroups is the entry the provisioner adds to each event's array: the hook's argv (the tego executable first) as
// one exec-form command, with matcher "*" on the tool events and none on the others.
func tegoGroups(hookArgv []string) map[string]hookGroup {
	cmd := hookCommand{Type: "command", Command: hookArgv[0], Args: hookArgv[1:], Timeout: HookTimeout}
	out := map[string]hookGroup{}
	for _, ev := range hookEvents {
		g := hookGroup{Hooks: []hookCommand{cmd}}
		if ev == EventPostToolUse || ev == EventPostToolUseFailure {
			g.Matcher = matchAll
		}
		out[ev] = g
	}
	return out
}

// userValue is the user's own --settings value, checked: every top-level key as given, and the two the provisioner
// reads and rewrites, env and hooks, decoded.
type userValue struct {
	// top is every top-level key of the user's object, re-encoded as given.
	top map[string]json.RawMessage
	// env is the user's env block (empty when they gave none).
	env map[string]string
	// hooks is each event's entries of the user's hooks (empty when they gave none).
	hooks map[string][]json.RawMessage
}

// parseUser checks user, the user's own --settings JSON (nil for none), as the value tego's hook will share a file
// with. Refused: a value that is not one JSON object; disableAllHooks set to anything but false (under which Claude
// Code runs no hook, tego's included); an env that is not an object of strings; and a hooks that is not well-formed
// matcher groups (userHooks). Claude Code reports a value its schema rejects as a Settings Error, which a -p run
// answers by skipping "the broken file or values", so a malformed key of the user's could take tego's hook down with
// it; the checks catch the shapes that cannot be valid, and deeper ones are left to Claude Code (the reason end-to-end run runs a
// merged file holding an invalid value against the real binary).
func parseUser(user []byte) (userValue, error) {
	u := userValue{top: map[string]json.RawMessage{}, env: map[string]string{}}
	if user != nil {
		if err := decodeOne(user, &u.top); err != nil {
			return userValue{}, fmt.Errorf("%w: the user's --settings is not one JSON object: %w", errSettings, err)
		}
		if u.top == nil {
			return userValue{}, fmt.Errorf("%w: the user's --settings is null, not a JSON object", errSettings)
		}
	}
	if raw, ok := u.top["disableAllHooks"]; ok {
		var off bool
		if err := json.Unmarshal(raw, &off); err != nil || off {
			return userValue{}, fmt.Errorf("%w: the user's --settings sets disableAllHooks, under which Claude Code runs no hook and the agent "+
				"would never hear of a refusal; remove it, or set harness: none", errSettings)
		}
	}
	if raw, ok := u.top["env"]; ok {
		var env map[string]*string
		if err := json.Unmarshal(raw, &env); err != nil || env == nil {
			return userValue{}, fmt.Errorf("%w: the user's --settings env is not an object of strings", errSettings)
		}
		for k, v := range env {
			if v == nil {
				return userValue{}, fmt.Errorf("%w: the user's --settings env is not an object of strings (%s is null)", errSettings, k)
			}
			u.env[k] = *v
		}
	}
	var err error
	if u.hooks, err = userHooks(u.top["hooks"]); err != nil {
		return userValue{}, err
	}
	return u, nil
}

// buildSettings is the settings file the run's claude loads: the user's value u with the hook's entry appended to
// each event's array under hooks, disableAllHooks false at the top level, and the mode variables pinned in env.
// Every other key and hook of the user's is kept (the same JSON value, re-encoded; Claude Code merges hook entries
// across settings levels, so theirs and tego's both run); the result is indented JSON with sorted keys.
//
// disableAllHooks is written false because Claude Code reads the value left after settings precedence, and the
// command line (--settings) outranks user, project and local settings: a true in ~/.claude/settings.json, in
// $CLAUDE_CONFIG_DIR, or in a project's .claude/settings.json or settings.local.json (a cloned repository's, or one
// the agent writes mid-run, which Claude Code reloads) would otherwise turn tego's hook off in a run recorded
// provisioned. The same false lets the user's own hooks at those levels run too. A managed disableAllHooks or
// allowManagedHooksOnly outranks the flag, and nothing in --settings overrides it (ADR 0063 (8)).
//
// env gets CLAUDE_CODE_SAFE_MODE and CLAUDE_CODE_SIMPLE "0" for the same reason: Claude Code reads a settings file's
// env block as it reads the shell's, so a lower level's env block could otherwise turn on safe mode or bare mode
// (no hook in either) in a run whose provision saw neither. A result past harness.MaxUserFile, the CLI's limit for a
// settings file, is refused.
func buildSettings(u userValue, groups map[string]hookGroup) ([]byte, error) {
	top, hooks, env := maps.Clone(u.top), maps.Clone(u.hooks), maps.Clone(u.env)
	top["disableAllHooks"] = json.RawMessage("false")
	env[envSafeMode], env[envSimple] = "0", "0"
	var err error
	if top["env"], err = json.Marshal(env); err != nil {
		return nil, err
	}
	for ev, g := range groups {
		b, err := json.Marshal(g)
		if err != nil {
			return nil, err
		}
		hooks[ev] = append(slices.Clip(hooks[ev]), b)
	}
	if top["hooks"], err = json.Marshal(hooks); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(top); err != nil {
		return nil, err
	}
	if buf.Len() > harness.MaxUserFile {
		return nil, fmt.Errorf("%w: the merged settings are %d bytes, past Claude Code's %d-byte limit for a settings file",
			errSettings, buf.Len(), harness.MaxUserFile)
	}
	return buf.Bytes(), nil
}

// userHooks is the user's hooks value (raw, nil for none) as each event's entries. Every event's value must be an
// array of matcher groups, on the events tego registers and on the ones it leaves alone (any event name is kept, for
// events newer than this code): each group an object whose matcher, when present, is a string and whose hooks is an
// array of objects with a string type. The user's entries share the file with tego's (parseUser says why that
// matters).
func userHooks(raw json.RawMessage) (map[string][]json.RawMessage, error) {
	events := map[string]json.RawMessage{}
	if raw != nil {
		if err := json.Unmarshal(raw, &events); err != nil || events == nil {
			return nil, fmt.Errorf("%w: the user's --settings hooks is not an object of event arrays", errSettings)
		}
	}
	out := make(map[string][]json.RawMessage, len(events))
	for _, ev := range slices.Sorted(maps.Keys(events)) {
		var entries []json.RawMessage
		if err := json.Unmarshal(events[ev], &entries); err != nil || entries == nil {
			return nil, fmt.Errorf("%w: the user's --settings hooks.%s is not an array", errSettings, ev)
		}
		for i, e := range entries {
			if err := checkGroup(e); err != "" {
				return nil, fmt.Errorf("%w: the user's --settings hooks.%s[%d]%s", errSettings, ev, i, err)
			}
		}
		out[ev] = entries
	}
	return out, nil
}

// checkGroup is what is wrong with e as a matcher group, worded after its path in the hooks value ("" when it is
// well-formed): not an object, a matcher that is not a string, or a hooks that is not an array of objects each with
// a string type.
func checkGroup(e json.RawMessage) string {
	var group map[string]json.RawMessage
	if err := json.Unmarshal(e, &group); err != nil || group == nil {
		return " is not an object (a matcher group)"
	}
	if m, ok := group["matcher"]; ok {
		var s *string
		if json.Unmarshal(m, &s) != nil || s == nil {
			return ".matcher is not a string"
		}
	}
	var hooks []json.RawMessage
	if err := json.Unmarshal(group["hooks"], &hooks); err != nil || hooks == nil {
		return ".hooks is not an array"
	}
	for j, h := range hooks {
		var hook map[string]json.RawMessage
		if err := json.Unmarshal(h, &hook); err != nil || hook == nil {
			return fmt.Sprintf(".hooks[%d] is not an object", j)
		}
		var typ *string
		if json.Unmarshal(hook["type"], &typ) != nil || typ == nil {
			return fmt.Sprintf(".hooks[%d].type is not a string", j)
		}
	}
	return ""
}

// decodeOne decodes exactly one JSON value from b into v: trailing data is refused, as a settings file is one value.
func decodeOne(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the JSON value")
	}
	return nil
}
