// SPDX-License-Identifier: Apache-2.0

package claudecode

import (
	"errors"
	"fmt"
	"strings"
)

// The Claude Code CLI options the provisioner reads (CLI reference, Claude Code 2.1.310).
const (
	// flagSettings is "--settings <file-or-json>": a settings file's path or inline JSON, as one argv element, also
	// spelled --settings=<value>.
	flagSettings = "--settings"
	// flagBare is "--bare", which sets CLAUDE_CODE_SIMPLE and skips every hook, a --settings file's included: "Minimal
	// mode: skip hooks (those defined in settings and by installed plugins ...)" (claude --help, 2.1.310; measured
	// by the reason end-to-end run).
	flagBare = "--bare"
	// flagSafeMode is "--safe-mode", under which no hook but a managed policy's loads; it sets CLAUDE_CODE_SAFE_MODE.
	flagSafeMode = "--safe-mode"
	// endOfOptions ends the options, but only where Claude Code's option parser reads it as an element of its own:
	// the parser (commander) takes the next element as the value of an option that takes one before it looks for
	// "--", so after --model -- the elements are still options. The provisioner has no table of Claude Code's
	// options, so it cannot tell the two "--" apart and reads past both (parseArgs).
	endOfOptions = "--"
)

// envSimple is the variable --bare sets and that turns bare mode, and so no hook, on by itself (headless page, bare
// mode; measured with 2.1.310: no hook runs).
const envSimple = "CLAUDE_CODE_SIMPLE"

// envSafeMode is the variable --safe-mode sets and that turns safe mode on by itself (environment variables page).
const envSafeMode = "CLAUDE_CODE_SAFE_MODE"

// errArgv is a claude argv the provisioner will not rewrite.
var errArgv = errors.New("claude command line")

// claudeArgs is what the provisioner reads from a claude argv: the user's own --settings value and the arguments
// without the user's --settings element(s).
type claudeArgs struct {
	// settings is the user's --settings value, and hasSettings whether one was given.
	settings    string
	hasSettings bool
	// rest is argv[1:] with the user's --settings and its value taken out, everything else in order.
	rest []string
}

// parseArgs reads args, a claude argv without its argv[0]. Only whole elements are matched: "--settings" with the
// next element as its value, "--settings=<value>", "--safe-mode" and "--bare"; an element that merely contains those
// words (a prompt that mentions them) is left alone. A --settings with no value or an empty one is refused (Claude
// Code itself refuses it: a run must not lose its hook to it), and so is --settings given twice, since how Claude
// Code merges two is not documented. So are --safe-mode, under which Claude Code loads no hook from --settings (only
// a managed policy's hooks run), and --bare, under which it runs no hook at all: the run would say it delivers what
// it cannot (fixSafeMode, fixBare).
//
// A "--" does not end the scan (endOfOptions: it may be an option's value, as in --model --, and then what follows is
// still options). After a "--", --settings, --settings=<value>, --safe-mode and --bare are refused as ambiguous: a
// flag that would replace tego's file or turn the hook off, or a prompt that is exactly that word, which tego cannot
// tell apart. Elements after a "--" are kept in rest as given.
func parseArgs(args []string) (claudeArgs, error) {
	var c claudeArgs
	set := func(v string) error {
		if c.hasSettings {
			return fmt.Errorf("%w: %s is given twice; give it once, as a path or inline JSON, and tego merges its hook into it", errArgv, flagSettings)
		}
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("%w: %s has an empty value", errArgv, flagSettings)
		}
		c.settings, c.hasSettings = v, true
		return nil
	}
	c.rest = make([]string, 0, len(args))
	ended := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case ended && (a == flagSettings || strings.HasPrefix(a, flagSettings+"=") || a == flagSafeMode || a == flagBare):
			return claudeArgs{}, fmt.Errorf("%w: %q after \"--\" is a flag to Claude Code when that \"--\" is an option's value "+
				"(--model --) and a prompt otherwise, and tego cannot tell which; drop it, or give %s before any \"--\" "+
				"(tego merges its hook into it)", errArgv, a, flagSettings)
		case ended:
		case a == endOfOptions:
			ended = true
		case a == flagSettings:
			if i+1 >= len(args) {
				return claudeArgs{}, fmt.Errorf("%w: %s has no value", errArgv, flagSettings)
			}
			if err := set(args[i+1]); err != nil {
				return claudeArgs{}, err
			}
			i++
			continue
		case strings.HasPrefix(a, flagSettings+"="):
			if err := set(strings.TrimPrefix(a, flagSettings+"=")); err != nil {
				return claudeArgs{}, err
			}
			continue
		case a == flagSafeMode:
			return claudeArgs{}, fmt.Errorf("%w: %s loads no hook but a managed policy's, so the agent would never hear of a refusal; %s",
				errArgv, flagSafeMode, fixSafeMode)
		case a == flagBare:
			return claudeArgs{}, fmt.Errorf("%w: %s runs no hook, so the agent would never hear of a refusal; %s", errArgv, flagBare, fixBare)
		}
		c.rest = append(c.rest, a)
	}
	return c, nil
}

// withSettings is argv with "--settings path" inserted at index 1, right after argv[0]: so that neither a trailing
// "--" nor a positional prompt can take the flag for an argument.
func withSettings(argv0 string, rest []string, path string) []string {
	out := make([]string, 0, len(rest)+3)
	out = append(out, argv0, flagSettings, path)
	return append(out, rest...)
}

// envOn reports whether env turns on the Claude Code flag variable name (envSimple, envSafeMode): an entry is
// truthy (1, true, yes or on, in any case), as Claude Code reads an environment flag. Any entry counts, should env
// hold the name twice, which errs toward the safe side: a refused run claims nothing.
func envOn(env []string, name string) bool {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name && truthy(v) {
			return true
		}
	}
	return false
}

// truthy reports whether v turns a Claude Code flag variable on: 1, true, yes or on, in any case, blanks trimmed.
func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
