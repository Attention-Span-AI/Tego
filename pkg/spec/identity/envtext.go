// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"path/filepath"
	"strings"
)

// What a message may show of the environment. This comment is the rule's one statement in the code (the engine
// notes state it, docs/development/operations.md "What a message shows of the environment"); every diagnostic,
// warning, error, log line and dashboard text follows it, through the three functions below where its package may
// import this one.
//
//	(a) NEVER PRINTED, whatever its length: the value of an entry of the AGENT'S environment. That is the
//	    contract's env section (set and pass-through entries), a harness entry, a credential, and anything read
//	    from another process's environment. The message names the variable (EnvEntryName). An entry so malformed
//	    that its name cannot be told from its value is called by its position, and nothing of it is echoed. A
//	    bare secret that is itself shaped like a variable name cannot be told from a name, and is shown as one.
//	(b) NEVER ECHOED: a value that failed validation, of any variable (a run id that is not a run id, a path
//	    variable that is not an absolute clean path of printable characters, EnvPlace). The message names the
//	    variable, says what is wrong and how the person prints it themselves (EnvInspect).
//	(c) PRINTED where the message is about it: a place Tego resolved from a location variable and validated
//	    (EnvPlace: HOME, the XDG folders, TMPDIR, TEGO_CONFIG and Tego's other path settings, TMUX_TMPDIR,
//	    SCREENDIR, a PATH directory), exactly as a place given by a flag or a settings file is printed; and a Tego
//	    identifier that passed validation (a run id, a parent run id, the invoking uid). A person must see which
//	    file is malformed and which folder could not be made.
//	(d) An explicit display or export of a contract (the rule table, the effective settings, merged YAML, JSON)
//	    shows what was asked for and is not a diagnostic. The rule table names an entry whose value comes from the
//	    caller's environment and says where it comes from; a value written in the contract file is shown as the
//	    file has it. Machine exports carry values.
//
// An inherited PATH is both a pass-through entry and a list of places: the rule table names it only as inherited,
// and an error about a program that was not found lists its directories ("searched: ..."), because that message is
// about those places; an env.set PATH is never printed.
//
// What protects a person is keeping secret-capable values out of messages, not hiding places.

// EnvEntryName is the variable an environment entry names, for a message: the text before its first "=" (the whole
// entry when it has none), and nothing of its value. ok is false when that text is not a variable name
// ([A-Za-z_][A-Za-z0-9_]*): the entry's name cannot be told from its value, so the message calls the entry by its
// position and echoes nothing of it (rule (a)).
func EnvEntryName(entry string) (name string, ok bool) {
	name, _, _ = strings.Cut(entry, "=")
	if !envName(name) {
		return "", false
	}
	return name, true
}

// envName reports whether s is a variable name: a letter or "_", then letters, digits and "_".
func envName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '_', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// EnvPlace reports whether value, read from a location variable, is a place a message may print (rule (c)): an
// absolute, clean path of printable characters, as a path given by a flag or a settings file would be. Any other
// value failed validation and is never echoed (rule (b)): the message names the variable and adds EnvInspect.
func EnvPlace(value string) bool {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return false
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// EnvInspect is how a person prints the variables a message names without the message echoing them (rule (b)):
// "print it with: echo $NAME", or "print them with: echo $A; echo $B" for more than one.
func EnvInspect(names ...string) string {
	if len(names) == 0 {
		return ""
	}
	cmds := make([]string, len(names))
	for i, n := range names {
		cmds[i] = "echo $" + n
	}
	if len(names) == 1 {
		return "print it with: " + cmds[0]
	}
	return "print them with: " + strings.Join(cmds, "; ")
}
