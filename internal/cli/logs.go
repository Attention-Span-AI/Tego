// SPDX-License-Identifier: Apache-2.0

package cli

import "flag"

func init() {
	register(cmdLogs)
	register(cmdAllow)
}

// alias is c under another name and summary: a newer verb for the same code. The name comes first, as a literal at
// each call, so isocheck reads it the way it reads cmdAnswer("approve", …).
func alias(name, summary string, c Command) Command {
	c.Name, c.Summary = name, summary
	return c
}

// cmdLogs is `tego logs <session> [-f]`: tego events under the session's verb, -f being --follow.
func cmdLogs() Command {
	return alias("logs", "a session's events (-f to follow); the same as tego events", logsOf(cmdEvents()))
}

// logsOf is the events command with logs' usage and -f.
func logsOf(c Command) Command {
	c.Usage = "<session> [-f] " + c.Usage[len("<run> "):]
	flags := c.Flags
	c.Flags = func(fs *flag.FlagSet) {
		flags(fs)
		fs.Var(fs.Lookup("follow").Value, "f", "the same as --follow")
	}
	return c
}

// cmdAllow is `tego allow <approval>`: tego approve under the approval's verb.
func cmdAllow() Command {
	return alias("allow", "allow an action a session is holding; the same as tego approve", cmdApprove())
}
