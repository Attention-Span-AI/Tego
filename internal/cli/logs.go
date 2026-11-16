// SPDX-License-Identifier: Apache-2.0

package cli

import "flag"

func init() {
	register(cmdLogs)
	register(cmdAllow)
}

// cmdLogs is `tego logs <session> [-f]`: tego events under the session's verb, -f being --follow.
func cmdLogs() Command {
	c := cmdEvents()
	c.Name, c.Summary = "logs", "a session's events (-f to follow); the same as tego events"
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
	c := cmdApprove()
	c.Name, c.Summary = "allow", "allow an action a session is holding; the same as tego approve"
	return c
}
