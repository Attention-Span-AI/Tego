// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"slices"
	"strings"
)

// planCommand is an exec rule on the program's command: block adds the command to exec.deny (the exec command-rule
// grammar, ADR 0048), so the program's other commands still run; allow removes an exec.deny command entry of this
// file that refused the event. exec.ask stays reserved (ADR 0048 (5)), so there is no ask.
func (p *planner) planCommand(prog string, isOwn, listed bool) (string, error) {
	if p.req.Action == Allow {
		if !p.t.Refused {
			return "", nothing("running %s was already allowed", prog)
		}
		k, e, ok := ruleEntry(p.t.Rule)
		if !ok || k != "exec.deny" || !strings.Contains(e, " ") {
			return "", refuse("running %s was refused by %s, not by a command entry of exec.deny; allow the program instead", prog, p.t.Rule)
		}
		if !slices.Contains(list(p.top, k), e) {
			return "", refuse("running %s was refused by %s, which this file does not spell; tego rule never changes it", prog, p.t.Rule)
		}
		p.remove(k, e)
		return "allow `" + e + "` to run", nil
	}
	cmd, grammar := Command(prog, p.t.Argv)
	if cmd == "" {
		return "", refuse("this run of %s names no subcommand a command rule can spell; block the whole program instead", prog)
	}
	if p.t.Refused {
		return "", nothing("running %s was already refused (%s)", prog, p.t.Rule)
	}
	if isOwn {
		return "", refuse("%s is the run's own command; blocking it would stop every run of this contract", prog)
	}
	if !listed {
		return "", refuse("this contract's exec: section has neither allow nor deny, and adding exec.deny would let " +
			"every other program run (deny-list mode); add an exec.allow list first")
	}
	p.add("exec.deny", cmd)
	base, sub, _ := strings.Cut(cmd, " ")
	if !grammar {
		return "refuse to run `" + cmd + "` (" + base + " has no grammar row, so any " + base + " run whose arguments hold the word " +
			sub + " is refused); other " + base + " commands still run", nil
	}
	return "refuse to run `" + cmd + "` however its options are spelled; other " + base + " commands still run", nil
}

// planHost is a net rule on the destination's whole host. net.allow names host:port only (no any-port form), and
// the grammar has no net deny list, so: block removes every net.allow and net.ask entry of this file for the host;
// allow and ask refuse. An allow the file does not spell (built in, a profile's) refuses.
func (p *planner) planHost(d string) (string, error) {
	host := hostOf(d)
	if host == "" {
		return "", refuse("%s names no host and port", d)
	}
	if p.req.Action != Block {
		return "", refuse("net.%s names a host and a port, and has no any-port form; pick this destination (%s) instead",
			map[Action]string{Allow: "allow", Ask: "ask"}[p.req.Action], d)
	}
	if !has(p.top, "net") {
		return "", refuse("this contract has no net: section, so the run's network is not restricted; adding one would " +
			"refuse every other destination: write the net: section yourself")
	}
	k, e, ok := ruleEntry(p.t.Rule)
	if !p.t.Refused {
		if !ok || k != "net.allow" && k != "net.ask" {
			return "", refuse("%s was allowed by %s, which tego rule does not narrow", d, p.t.Rule)
		}
		if !slices.Contains(list(p.top, k), e) {
			return "", refuse("%s was allowed by %s, which this file does not spell; tego rule never changes it", d, p.t.Rule)
		}
	}
	for _, key := range []string{"net.allow", "net.ask"} {
		for _, entry := range list(p.top, key) {
			if sameHost(entry, host) {
				p.remove(key, entry)
			}
		}
	}
	if len(p.changes) == 0 {
		return "", nothing("no entry of this contract names %s: every port of it is already refused", host)
	}
	return "refuse connections to every port of " + host, nil
}
