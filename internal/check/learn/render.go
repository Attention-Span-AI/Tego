// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/check/secretpath"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const (
	mib = 1 << 20
	gib = 1 << 30
)

// suggestLimits is the limits comment block's numbers: memory about twice the run's peak (in whole 64 MiB, at least
// 64 MiB), pids four times its peak (at least 16), and wall three times how long it ran (in whole minutes, at least
// one). A number is empty where the record held no peak. They are a starting point for a person: a run's peaks say
// nothing of the worst a later run needs.
func suggestLimits(end *record.RunEndPayload, ran time.Duration) *Limits {
	l := &Limits{}
	if r := end.Resources; r != nil {
		if r.MemoryPeak != nil && *r.MemoryPeak > 0 {
			l.MemoryPeak = fmt.Sprintf("%.1fMiB", float64(*r.MemoryPeak)/mib)
			l.Memory = formatBytes(max(64*mib, ceilTo(2*int64(min(*r.MemoryPeak, 1<<60)), 64*mib)))
		}
		if r.PidsPeak != nil && *r.PidsPeak > 0 {
			l.PidsPeak = strconv.FormatUint(*r.PidsPeak, 10)
			l.Pids = strconv.FormatInt(max(16, 4*int64(min(*r.PidsPeak, 1<<40))), 10)
		}
	}
	if ran > 0 {
		l.Ran = roundRan(ran).String()
		minutes := max(1, (int64(3*ran/time.Second)+59)/60)
		l.Wall = formatMinutes(minutes)
	}
	if *l == (Limits{}) {
		return nil
	}
	return l
}

func ceilTo(n, unit int64) int64 { return (n + unit - 1) / unit * unit }

// formatBytes is n bytes, a multiple of 64 MiB, in the IEC unit the contract reads: GiB when it is whole ones.
func formatBytes(n int64) string {
	if n%gib == 0 {
		return strconv.FormatInt(n/gib, 10) + "GiB"
	}
	return strconv.FormatInt(n/mib, 10) + "MiB"
}

// formatMinutes is m minutes as one duration unit the contract reads: hours when whole ones.
func formatMinutes(m int64) string {
	if m%60 == 0 {
		return strconv.FormatInt(m/60, 10) + "h"
	}
	return strconv.FormatInt(m, 10) + "m"
}

// sortLeft orders what was left out by section (fs, exec, net, the order the contract prints them), then by how
// often it was seen, then by name, so a proposal of the same record is the same bytes.
func sortLeft(left []Excluded) {
	rank := map[string]int{"fs": 0, "exec": 1, "net": 2}
	sort.SliceStable(left, func(i, j int) bool {
		a, b := left[i], left[j]
		switch {
		case rank[a.Section] != rank[b.Section]:
			return rank[a.Section] < rank[b.Section]
		case a.Count != b.Count:
			return a.Count > b.Count
		}
		return a.What < b.What
	})
}

// quote is s as a YAML double-quoted scalar. s is a plain string (see plain): only the backslash and the quote need
// escaping.
func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func times(n int) string {
	if n == 1 {
		return "seen once"
	}
	return fmt.Sprintf("seen %d times", n)
}

// Contract is the proposed file: YAML that agent.Load reads, with the comments a reviewer needs. Every list is
// written, empty or not: an absent section means "no restriction", and a proposal must never say that by leaving
// something out.
func (p *Proposal) Contract() string {
	var b strings.Builder
	p.header(&b)
	b.WriteString("version: 0\n")
	fmt.Fprintf(&b, "name: %s\n", p.Name)
	if p.CommandNote != "" {
		fmt.Fprintf(&b, "# %s\n", p.CommandNote)
	}
	cmd := make([]string, len(p.Command))
	for i, c := range p.Command {
		cmd[i] = quote(c)
	}
	fmt.Fprintf(&b, "command: [%s]\n", strings.Join(cmd, ", "))

	b.WriteString("\nfs:\n")
	b.WriteString("  # Reads are not restricted here; fs.deny_read is left to the built-in list, which learn never removes.\n")
	p.list(&b, "write", p.Write, "fs")
	if p.Collapsed != "" {
		fmt.Fprintf(&b, "  # The directories written were many, so they are merged to %s.\n", p.Collapsed)
	}

	b.WriteString("\nexec:\n")
	b.WriteString("  # The command above is admitted on its own; these are the other programs the run started.\n")
	p.list(&b, "allow", p.Exec, "exec")

	b.WriteString("\nnet:\n")
	if p.hasInet() {
		b.WriteString("  # tego records the address a program connected to, never the host name it asked for, so these\n")
		b.WriteString("  # are addresses, and a service's addresses change. To allow a service by name, write the name in\n")
		b.WriteString("  # place of its addresses, for example \"tcp://api.example.com:443\"; tego resolves it when the run starts.\n")
	}
	p.list(&b, "allow", p.Net, "net")

	p.limits(&b)
	return b.String()
}

func (p *Proposal) hasInet() bool {
	for _, it := range p.Net {
		if strings.HasPrefix(it.Value, "tcp://") || strings.HasPrefix(it.Value, "udp://") {
			return true
		}
	}
	return false
}

// list writes one allow list and the "observed, not allowed" comments of its section after it.
func (p *Proposal) list(b *strings.Builder, key string, items []Item, section string) {
	if len(items) == 0 {
		fmt.Fprintf(b, "  %s: []\n", key)
	} else {
		fmt.Fprintf(b, "  %s:\n", key)
		for _, it := range items {
			note := times(it.Count)
			if it.Note != "" {
				note += "; " + it.Note
			}
			fmt.Fprintf(b, "    - %s  # %s\n", quote(it.Value), note)
		}
	}
	for _, ex := range p.Left {
		if ex.Section == section {
			fmt.Fprintf(b, "  # observed, not allowed: %s (%s): %s\n", ex.What, times(ex.Count), ex.Why)
		}
	}
}

func (p *Proposal) limits(b *strings.Builder) {
	b.WriteString("\n# limits: a suggestion from this one run's resource peaks, not what the agent needs at its worst:\n")
	b.WriteString("# memory about twice the peak, pids about four times, wall about three times how long the run lasted.\n")
	l := p.Limits
	if l == nil {
		b.WriteString("# The record holds no resource peaks (the run has no run_end, or its cgroup was not readable), so none is suggested.\n")
		return
	}
	b.WriteString("# Remove the leading \"# \" to use them.\n")
	b.WriteString("# limits:\n")
	if l.Memory != "" {
		fmt.Fprintf(b, "#   memory: %s  # peak %s\n", l.Memory, l.MemoryPeak)
	}
	if l.Pids != "" {
		fmt.Fprintf(b, "#   pids: %s  # peak %s\n", l.Pids, l.PidsPeak)
	}
	if l.Wall != "" {
		fmt.Fprintf(b, "#   wall: %s  # the run lasted %s\n", l.Wall, l.Ran)
	}
}

func (p *Proposal) header(b *strings.Builder) {
	for _, w := range p.Warnings() {
		if strings.HasPrefix(w, "this run opened") {
			fmt.Fprintf(b, "# WARNING: %s.\n", w)
		}
	}
	fmt.Fprintf(b, "# Proposed boundary contract, generated by `tego learn` from run %s (agent %s).\n",
		record.Printable(p.Run), quote(record.Printable(p.Agent)))
	if p.Ended {
		fmt.Fprintf(b, "# The run started %s, lasted %s and ended: %s", p.Started.UTC().Format(time.RFC3339), p.Ran, record.Printable(p.EndReason))
		if p.ExitCode != 0 {
			fmt.Fprintf(b, ", exit code %d", p.ExitCode)
		}
		b.WriteString(".\n")
	} else {
		fmt.Fprintf(b, "# The run started %s; its record has no run_end, so it was still going or was cut off.\n", p.Started.UTC().Format(time.RFC3339))
	}
	b.WriteString("#\n")
	b.WriteString("# This is a PROPOSAL for a person to review, not a policy to adopt unread. It allows what that run did and no\n")
	b.WriteString("# more. It is built from the run's own record, so it is only as good as the run was representative, and anything\n")
	b.WriteString("# the agent did while it was watched is in it. Read every entry, then run `tego compile` on the file.\n")
	b.WriteString("#\n")
	b.WriteString("# It never removes fs.deny_read: the built-in credential list is left to apply, so a read of a path on it that the\n")
	b.WriteString("# run made will now be refused. Keep this file outside the workspace and outside every fs.write entry below: tego\n")
	b.WriteString("# refuses a contract the agent could rewrite. Paths are as the run recorded them, and tego follows symlinks when\n")
	b.WriteString("# it compiles, so check that each fs.write entry still names the directory it says.\n")
	b.WriteString("#\n")
	b.WriteString("# Left out, and why:\n")
	for _, l := range p.leftOut() {
		fmt.Fprintf(b, "#   - %s\n", l)
	}
	b.WriteString("#\n")
}

// leftOut is the header's list of what the proposal does not carry.
func (p *Proposal) leftOut() []string {
	var out []string
	if p.Reads > 0 {
		out = append(out, fmt.Sprintf("reads: the run opened files for reading %d times, and none is listed. A contract restricts reads only through"+
			" fs.deny_read, whose built-in list applies, so reads stay open: the agent can read any file that list does not name.", p.Reads))
	} else {
		out = append(out, "reads: none were recorded, and reads stay open: the agent can read any file the built-in fs.deny_read list does not name.")
	}
	out = append(out, "env: there is no env section, so env stays open: every variable of the launcher's environment reaches the agent, secrets"+
		" included. Add env.pass with the names the agent needs.")
	if p.LeakChecked && len(p.Leaks) == 0 {
		out = append(out, fmt.Sprintf("leaks: no place off the contract was first reached within %d s and %d lines of an open of a secret for reading."+
			" That rule goes by file names and closeness: it proves nothing, it does not judge system lookups or port 53 on this machine,"+
			" and a place first reached before the read is not caught.", secretpath.NearSeconds, secretpath.NearLines))
	}
	if n := p.leftCount("fs", "workspace"); n > 0 {
		out = append(out, fmt.Sprintf("writes outside the workspace %s: %d of them, listed under fs.write as observed, not allowed."+
			" An agent's own state (a config or cache directory) is usually here: point it inside the workspace and learn again,"+
			" or give --workspace a directory that holds both.", dirsOrNone(p.Workspace), n))
	}
	if n := p.leftCount("fs", "tego's own state directory"); n > 0 {
		out = append(out, fmt.Sprintf("writes in or around tego's own state directories: %d, never proposed (tego refuses a contract that lets the agent write them).", n))
	}
	if n := p.leftCount("exec", ""); n > 0 {
		out = append(out, fmt.Sprintf("programs started %d times that tego could not run in its cage, that are not programs on this machine now, that are /proc paths, or whose name is not a plain absolute path: listed under exec.allow as observed, not allowed.", n))
	}
	if n := p.leftCount("net", ""); n > 0 {
		out = append(out, fmt.Sprintf("connections not proposed: %d, listed under net.allow as observed, not allowed (a dangerous socket, a raw socket, a route probe, a send next to a secret read, or an unrecognised destination).", n))
	}
	if p.Refused > 0 {
		out = append(out, fmt.Sprintf("%d actions the record shows refused or held for approval: a refused action did not happen, so none is proposed.", p.Refused))
	}
	if p.Alternates > 0 {
		out = append(out, fmt.Sprintf("%d file opens a person answered with another file (tego alternate): the agent did not get the file it asked for, so none is proposed.", p.Alternates))
	}
	if p.Failed > 0 {
		out = append(out, fmt.Sprintf("%d file and exec actions that failed: none is proposed.", p.Failed))
	}
	if p.SearchMisses > 0 {
		out = append(out, fmt.Sprintf("%d exec attempts that were not a program starting (a search of PATH tries each directory in turn): only the one that ran is listed.", p.SearchMisses))
	}
	if p.Unresolved > 0 {
		out = append(out, fmt.Sprintf("%d actions whose path was not absolute, which no entry can name.", p.Unresolved))
	}
	if p.RuntimeGranted > 0 {
		out = append(out, fmt.Sprintf("%d file actions in the run's own CODEX_HOME, which every run grants itself (fs.codex_home): no entry names it.", p.RuntimeGranted))
	}
	if p.HarnessStateGranted > 0 {
		out = append(out, fmt.Sprintf("%d file actions in the hook-state directory the run grants its harness itself (fs.harness-state): no entry names it.", p.HarnessStateGranted))
	}
	if p.HarnessHookGranted > 0 {
		out = append(out, fmt.Sprintf("%d execs of the harness hook the run grants itself (exec.harness-hook), its exact argv only: an entry naming the tego binary would admit every argv.", p.HarnessHookGranted))
	}
	if p.Truncated {
		out = append(out, "the run touched more distinct paths and endpoints than learn keeps, so what is listed is incomplete.")
	}
	out = append(out, "models, capture and tier: the record holds none of them, so tego's defaults apply.")
	out = append(out, "DNS lookups to the machine's resolver need no entry: tego allows the resolver itself.")
	return out
}

func dirsOrNone(ws string) string {
	if ws == "" {
		return "(there is none)"
	}
	return quote(record.Printable(ws))
}

// leftCount is how many times the section's left-out entries whose reason contains why were seen.
func (p *Proposal) leftCount(section, why string) (n int) {
	for _, ex := range p.Left {
		if ex.Section == section && strings.Contains(ex.Why, why) {
			n += ex.Count
		}
	}
	return n
}
