// SPDX-License-Identifier: Apache-2.0

package result

import (
	"fmt"
	"strings"
)

// footerWord is the one place a scan limit is worded. operator is what `tego scan` prints (empty means the
// code itself); plain is what a person is told on the Agents page. Both live in this table so that a new code
// cannot get one wording without the other (TestFooterWordsCoverEveryCode).
type footerWord struct{ operator, plain string }

var exclusionTable = map[string]footerWord{
	"other-users":             {"", "Other people's accounts on this computer."},
	"system-units":            {"", "Services that the system itself starts."},
	"containers-unattributed": {"container attribution", "Which container a program belongs to."},
	"mcp-deferred":            {"", "Tool servers set up for agents (not looked at in this scan)."},
	"units-deferred":          {"", "Services started in the background (not looked at in this scan)."},
	"unreadable-processes":    {"unreadable own processes", "Your programs that do not let Tego read their files."},
	"unknown-owners":          {"processes with unknown ownership", "Programs whose owner could not be found out."},
	"between-scans":           {"processes that ended before or during the snapshot", "Programs that stopped before or while the scan ran."},
	"libraries":               {"libraries without signatures", "Code libraries that agents load."},
	"remote-agents":           {"", "Agents that run on other computers."},
	"environment":             {"", "The settings values a program was started with."},
	"memory":                  {"", "What programs hold in memory."},
	"source-code":             {"", "The contents of your source code."},
	"network":                 {"", "Network traffic."},
	"unknown-formats":         {"other MCP clients and formats (not read)", "Agent tools whose settings Tego does not know how to read."},
	"other-user-settings":     {"other users' MCP settings and tool settings (not read)", "Other people's agent settings."},
	"nonlocal-homes":          {"NSS-only home discovery and unlisted unit/cron roots (not read)", "Home folders that come from a company or network login, and background-task folders Tego was not told about."},
	"unresolved-units":        {"runtime/generated user units; /etc/xdg/systemd/user, /usr/local/lib/systemd/user, /usr/share/systemd/user, /usr/local/share/systemd/user, ~/.config/systemd/user.control and other XDG unit roots (not read); /etc/systemd/system.control, /run/systemd/system.control, /run/systemd/transient, /run/systemd/generator.early, /run/systemd/generator, /run/systemd/generator.late, /etc/systemd/system.attached, /run/systemd/system.attached, /usr/local/lib/systemd/system and other system unit roots (not read); shell/env and other launch wrappers, program specifiers and environment expansions (unresolved)", "Background services whose start command is built at run time, and some system service folders."},
	"unresolved-cron":         {"cron shell bodies, substitutions and unsupported command forms (unresolved); schedules and environment values (not kept)", "Scheduled tasks whose command is built by a shell. Their schedules and values were not kept."},
	"scan-not-performed":      {"", "Everything: the scan could not run, so nothing was looked at."},
	"unknown-names":           {"agents under a name no rule knows", "Agents that go by a name Tego has no rule for."},
	"outer-pid-namespace":     {"outer pid namespaces (visibility unknown)", "Programs outside the container this scan ran in."},
	"project-deferred":        {"", "Project files (not looked at in this scan)."},
	"project-parents":         {"project parent folders (not walked)", "The folders above your project."},
	"project-children":        {"project child folders (not walked)", "The folders inside your project."},
	"project-alternates":      {"alternate manifests and lockfiles (not walked)", "Other project files, such as a second package list."},
	"project-includes":        {"project includes, URLs and source files (not followed)", "Files that your project files point to."},
	"container-patterns":      {"container runtime APIs, names, images and cgroups outside the fixed id patterns (not read)", "Containers that cannot be recognised from their id alone."},
}

// PlainExclusion is a not-looked-at code in plain words for the Agents page.
func PlainExclusion(code string) string {
	if w, ok := exclusionTable[code]; ok {
		return w.plain
	}
	return "Something this version of Tego does not describe."
}

// plainReason says why a source could not be read, and what the person can do, in plain words.
func plainReason(reason, kind string) string {
	switch reason {
	case "permission":
		return "Tego is not allowed to open it."
	case "gone":
		return "It disappeared while the scan ran."
	case "changed":
		return "It changed while the scan ran."
	case "owner":
		return "Its owner is not you or the administrator, so Tego will not trust it. Use a file or folder you own, or ask its owner to copy it."
	case "mode":
		return "Other users are allowed to change it, so Tego will not trust it. Remove write access for the group and for everyone else."
	case "symlink":
		return "It is a link to somewhere else, which Tego does not follow."
	case "type":
		return "It is not the kind of file Tego expected."
	case "size":
		return "It is bigger than Tego reads."
	case "syntax":
		return "It could not be understood."
	case "unsupported":
		return "It uses a form Tego does not read yet."
	case "unresolved":
		if kind == "E" {
			return "Its start command is built at run time, so Tego could not work it out."
		}
		return "Tego could not work it out."
	case "limit", "deadline":
		return "The scan reached its size or time limit before it finished."
	case "mount":
		return "It sits on another disk or mount, which Tego does not cross."
	case "privilege":
		return "Reading it needs more rights than this scan had."
	case "governed":
		return "Tego's own rules for this run kept the scan from reading it."
	case "io":
		return "Reading it failed."
	}
	return "Tego could not read it."
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// PlainScan is the plain footer: Lines say what the scan did and could not read; NotLooked lists what it never
// looked at.
type PlainScan struct{ Lines, NotLooked []string }

// PlainFooter is the scan's footer for the Agents page: the same facts as Footer, one short line each, in plain
// words, so each line says what it means for the person. It reads the same snapshot and the same codes.
func PlainFooter(s Snapshot) PlainScan {
	var l []string
	switch {
	case s.Status == "failed":
		l = append(l, "The scan did not finish. Nothing below is a complete picture.")
	case s.Mode == "advanced":
		l = append(l, "This scan covered every user's programs on this computer. Settings and project files were checked for one account only.")
	default:
		l = append(l, "This scan looked at your own programs only.")
	}
	switch s.Check {
	case "outside-observed":
		l = append(l, "It found programs that look like agents running outside Tego.")
	case "none-observed":
		l = append(l, "It found no agent running outside Tego among the programs it could see.")
	case "unreadable-observed", "none-observed-allow-unreadable":
		l = append(l, "It found no agent running outside Tego, but some of your programs could not be checked.")
	case "unknown":
		l = append(l, "It could not tell whether an agent runs outside Tego.")
	}
	var names []string
	for _, r := range s.Rules {
		names = append(names, r.Name)
	}
	if len(names) > 0 {
		l = append(l, "It looked for these agents: "+strings.Join(names, ", ")+".")
	}
	read, notRead := 0, 0
	for _, src := range s.Sources {
		read += src.Read
		notRead += src.NotRead
	}
	if notRead == 0 {
		l = append(l, fmt.Sprintf("It read %d %s and every one could be read.", read, plural(read, "place", "places")))
	} else {
		l = append(l, fmt.Sprintf("It read %d %s and could not read %d.", read, plural(read, "place", "places"), notRead))
	}
	if s.Counts.Exited > 0 || s.Counts.KernelThreads > 0 {
		l = append(l, fmt.Sprintf("%d %s ended while the scan ran, so %s not checked. %d %s that belong to the operating system %s left out; they are not agents.",
			s.Counts.Exited, plural(s.Counts.Exited, "program", "programs"), plural(s.Counts.Exited, "it was", "they were"),
			s.Counts.KernelThreads, plural(s.Counts.KernelThreads, "task", "tasks"), plural(s.Counts.KernelThreads, "was", "were")))
	}
	if n := s.Counts.UnreadablePrograms; n > 0 {
		pids := make([]string, 0, len(s.UnreadableProgramPIDs))
		for _, pid := range s.UnreadableProgramPIDs {
			pids = append(pids, fmt.Sprint(pid))
		}
		line := fmt.Sprintf("%d of your programs do not let their file be read", n)
		if n == 1 {
			line = "1 of your programs does not let its file be read"
		}
		if len(pids) > 0 {
			line += " (process numbers " + strings.Join(pids, ", ") + ")"
		}
		l = append(l, line+". Tego cannot tell whether these are agents; any program can make itself unreadable.")
	}
	for _, src := range s.Sources {
		if src.State != "not-read" && src.State != "partial" {
			continue
		}
		line := "Could not read " + pathWord(src.Locator) + ". " + plainReason(src.Reason, src.Kind)
		if src.Reason == "mode" && src.WritableGroup != nil {
			line += " The group " + fmt.Sprintf("%q", *src.WritableGroup) + " can change it."
		}
		if src.AccountRepair != "" {
			line += " " + src.AccountRepair
		}
		l = append(l, line+" Tego cannot tell whether these are agents.")
	}
	if len(s.Limits) > 0 {
		l = append(l, "The scan stopped early, so the rest is unknown.")
	}
	out := PlainScan{Lines: l}
	for _, code := range s.Exclusions {
		out.NotLooked = append(out.NotLooked, PlainExclusion(code))
	}
	return out
}
