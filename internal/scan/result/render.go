// SPDX-License-Identifier: Apache-2.0

package result

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/shellword"
)

// Render writes the snapshot and required limitations. live must come from a
// current record probe, never from the snapshot being rendered.
func Render(out, errs io.Writer, s Snapshot, asJSON, verbose bool, live map[string]bool) error {
	var err error
	if asJSON {
		err = json.NewEncoder(out).Encode(s)
	} else {
		err = renderText(out, s, verbose, live)
	}
	footerErr := Footer(errs, s, false)
	if err != nil {
		return err
	}
	return footerErr
}

func renderText(w io.Writer, s Snapshot, verbose bool, live map[string]bool) error {
	var b strings.Builder
	scope := "own processes only"
	if s.Mode == "advanced" {
		scope = "all users: matching processes, configured units and cron; container cgroup suggestions"
	} else if s.As.UID == 0 {
		scope = "root's own processes only"
	}
	fmt.Fprintf(&b, "Tego scan: uid %d, %s, %s, catalog %s. Saves ~/.tego/scan/last.json unless --check.\n", s.As.UID, scope, s.Finished.Format("2006-01-02T15:04:05Z"), s.Catalog)
	if slices.Contains(s.Exclusions, "scan-not-performed") {
		b.WriteString("Read: none; scan not performed.\n")
	}
	if s.Counts.Running+s.Counts.Installed+s.Counts.Settings+s.Counts.MCP+s.Counts.Units+s.Counts.SystemUnits+s.Counts.Cron+s.Counts.Project == 0 && len(s.Limits) == 0 && s.Status == "ok" {
		b.WriteString("No match among the rules and sources read.\n")
	}
	for _, i := range s.Items {
		facts := []string{}
		for _, e := range i.Evidence {
			facts = append(facts, e.Fact)
		}
		switch i.Kind {
		case "process":
			p := i.Process()
			fmt.Fprintf(&b, "Running: program named %s, pid %d; %s; evidence: %s.\n", i.Name, p.PID, MembershipWords(p, live), strings.Join(facts, ", "))
			foreign := s.Mode == "advanced" && p.UID != s.As.Recipient
			if s.Mode == "advanced" {
				if foreign {
					fmt.Fprintf(&b, "  observed uid %d; folder not recorded for other accounts.\n", p.UID)
				} else {
					fmt.Fprintf(&b, "  observed uid %d.\n", p.UID)
				}
			}
			if p.Container != nil {
				var v Container
				if json.Unmarshal(*p.Container, &v) == nil {
					fmt.Fprintf(&b, "  Container cgroup suggestion: %s %s; runtime identity not checked.\n", v.Runtime, v.ID)
				}
			}
			if verbose {
				fmt.Fprintf(&b, "  uid %d; start ticks %s; exe %s", p.UID, p.Start, pathWord(p.Exe))
				if !foreign {
					fmt.Fprintf(&b, "; cwd %s", pathWord(p.Cwd))
				}
				b.WriteByte('\n')
			}
		case "program":
			f := i.File()
			fmt.Fprintf(&b, "Installed candidate: program named %s; %s; evidence: %s.\n", i.Name, pathWord(f.Path), strings.Join(facts, ", "))
			if f.Target != nil {
				fmt.Fprintf(&b, "  target %s\n", pathWord(f.Target))
			}
		case "settings":
			fmt.Fprintf(&b, "Settings metadata: %s; %s; evidence: settings path exists, contents not read.\n", i.Name, pathWord(i.File().Path))
		case "mcp_server":
			v := i.Config()
			fmt.Fprintf(&b, "Configured MCP server: %q named in %s (%s, %s); transport %s; program %s; %d arguments; configured only; evidence: mcp-key.\n", v.Server, pathWord(v.Path), v.Client, v.Scope, v.Transport, pathWord(v.Program), v.Arguments)
		case "user_unit", "system_unit", "timer":
			v := i.Unit()
			label := "User"
			owner := ""
			if v.UID == nil {
				label = "System"
			} else if s.Mode == "advanced" {
				owner = fmt.Sprintf("; uid %d", *v.UID)
			}
			if i.Kind == "timer" {
				fmt.Fprintf(&b, "%s timer: %s; %s%s; configured to trigger %s; loaded state and firing time not checked; evidence: timer-unit.\n", label, v.Name, pathWord(v.Path), owner, pathWord(v.Triggers))
				break
			}
			fmt.Fprintf(&b, "%s unit: %s; %s%s; startup matches %s; %d arguments; configured only; loaded state not checked; evidence: exec-start.\n", label, v.Name, pathWord(v.Path), owner, i.Name, v.Arguments)
			if v.Specifiers {
				b.WriteString("  % specifiers left unexpanded.\n")
			}
		case "cron":
			v := i.Cron()
			uid := "unknown"
			if v.UID != nil {
				uid = fmt.Sprint(*v.UID)
			}
			fmt.Fprintf(&b, "Cron entry: %s; uid %s; configured program named %s; schedule and command omitted; execution not checked; evidence: cron-command.\n", pathWord(v.Path), uid, i.Name)
		case "project":
			p := i.Project()
			if p.Dependency != nil {
				fmt.Fprintf(&b, "Project: %s declares a dependency on %s; evidence: dependency.\n", pathWord(p.Path), *p.Dependency)
			} else {
				fmt.Fprintf(&b, "Project: %s; evidence: marker path exists, contents not read.\n", pathWord(p.Path))
			}
		case "other_program":
			p := i.Process()
			fmt.Fprintf(&b, "Other program: pid %d; exe %s; cwd %s; evidence: interpreter.\n", p.PID, pathWord(p.Exe), pathWord(p.Cwd))
		}
		if verbose {
			for _, e := range i.Evidence {
				fmt.Fprintf(&b, "  rule %s; source %s; fact %s\n", e.RuleID, e.SourceID, e.Fact)
			}
			if len(i.Caveats) > 0 {
				fmt.Fprintf(&b, "  caveats: %s\n", strings.Join(i.Caveats, ", "))
			}
		}
	}
	fmt.Fprintf(&b, "Other interpreters: %d. Tego cannot tell whether these are agents.\n", s.Counts.Other)
	if verbose {
		fmt.Fprintf(&b, "Counts: running=%d in_run=%d outside_run=%d membership_unknown=%d installed=%d settings=%d project=%d mcp_servers=%d user_units=%d system_units=%d cron_entries=%d other=%d\n", s.Counts.Running, s.Counts.InRun, s.Counts.Outside, s.Counts.Unknown, s.Counts.Installed, s.Counts.Settings, s.Counts.Project, s.Counts.MCP, s.Counts.Units, s.Counts.SystemUnits, s.Counts.Cron, s.Counts.Other)
	}
	if err := Footer(&b, s, verbose); err != nil {
		return err
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func pathWord(p *string) string {
	if p == nil {
		return "unknown"
	}
	return fmt.Sprintf("%q", *p)
}

// Footer cannot be disabled by hints, a pipe, verbosity or check mode.
func Footer(w io.Writer, s Snapshot, full bool) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Scope: %s uid %d; status %s; check %s.\n", s.Mode, s.As.UID, s.Status, s.Check)
	if s.Mode == "advanced" {
		fmt.Fprintf(&b, "Advanced: all users' matching processes; configured units for local passwd accounts; system units and cron; container ids are cgroup suggestions only. Result recipient uid %d.\n", s.As.Recipient)
		fmt.Fprintf(&b, "Program candidates, settings, MCP, project hints and other interpreters cover recipient uid %d only.\n", s.As.Recipient)
	}
	names := []string{}
	for _, r := range s.Rules {
		names = append(names, r.ID+" ("+r.Name+")")
	}
	fmt.Fprintf(&b, "Rules: %s\n", strings.Join(names, ", "))
	read, notRead := 0, 0
	for _, src := range s.Sources {
		read += src.Read
		notRead += src.NotRead
	}
	fmt.Fprintf(&b, "Sources: read %d, not read %d.\n", read, notRead)
	fmt.Fprintf(&b, "Exited during the scan: %d. Kernel threads: %d.\n", s.Counts.Exited, s.Counts.KernelThreads)
	if s.Counts.UnreadablePrograms > 0 {
		fmt.Fprintf(&b, "%d of your processes do not let their program file be read; pids:", s.Counts.UnreadablePrograms)
		for _, pid := range s.UnreadableProgramPIDs {
			fmt.Fprintf(&b, " %d", pid)
		}
		fmt.Fprintf(&b, ". %s\n", UnreadableProgramsWarning)
	}
	for _, src := range s.Sources {
		if !full && src.State != "not-read" && src.State != "partial" {
			continue
		}
		fmt.Fprintf(&b, "Source %s %s %s: %s; read %d, not read %d; reason %s", src.ID, src.Kind, pathWord(src.Locator), src.State, src.Read, src.NotRead, src.Reason)
		if src.State == "not-read" || src.State == "partial" {
			if src.Reason == "unresolved" && src.Kind == "E" {
				b.WriteString("; could not be determined; Tego cannot tell whether these are agents")
			} else {
				b.WriteString("; could not be read; Tego cannot tell whether these are agents")
			}
		}
		if src.Reason == "mode" {
			if src.WritableGroup != nil {
				fmt.Fprintf(&b, "; group %q: %s; chmod g-w", *src.WritableGroup, groupEvidenceWords(src.GroupEvidence))
				if src.Locator != nil {
					fmt.Fprintf(&b, " -- %s", shellword.Quote(*src.Locator))
				}
			} else {
				b.WriteString("; chmod o-w and chmod g-w on this file or folder")
			}
		}
		if src.AccountRepair != "" {
			fmt.Fprintf(&b, "; %s", src.AccountRepair)
		}
		if src.Reason == "owner" {
			b.WriteString("; use a file or folder owned by you or root; ask its owner to copy it or correct its ownership")
		}
		b.WriteByte('\n')
	}
	b.WriteString("Not looked at: ")
	for n, code := range s.Exclusions {
		if n > 0 {
			b.WriteString("; ")
		}
		b.WriteString(exclusionWords(code))
	}
	b.WriteByte('\n')
	if len(s.Limits) > 0 {
		fmt.Fprintf(&b, "Stopped at: %s; remaining scope unknown.\n", strings.Join(s.Limits, ", "))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func exclusionWords(s string) string {
	if w, ok := exclusionTable[s]; ok && w.operator != "" {
		return w.operator
	}
	return s
}

func groupEvidenceWords(code string) string {
	switch code {
	case "accounts-unreadable":
		return "local account database could not be read completely or changed during collection; run the scan again"
	case "accounts-limit":
		return "local account database reached its size limit"
	case "accounts-malformed":
		return "local account database is malformed or truncated"
	case "directory-service":
		return "directory-service or other non-files account source; local evidence is incomplete"
	case "owner-not-local":
		return "owner has no local account entry; directory-service-only accounts are refused"
	case "group-missing":
		return "group has no local database entry; directory-service-only groups are refused"
	case "shared-primary":
		return "another local account has this primary group"
	case "other-member":
		return "group entry lists a member other than the owner"
	case "access-acl":
		return "access ACL is present or could not be checked"
	default:
		return "complete local evidence of a private group is unavailable"
	}
}
