// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/grouptrust"
	"github.com/attention-span-ai/tego/internal/scan/catalog"
	"github.com/attention-span-ai/tego/internal/scan/result"
	"github.com/attention-span-ai/tego/internal/watch/sig"
)

// processObservation has only closed identifiers, numeric identity and typed paths.
// Match input (including comm) never escapes readProcess.
type processObservation struct {
	PID, PPID                     int
	UID                           uint32
	Start                         uint64
	Exe, Cwd, SourcePath          string
	RuleID, Name                  string
	Fact                          sig.Fact
	Membership, RunID             string
	Other                         bool
	ContainerRuntime, ContainerID string
}

type processSource struct {
	Path, State, Reason string
	WritableGroup       *string
	GroupEvidence       string
	AccountRepair       string
	Read, NotRead       int
	Critical            bool
}

type processSnapshot struct {
	Processes             []processObservation
	Sources               []processSource
	Read, OtherUID        int
	Exited, KernelThreads int
	UnreadablePIDs        []int
	Usable, Unknown       bool
	Limited               bool
	ByteLimited           bool
}

type processRead struct {
	observation                      processObservation
	sources                          []processSource
	own                              bool
	otherUID                         bool
	critical                         bool
	exited, kernelThread, unreadable bool
}

func procSource(path string, err error, critical bool) processSource {
	if err != nil {
		var parent *parentError
		if errors.As(err, &parent) {
			path = filepath.Join(filepath.Dir(path), parent.relative)
		}
		s := processSource{Path: path, State: "not-read", Reason: fixedReason(err), NotRead: 1, Critical: critical}
		var mode *grouptrust.ModeError
		if errors.As(err, &mode) && mode.Group != "" {
			s.WritableGroup = result.Path(mode.Group)
			s.GroupEvidence = mode.Evidence
			s.AccountRepair = mode.AccountRepair
		}
		return s
	}
	return processSource{Path: path, State: "read", Reason: "none", Read: 1}
}

func readProcesses(ctx context.Context, fs procAccess, root string, uid uint32, rows []catalog.Row) processSnapshot {
	return readProcessesMode(ctx, fs, root, uid, rows, false)
}

func readProcessesMode(ctx context.Context, fs procAccess, root string, uid uint32, rows []catalog.Row, advanced bool) processSnapshot {
	duration := 2 * time.Second
	if advanced {
		duration = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	budget := &budgetProc{procAccess: fs, remaining: processInputBudget}
	fs = budget
	out := processSnapshot{Processes: []processObservation{}, Sources: []processSource{}, UnreadablePIDs: []int{}}
	ids, err := fs.pids(ctx)
	out.Usable = err == nil || len(ids) > 0
	out.Unknown = err != nil
	out.Sources = append(out.Sources, procSource(root, err, true))
	if err == nil {
		out.Sources[0].Read = 0
	} // enumeration is not a second count of process reads
	sourceBytes := 0
	all := make(map[int]processObservation, len(ids))
	matched := map[int]bool{}
	for _, pid := range ids {
		// Keep a row reserved for the unknown remainder; do not silently trim failures.
		if len(out.Sources) >= 2000 || len(matched) >= 512 || ctx.Err() != nil || budget.remaining <= 0 {
			reason := errLimit
			if ctx.Err() != nil {
				reason = ctx.Err()
			}
			out.Sources = append(out.Sources, procSource(root, reason, true))
			out.Unknown = true
			out.Limited = true
			break
		}
		p, e := fs.open(pid)
		if e != nil {
			if processGone(e) {
				out.Exited++
				continue
			}
			out.Sources = append(out.Sources, procSource(filepath.Join(root, strconv.Itoa(pid)), e, true))
			out.Unknown = true
			continue
		}
		locator := filepath.Join(root, strconv.Itoa(pid))
		var got processRead
		if advanced {
			got = readProcessMode(ctx, p, pid, uid, rows, locator, true)
		} else {
			got = readProcess(ctx, p, pid, uid, rows, locator)
		}
		p.close()
		if got.exited {
			out.Exited++
			continue
		}
		if got.kernelThread {
			out.KernelThreads++
			continue
		}
		if got.unreadable && !advanced {
			// A process the caller proves to be Tego's own dashboard is not an unreadable program: nothing was read of it
			// that could be an agent's, and a proof that names it is one a program that is no dashboard cannot make
			// (runlock.DashboardPID). It still counts as an own process that was read.
			if named, ok := ctx.Value(namedProgramKey{}).(func(int) bool); ok && named(pid) {
				got.unreadable, got.sources = false, nil
			}
		}
		cost := 0
		for _, source := range got.sources {
			if source.Reason == "limit" {
				out.Limited = true
			}
			b, _ := json.Marshal(source)
			cost += len(b)
		}
		if len(out.Sources)+len(got.sources) > 2000 || sourceBytes+cost > 400<<10 {
			out.Sources = append(out.Sources, procSource(root, errLimit, true))
			out.Unknown = true
			out.Limited = true
			break
		}
		sourceBytes += cost
		out.Sources = append(out.Sources, got.sources...)
		if got.unreadable {
			out.UnreadablePIDs = append(out.UnreadablePIDs, pid)
		}
		out.Unknown = out.Unknown || got.critical
		if got.otherUID {
			out.OtherUID++
			continue
		}
		if !got.own {
			continue
		}
		if !got.critical {
			out.Read++
		}
		v := got.observation
		if advanced && v.UID != uid {
			v.Other = false
		}
		all[pid] = v
		if v.RuleID != "" {
			matched[pid] = true
		}
	}
	itemBytes := 0
	ancestryIssue := false
	for _, pid := range ids {
		v, ok := all[pid]
		if !ok || v.RuleID == "" && !v.Other {
			continue
		}
		ancestor := v.PPID
		childStart := v.Start
		seen := map[int]bool{pid: true}
		grouped := false
		for depth := 0; ancestor > 0; depth++ {
			parent, ok := all[ancestor]
			if !ok || parent.Start > childStart {
				break
			}
			var ancestryErr error
			if depth >= maxThreads {
				ancestryErr = errLimit
			} else if seen[ancestor] {
				ancestryErr = errChanged
			}
			if ancestryErr != nil {
				out.Unknown = true
				out.Limited = out.Limited || ancestryErr == errLimit
				grouped = false
				if !ancestryIssue {
					out.Sources = append(out.Sources, procSource(root, ancestryErr, true))
					ancestryIssue = true
				}
				break
			}
			seen[ancestor] = true
			if matched[ancestor] && sameSession(v, parent) {
				grouped = true
			}
			childStart = parent.Start
			ancestor = parent.PPID
		}

		if !grouped {
			b, _ := json.Marshal(v)
			if len(out.Processes) >= 512 || itemBytes+len(b) > 500<<10 {
				out.Sources = append(out.Sources, procSource(root, errLimit, true))
				out.Unknown = true
				out.Limited = true
				break
			}
			itemBytes += len(b)
			out.Processes = append(out.Processes, v)
		}
	}
	out.ByteLimited = budget.limited || budget.remaining <= 0
	return out
}

// Scheduling state and flags can change between reads without changing identity.
func sameProcessIdentity(a, b statInfo) bool {
	return a.pid == b.pid && a.ppid == b.ppid && a.start == b.start && a.tty == b.tty && a.comm == b.comm
}

func processGone(err error) bool { return errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) }

func readProcess(ctx context.Context, p processFiles, pid int, uid uint32, rows []catalog.Row, locator string) (out processRead) {
	return readProcessMode(ctx, p, pid, uid, rows, locator, false)
}

func readProcessMode(ctx context.Context, p processFiles, pid int, uid uint32, rows []catalog.Row, locator string, advanced bool) (out processRead) {
	ownerUID := uid
	recipientUID := uid
	selectedThread := 0
	defer func() {
		if out.exited && selectedThread != 0 {
			live, err := anotherLiveTask(ctx, p, pid, selectedThread, ownerUID)
			if live || err != nil {
				if err == nil {
					err = errChanged
				}
				out = processRead{critical: true, sources: []processSource{procSource(filepath.Join(locator, "task"), err, true)}}
			}
		}
		if out.exited {
			out = processRead{exited: true}
		}
	}()
	fail := func(name string, err error, critical bool) {
		if critical && processGone(err) {
			out.exited = true
			return
		}
		// One failed entity count; further reasons are diagnostics, not additional missing processes.
		s := procSource(filepath.Join(locator, name), err, critical)
		for _, prev := range out.sources {
			if prev.NotRead > 0 {
				s.NotRead = 0
				break
			}
		}
		out.sources = append(out.sources, s)
		out.critical = out.critical || critical
	}
	// Directory ownership costs no proc content. Root ownership also covers an
	// own process made non-dumpable; status and the exe refusal decide that case.
	owner, e := p.owner()
	if e != nil {
		fail("status", e, true)
		return out
	}
	// A directory owned by another user is still read once, for its uid line only (never stat, cmdline, exe, cgroup
	// or cwd): proc's owner is the effective uid, so a setuid program run by the caller (real uid the caller's)
	// shows another owner, and nothing else says whose process it is. Such a process is mixed, not foreign.
	foreign := !advanced && owner != uid && owner != 0
	before, e := readStatus(p)
	if e != nil {
		fail("status", e, true)
		return out
	}
	if advanced {
		uid = before.uids[0]
		ownerUID = before.uids[1]
	} else {
		// Basic scope attributes a process to one uid only when all four are one. If none is the caller's it is
		// another user's and is skipped; if some are, it cannot be attributed and the scan cannot call it absent.
		mine, all := false, true
		for _, id := range before.uids {
			mine = mine || id == uid
			all = all && id == uid
		}
		if !mine {
			out.otherUID = true
			return out
		}
		// For a caller that is not root, a mixed process whose proc owner and effective uid are both root is root's:
		// sudo and su run a setuid-root program's code, not the login's, and basic scope already counts root's
		// processes as another user's. A mixed process with another non-root effective uid (a setuid copy) is not.
		if uid != 0 && owner == 0 && before.uids[1] == 0 {
			out.otherUID = true
			return out
		}
		// Root reads every process, so one root owns (proc owner root: sudo and su are real uid the login's, effective
		// root) is judged by its program like any other. Without this the parent of every `sudo tego scan` made the
		// answer uncertain. For any other caller, and for a process owned by another user, it stays uncertain.
		if foreign || !all && !(uid == 0 && owner == 0) {
			fail("status", errOwner, true)
			return out
		}
	}
	stat, e := readStat(p)
	if e != nil {
		fail("stat", e, true)
		return out
	}
	if stat.pid != pid {
		fail("stat", errChanged, true)
		return out
	}
	if stat.flags&0x00200000 != 0 {
		out.kernelThread = true
		return out
	} // Linux PF_KTHREAD.
	leaderExited := stat.state == 'Z' || stat.state == 'X' || stat.state == 'x'
	input := p
	readLocator := locator
	var threadStat statInfo
	var threadOwner uint32
	exe, e := p.link("exe")
	if advanced && errors.Is(e, os.ErrPermission) && !leaderExited {
		fail("exe", e, true)
		return out
	}
	if errors.Is(e, os.ErrPermission) && !leaderExited {
		// Do not infer identity from argv or comm when the program file is hidden.
		after, se := readStatus(p)
		afterStat, ste := readStat(p)
		afterOwner, oe := p.owner()
		_, ee := p.link("exe")
		if se != nil {
			fail("status", se, true)
			return out
		}
		if ste != nil {
			fail("stat", ste, true)
			return out
		}
		if oe != nil {
			fail("status", oe, true)
			return out
		}
		if !errors.Is(ee, os.ErrPermission) || after.uids != before.uids || !sameProcessIdentity(afterStat, stat) || afterOwner != owner {
			if processGone(ee) {
				out.exited = true
			} else {
				fail("stat", errChanged, true)
			}
			return out
		}
		out.unreadable = true
		out.sources = []processSource{{State: "unreadable-program", Reason: "permission", NotRead: 1}}
		return out
	}
	// An exited leader can have root-owned proc metadata while its surviving
	// tasks still belong to the caller. Check those tasks before deciding exit.
	// A privileged read can see a nondumpable process through root-owned proc
	// metadata. Other stable proc owners must match the effective uid. Basic
	// scope retains its existing equal-uid and hidden-program rules.
	validOwner := owner == ownerUID || advanced && owner == 0
	if !validOwner && !leaderExited && !processGone(e) {
		fail("status", errOwner, true)
		return out
	}
	if e != nil {
		fail("exe", e, false)
		// An exited thread-group leader can retain live threads. Read through a pinned
		// task directory, then recheck both the thread and leader identities.
		tids, te := p.tasks(ctx)
		if te != nil {
			fail("task", te, true)
			return out
		}
		for _, tid := range tids {
			if len(out.sources) >= 8 {
				fail("task", errLimit, true)
				break
			}
			if ctx.Err() != nil {
				fail("task", ctx.Err(), true)
				break
			}
			if tid == pid {
				continue
			}
			candidate, ce := p.thread(tid)
			if ce != nil {
				if !processGone(ce) {
					fail("task/"+strconv.Itoa(tid), ce, true)
				}
				continue
			}
			to, oe := candidate.owner()
			if oe != nil || to != ownerUID && to != 0 {
				candidate.close()
				if !processGone(oe) {
					fail("task/"+strconv.Itoa(tid), errOwner, true)
				}
				continue
			}
			ts, se := readStatus(candidate)
			st, ste := readStat(candidate)
			candidateExe, ee := candidate.link("exe")
			if se == nil && oe == nil && ste == nil && (st.state == 'Z' || st.state == 'X' || st.state == 'x') {
				candidate.close()
				continue
			}
			if processGone(se) || processGone(ste) || processGone(ee) {
				candidate.close()
				continue
			}
			var candidateErr error
			for _, e := range []error{se, ste, ee} {
				if e != nil {
					candidateErr = e
					break
				}
			}
			if candidateErr != nil {
				candidate.close()
				fail("task/"+strconv.Itoa(tid), candidateErr, true)
				continue
			}
			if ts.uids == before.uids && (to == owner || owner == 0 && (leaderExited || processGone(e)) && to == ownerUID) && st.pid == tid && st.start >= stat.start {
				input = candidate
				readLocator = filepath.Join(locator, "task", strconv.Itoa(tid))
				threadStat = st
				threadOwner = to
				selectedThread = tid
				exe = candidateExe
				e = nil
				break
			}
			candidate.close()
			fail("task/"+strconv.Itoa(tid), errChanged, true)
		}
		if e != nil {
			// A missing leader program file cannot erase a live task's read failure.
			if out.critical {
				return out
			}
			if stat.state == 'Z' || stat.state == 'X' || stat.state == 'x' {
				out.exited = true
			} else {
				fail("exe", e, true)
			}
			return out
		}
		defer input.close()
	}
	inputFail := func(name string, err error, critical bool) {
		if input != p {
			name = filepath.Join("task", strconv.Itoa(threadStat.pid), name)
		}
		fail(name, err, critical)
	}
	if strings.HasSuffix(exe, " (deleted)") {
		// The kernel marker and a literal name have the same spelling. Keep the
		// observed path; do not invent a basename or a negative identity answer.
		inputFail("exe", errUnsupported, true)
	}
	comm := stat.comm
	if input != p {
		comm = threadStat.comm
	}
	facts := sig.Facts{Exe: exe, Comm: comm}
	fileIdentityRead := false
	argv, e := input.read("cmdline", maxArgvBytes)
	if e == nil {
		facts.Argv, e = parseArgv(argv)
	}
	if e != nil {
		inputFail("cmdline", e, true)
	}
	for _, r := range rows {
		if r.Rule.File != (sig.FileID{}) {
			fileIdentityRead = true
			facts.File, e = input.fileID()
			if e != nil {
				inputFail("exe", e, true)
			}
			break
		}
	}
	v := processObservation{PID: pid, PPID: stat.ppid, UID: uid, Start: stat.start, SourcePath: readLocator, Membership: "unknown"}
	for _, r := range rows {
		if fact, ok := r.Rule.Evidence(facts); ok {
			name, valid := catalog.ObservedName(r.ID)
			if !valid {
				inputFail("cmdline", errSyntax, true)
				continue
			}
			v.RuleID = r.ID
			v.Name = name
			v.Fact = fact
			break
		}
	}

	interpreter := isInterpreter(exe) && (!advanced || uid == recipientUID)
	if v.RuleID != "" || interpreter {
		b, ce := input.read("cgroup", maxProcText)
		var cg cgroupInfo
		if ce == nil {
			cg, ce = parseCgroup(b, uid)
		}
		switch {
		case ce != nil:
			inputFail("cgroup", ce, v.RuleID != "")
		case cg.run != "":
			v.Membership = "in-run"
			v.RunID = cg.run
		default:
			v.Membership = "outside-run"
		}
		if advanced && ce == nil {
			v.ContainerRuntime, v.ContainerID = parseContainer(b)
		}
		v.Other = v.RuleID == "" && interpreter && (stat.tty != 0 || cg.userUnit)
		if v.RuleID != "" || v.Other {
			v.Exe = exe
			// A foreign working folder can name private work and supplies no
			// matching or grouping fact (ADR 0145, B2-3 privacy amendment).
			if !advanced || uid == recipientUID {
				v.Cwd, ce = input.link("cwd")
				if ce != nil {
					inputFail("cwd", ce, false)
				}
			}
		}
	}
	after, e := readStatus(p)
	if e != nil {
		fail("status", e, true)
		return out
	}
	afterStat, e := readStat(p)
	if e != nil {
		fail("stat", e, true)
		return out
	}
	afterOwner, e := p.owner()
	if e != nil {
		fail("status", e, true)
		return out
	}
	afterExe, e := input.link("exe")
	if e != nil {
		fail("exe", e, true)
		return out
	}
	if before.uids != after.uids || afterOwner != owner || !sameProcessIdentity(stat, afterStat) || afterExe != exe {
		fail("stat", errChanged, true)
		return out
	}
	if fileIdentityRead {
		afterFile, fe := input.fileID()
		if fe != nil {
			inputFail("exe", fe, true)
			return out
		}
		if afterFile != facts.File {
			inputFail("exe", errChanged, true)
			return out
		}
	}
	if input != p {
		ts, te := readStatus(input)
		st, se := readStat(input)
		to, oe := input.owner()
		for _, e := range []error{te, se, oe} {
			if e != nil {
				fail("task", e, true)
				return out
			}
		}
		if ts.uids != before.uids || !sameProcessIdentity(st, threadStat) || to != threadOwner {
			fail("task", errChanged, true)
			return out
		}
	}
	if ctx.Err() != nil {
		fail("stat", ctx.Err(), true)
		return out
	}
	out.own = true
	out.observation = v
	out.sources = append(out.sources, processSource{Path: readLocator, State: "read", Reason: "none", Read: 1})
	if len(out.sources) > 1 { // required input failures have no successful entity count
		for _, s := range out.sources {
			if s.Critical {
				out.sources[len(out.sources)-1].Read = 0
				break
			}
		}
	}
	return out
}

// A selected task can exit while its thread group still runs. Count an exit
// only after checking the other pinned tasks; an unreadable live group is a gap.
func anotherLiveTask(ctx context.Context, p processFiles, leader, selected int, uid uint32) (bool, error) {
	tids, err := p.tasks(ctx)
	if processGone(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, tid := range tids {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if tid == leader || tid == selected {
			continue
		}
		candidate, err := p.thread(tid)
		if processGone(err) {
			continue
		}
		if err != nil {
			return false, err
		}
		owner, oe := candidate.owner()
		if oe != nil || owner != uid && owner != 0 {
			candidate.close()
			if processGone(oe) {
				continue
			}
			if oe != nil {
				return false, oe
			}
			return false, errOwner
		}
		st, se := readStat(candidate)
		candidate.close()
		if processGone(se) {
			continue
		}
		if se != nil {
			return false, se
		}
		if st.pid != tid {
			return false, errChanged
		}
		if st.state != 'Z' && st.state != 'X' && st.state != 'x' {
			return true, nil
		}
	}
	return false, nil
}

func isInterpreter(exe string) bool {
	base := filepath.Base(exe)
	switch base {
	case "node", "bun", "deno", "java", "ruby":
		return true
	}
	if !strings.HasPrefix(base, "python") {
		return false
	}
	rest := strings.TrimPrefix(base, "python")
	return rest == "" || strings.Trim(rest, "0123456789.") == ""
}

// A shared ancestor alone cannot establish a session. Keep a child with a
// different purpose or membership so grouping cannot erase an outside finding.
func sameSession(child, parent processObservation) bool {
	return child.UID == parent.UID && child.ContainerRuntime == parent.ContainerRuntime && child.ContainerID == parent.ContainerID && child.Membership != "unknown" && child.Membership == parent.Membership && child.RunID == parent.RunID && (child.Other || child.Name == parent.Name)
}
