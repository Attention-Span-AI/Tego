// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ADR 0047: a mutation in an fs.ask scope (unlink, rmdir, mkdir, rename, symlink, link) is asked, and an approved one
// is made by this process under the task's identity, never continued. The scope grants the run nothing in the kernel
// (SEMANTICS §3.1), so nothing inside the run can make it: the open deputy's own domain and the plane would refuse it.
// What makes the completion race-free is where it acts: each end is the one name in a directory pinned O_PATH by a
// walk made as the task, and every directory a scope governs is one the agent has no right to rename, create in or
// remove from (Landlock at every tier, the plane at tiers 2 and 3), so the pinned directories stay where the person was
// shown they are while the person decides. The completion still checks each pin's place and each name's object again
// before the syscall, which only a process outside the run could have changed.

// mutationArgs are what a mutation's syscall carries besides its names: unlinkat's AT_REMOVEDIR, renameat2's flags,
// mkdir's mode.
type mutationArgs struct {
	flags int
	mode  uint32
}

// mutationEndQuery is one name a mutation acts on, as the task spelled it.
type mutationEndQuery struct {
	dirfd int32
	path  string
}

// mutationQuery is a held mutation as the task asked it.
type mutationQuery struct {
	op     string
	tid    int
	ends   []mutationEndQuery
	args   mutationArgs
	target string // a symlink's stored target, never walked
}

// mutationEnd is one end of a held mutation: the directory the name is made, removed or renamed in, held O_PATH and
// walked as the task, the name, and what the name held when it was pinned.
type mutationEnd struct {
	dir     int
	dirID   fileID
	dirPath string // the directory as this process's view names it, checked by inode
	leaf    string
	present bool
	leafID  fileID
	leafDir bool
}

func (e *mutationEnd) path() string { return filepath.Join(e.dirPath, e.leaf) }

// heldMutation is a mutation pinned for an ask, with the identity it is made under.
type heldMutation struct {
	q     mutationQuery
	ends  []mutationEnd
	creds sys.TaskCreds
	umask int
}

func (h *heldMutation) close(l *Loop) {
	for i := range h.ends {
		l.closeDup(h.ends[i].dir)
	}
}

type askMutationKernel interface {
	PrepareAskMutation(mutationQuery) (*heldMutation, error)
	// CompleteAskMutation makes the mutation; moved reports that a pin no longer named what it was shown as, and
	// nothing was made, and err is otherwise the syscall's own result.
	CompleteAskMutation(*heldMutation) (moved bool, err error)
}

// errKernelAnswers is a pin that found the mutation fails before any permission check (a missing name to remove, a
// name to make that exists): the task's own syscall, continued, gets that answer from the kernel, so nobody is asked.
var errKernelAnswers = errors.New("supervisor: the kernel answers this mutation before its permission check")

// errMutationUnsupported is a spelling or a flag no held completion makes (a trailing slash where the op takes no
// directory, a final "." or "..", AT_EMPTY_PATH, AT_SYMLINK_FOLLOW onto a symlink, RENAME_WHITEOUT): the syscall keeps
// today's path, where the kernel refuses a mutation in a scope that grants nothing.
var errMutationUnsupported = errors.New("supervisor: unsupported held mutation")

// dirOnly reports whether the op acts only on a directory, so a trailing slash on its name changes nothing.
func (q mutationQuery) dirOnly() bool {
	return q.op == record.FSMkdir || (q.op == record.FSUnlink && q.args.flags&unix.AT_REMOVEDIR != 0)
}

func (k sysKernel) PrepareAskMutation(q mutationQuery) (*heldMutation, error) {
	creds, err := sys.ReadTaskCreds(q.tid)
	if err != nil {
		return nil, err
	}
	mask := 0
	if q.op == record.FSMkdir {
		if mask, err = taskUmask(q.tid); err != nil {
			return nil, err
		}
	}
	h := &heldMutation{q: q, creds: creds, umask: mask}
	err = runAskOpenAs(creds, mask, func() error {
		for _, e := range q.ends {
			end, err := pinMutationEnd(q, e)
			if end.dir >= 0 {
				h.ends = append(h.ends, end)
			}
			if err != nil {
				return err
			}
		}
		return mutationState(q, h.ends)
	})
	if err != nil {
		for i := range h.ends {
			_ = k.CloseFD(h.ends[i].dir) // a pin of a mutation nobody is asked about; a failed close leaks nothing reusable
		}
		return nil, err
	}
	return h, nil
}

// pinMutationEnd walks the directory part of e's name as the task's lookup does (walkExec: its root and cwd or dirfd,
// every symlink followed, the parent walk filename_parentat makes) and holds it O_PATH, then reads what the final name
// holds there, never following it.
func pinMutationEnd(q mutationQuery, e mutationEndQuery) (mutationEnd, error) {
	end := mutationEnd{dir: -1}
	parent, leaf, err := mutationLeaf(e.path, q.dirOnly())
	if err != nil {
		return end, err
	}
	fd, _, _, err := walkExec(pathQuery{tid: q.tid, dirfd: e.dirfd, path: parent}, false)
	if err != nil {
		return end, errKernelAnswers // the task's own parent walk fails the same way
	}
	end.dir, end.leaf = fd, leaf
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return end, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return end, errKernelAnswers // ENOTDIR, the kernel's
	}
	if st.Nlink == 0 {
		return end, errKernelAnswers // a removed directory: ENOENT
	}
	end.dirID = fileID{dev: st.Dev, ino: st.Ino}
	link, err := readlinkRaw("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return end, err
	}
	if !strings.HasPrefix(link, "/") || !sameInodeHere(link, &st) {
		return end, errOtherView
	}
	end.dirPath = link
	var leafSt unix.Stat_t
	switch err = unix.Fstatat(fd, leaf, &leafSt, unix.AT_SYMLINK_NOFOLLOW); {
	case err == nil:
		end.present, end.leafID, end.leafDir = true, fileID{dev: leafSt.Dev, ino: leafSt.Ino}, leafSt.Mode&unix.S_IFMT == unix.S_IFDIR
	case errors.Is(err, unix.ENOENT):
	default:
		return end, errKernelAnswers // the name's own lookup fails (EACCES on search, ENAMETOOLONG)
	}
	return end, nil
}

// mutationLeaf splits a mutation's pathname, as the task passed it, into the directory part its walk pins and the one
// name the mutation acts on there, as filename_parentat splits it: trailing slashes are dropped, which only an op on a
// directory accepts (dirOnly; elsewhere errMutationUnsupported), and a name that is "", "." or ".." is never a held
// mutation's (the kernel refuses each before a permission check of its own: EEXIST, EBUSY, EINVAL, ENOTEMPTY, ENOENT).
// The name holds no "/" and no NUL; it is the pinned directory's entry, never walked further.
func mutationLeaf(path string, dirOnly bool) (parent, leaf string, err error) {
	if path == "" || strings.IndexByte(path, 0) >= 0 {
		return "", "", errMutationUnsupported
	}
	if strings.HasSuffix(path, "/") && !dirOnly {
		return "", "", errMutationUnsupported
	}
	parent, leaf = splitFinal(path)
	if leaf == "" || leaf == "." || leaf == ".." {
		return "", "", errMutationUnsupported
	}
	return parent, leaf, nil
}

// mutationState answers, from what each name held at the pin, the mutations the kernel fails before its permission
// check (errKernelAnswers) and the forms no held completion makes (errMutationUnsupported).
func mutationState(q mutationQuery, ends []mutationEnd) error {
	src := &ends[0]
	switch q.op {
	case record.FSUnlink:
		rmdir := q.args.flags&unix.AT_REMOVEDIR != 0
		if !src.present || src.leafDir != rmdir {
			return errKernelAnswers // ENOENT, EISDIR, ENOTDIR
		}
	case record.FSMkdir, record.FSSymlink:
		if src.present {
			return errKernelAnswers // EEXIST
		}
	case record.FSLink:
		if q.args.flags&^unix.AT_SYMLINK_FOLLOW != 0 {
			return errMutationUnsupported // AT_EMPTY_PATH: a descriptor's end
		}
		if !src.present || src.leafDir || ends[1].present {
			return errKernelAnswers // ENOENT, EPERM, EEXIST
		}
		if q.args.flags&unix.AT_SYMLINK_FOLLOW != 0 {
			var st unix.Stat_t
			if err := unix.Fstatat(src.dir, src.leaf, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil || st.Mode&unix.S_IFMT == unix.S_IFLNK {
				return errMutationUnsupported // the followed link's target would be another end
			}
		}
	case record.FSRename:
		f := uint(q.args.flags)
		dst := &ends[1]
		switch {
		case f&^(unix.RENAME_NOREPLACE|unix.RENAME_EXCHANGE) != 0 || f == unix.RENAME_NOREPLACE|unix.RENAME_EXCHANGE:
			return errMutationUnsupported // RENAME_WHITEOUT, or flags the kernel refuses EINVAL
		case !src.present, f&unix.RENAME_NOREPLACE != 0 && dst.present, f&unix.RENAME_EXCHANGE != 0 && !dst.present:
			return errKernelAnswers // ENOENT, EEXIST
		case f&unix.RENAME_EXCHANGE == 0 && dst.present && src.leafDir != dst.leafDir:
			return errKernelAnswers // ENOTDIR, EISDIR
		}
	default:
		return errMutationUnsupported
	}
	return nil
}

func (k sysKernel) CompleteAskMutation(h *heldMutation) (moved bool, err error) {
	err = runAskOpenAs(h.creds, h.umask, func() error {
		for i := range h.ends {
			if !h.ends[i].unchanged() {
				moved = true
				return nil
			}
		}
		q, e := h.q, h.ends
		switch q.op {
		case record.FSUnlink:
			return unix.Unlinkat(e[0].dir, e[0].leaf, q.args.flags&unix.AT_REMOVEDIR)
		case record.FSMkdir:
			return unix.Mkdirat(e[0].dir, e[0].leaf, q.args.mode)
		case record.FSSymlink:
			return unix.Symlinkat(q.target, e[0].dir, e[0].leaf)
		case record.FSLink:
			return unix.Linkat(e[0].dir, e[0].leaf, e[1].dir, e[1].leaf, 0)
		case record.FSRename:
			return unix.Renameat2(e[0].dir, e[0].leaf, e[1].dir, e[1].leaf, uint(q.args.flags))
		}
		return unix.EINVAL
	})
	return moved, err
}

// unchanged reports whether the end's directory is still the pinned one, still linked and still named as the person
// was shown, and its name still holds what it held at the pin (the same object, or nothing).
func (e *mutationEnd) unchanged() bool {
	var st unix.Stat_t
	if unix.Fstat(e.dir, &st) != nil || st.Nlink == 0 || (fileID{dev: st.Dev, ino: st.Ino}) != e.dirID {
		return false
	}
	if link, err := readlinkRaw("/proc/self/fd/" + strconv.Itoa(e.dir)); err != nil || link != e.dirPath {
		return false
	}
	var leaf unix.Stat_t
	err := unix.Fstatat(e.dir, e.leaf, &leaf, unix.AT_SYMLINK_NOFOLLOW)
	if !e.present {
		return errors.Is(err, unix.ENOENT)
	}
	return err == nil && (fileID{dev: leaf.Dev, ino: leaf.Ino}) == e.leafID
}

// askMutation asks a person about a mutation in an fs.ask scope that the run's kernel would refuse (d refused, and by
// no supervisor floor: a floor's refusal on the copied names is final, ADR 0041 D3 (1)), and answers it: the
// supervisor's own completion on the pinned names once approved, a refusal otherwise. It reports whether it answered
// the notification; when it did not (no end in a scope, a form it does not make, a mutation the kernel fails before
// its permission check), the caller's path answers it as before.
func (l *Loop) askMutation(n *notif, r *reader, q mutationQuery, d fsDecided) bool {
	c := l.table.Load()
	rt := c.pol.Rules
	if rt == nil || len(rt.FSAsk) == 0 || d.verdict == record.VerdictAllow || d.floor || l.observing() || r.failed || r.unreadPath != "" {
		return false
	}
	k, ok := l.k.(askMutationKernel)
	if !ok || !l.valid(n) {
		return false
	}
	h, err := k.PrepareAskMutation(q)
	if !l.valid(n) {
		if h != nil {
			h.close(l)
		}
		return true
	}
	if err != nil {
		return false
	}
	defer h.close(l)
	p1, p2 := h.ends[0].path(), ""
	if len(h.ends) > 1 {
		p2 = h.ends[1].path()
	} else if q.op == record.FSSymlink {
		p2 = q.target
	}
	refuse := func(errno unix.Errno, reason record.Reason, rule string, unsupported bool, g *gate.Decision) bool {
		l.respond(n, respErrno(errno))
		l.emitFS(n, r, q.op, p1, p2, 0, fsDecided{rule: rule, verdict: record.VerdictRefused, reason: reason, enforce: true, unsupported: unsupported, gate: g})
		return true
	}
	// Every end in one scope, each governed by the scope itself rather than an entry nested in it.
	var scope *agent.FSRule
	inScope := 0
	for i := range h.ends {
		p := h.ends[i].path()
		rule := fsAskRule(rt, p)
		if rule == nil {
			continue // beneath no scope: this end is decided as before, or makes the mutation cross entries
		}
		near := decide.NearestIn(c.fsResolved, p)
		if near != nil && near.DenyRead {
			return refuse(refusalErrno, record.ReasonReadDenied, near.Name, false, nil)
		}
		if _, v, _ := c.fsVerdictIn(c.fsResolved, p, q.op, 0, q.dirObject()); v == record.VerdictAllow ||
			(near != nil && decide.TrimDir(rule.Governed()) != near.Path && agent.Covers(rule.Governed(), near.Path)) {
			continue
		}
		if scope == nil || scope == rule {
			scope = rule
			inScope++
		}
	}
	if scope == nil {
		return false
	}
	name := scope.RuleName()
	if name == "" {
		name = "fs.ask"
	}
	if inScope != len(h.ends) {
		// ADR 0047 (3): the ends lie in different entries. Refused as the kernel refuses a move it cannot carry rights
		// across (Landlock's REFER), EXDEV, so a tool copies and unlinks instead, each asked where it lands.
		return refuse(unix.EXDEV, reasonFor(q.op), name, true, nil)
	}
	// A person's live block refuses before anyone is asked, as it refuses a held open (liveFS), and again after the
	// answer, which a block added while the person decided outranks.
	if ld, blocked := l.liveMutation(n, r, q.op, h); blocked {
		return refuse(refusalErrno, ld.reason, ld.rule, false, nil)
	}
	for i := range h.ends {
		p := h.ends[i].path()
		if !l.askScopeValid(scope, p) {
			return refuse(refusalErrno, record.ReasonAskUnavailable, name, false, nil)
		}
		// Never a protected target, a directory above one, or any entry's own path or one above it: an approval makes,
		// removes and moves only names no rule is about.
		if t, denied := c.denyWriteTarget(p, true); denied {
			return refuse(refusalErrno, reasonFor(q.op), t.RuleName(), false, nil)
		}
		if t, denied := rt.AskDenyWriteTarget(p, true); denied {
			return refuse(refusalErrno, reasonFor(q.op), t.RuleName(), false, nil)
		}
		for j := range rt.FS {
			if agent.Covers(p, rt.FS[j].Governed()) {
				return refuse(refusalErrno, reasonFor(q.op), rt.FS[j].RuleName(), false, nil)
			}
		}
		// Nor tego's own state (the ledger, the run's runtime directory), inside it or above it, which compile keeps
		// out of every scope it can see and the launcher names beyond the table (Options.OwnState).
		for _, o := range append(slices.Clip(rt.OwnState), l.ownState...) {
			if agent.Covers(o, p) || agent.Covers(p, o) {
				return refuse(refusalErrno, reasonFor(q.op), name, false, nil)
			}
		}
	}
	if rule, why, refused := l.mutationNameRefused(q, h); refused {
		return refuse(refusalErrno, why, rule, false, nil)
	}
	// The gate scores the held names as it scores the agent's own mutation (gateFS); a refusal stands, and an ask
	// carries its score.
	gd := c.gateFS(q.op, p1, p2, 0, h.gateFacts(c), true).gate
	if gd != nil && gd.Verdict == gate.Refused {
		return refuse(refusalErrno, record.ReasonFSGate, gd.Rule, false, gd)
	}
	req := ask.Request{Op: q.op, Target: p1, Rule: name, Hold: ask.HoldMutation, PID: l.tgidOf(n.pid), TID: n.pid}
	if q.op != record.FSUnlink && q.op != record.FSMkdir {
		req.Target2 = p2
	}
	if gd != nil {
		req.Score, req.GateRule = &gd.Score, gd.Rule
	}
	decision, err := l.askHeld(n, req)
	decision.CloseAlternate()
	if n.gone {
		return true
	}
	if err != nil || !decision.Approved {
		return refuse(refusalErrno, record.Reason(askReason(decision, err)), name, false, gd)
	}
	if !l.valid(n) {
		return true
	}
	if !l.askScopeValid(scope, p1) || (p2 != "" && len(h.ends) > 1 && !l.askScopeValid(scope, p2)) {
		return refuse(refusalErrno, record.ReasonAskUnavailable, name, false, gd)
	}
	if ld, blocked := l.liveMutation(n, r, q.op, h); blocked {
		return refuse(refusalErrno, ld.reason, ld.rule, false, gd)
	}
	if rule, why, refused := l.mutationNameRefused(q, h); refused {
		return refuse(refusalErrno, why, rule, false, gd)
	}
	moved, err := k.CompleteAskMutation(h)
	if moved {
		return refuse(refusalErrno, record.ReasonAskUnavailable, name, false, gd)
	}
	l.respond(n, respResult(0, err))
	result := int64(0)
	if err != nil {
		var errno unix.Errno
		if !errors.As(err, &errno) {
			errno = unix.EACCES
		}
		result = -int64(errno)
	}
	if n.gone {
		if err == nil {
			l.metrics.orphaned.Add(1)
		}
		l.emitHumanMutation(n, req, q.op, p1, p2, err == nil, true, nil, gatePayload(gd, false))
		return true
	}
	if l.activity != nil && err == nil {
		l.activity()
	}
	l.emitHumanMutation(n, req, q.op, p1, p2, err == nil, false, &result, gatePayload(gd, false))
	return true
}

// emitHumanMutation writes the line of a mutation a person's answer completed (ADR 0047): authority human, verdict
// allow, the held names, operation_completed (the syscall this process made returned 0), syscall_ret (its result as
// the task got it) and result_unknown when the task's syscall was gone before it was answered. A completed one is not
// written under record: off, whose ask and answer lines already say it; one that failed is.
func (l *Loop) emitHumanMutation(n *notif, req ask.Request, op, p, p2 string, performed, unknown bool, syscallRet *int64, gf GateFields) {
	if !l.table.Load().recording() && performed {
		return
	}
	ev := action(l.event(n, record.KindFS, record.SourceSupervisor), req.Rule, record.VerdictAllow, "")
	ev.PID, ev.Authority = req.PID, record.AuthorityHuman
	l.awaitPrev(n)
	l.emit(ev, struct {
		record.FSPayload
		GateFields
		OperationCompleted bool   `json:"operation_completed"`
		ResultUnknown      bool   `json:"result_unknown,omitempty"`
		SyscallRet         *int64 `json:"syscall_ret,omitempty"`
	}{record.FSPayload{Op: op, Path: p, Path2: p2}, gf, performed, unknown, syscallRet})
}

// liveMutation matches a held mutation's pinned names against the run's live blocks (liveFS): both ends of a rename or a
// link, a symlink's own name but never its stored target. blocked reports a refusal, whose rule and reason d carries.
func (l *Loop) liveMutation(n *notif, r *reader, op string, h *heldMutation) (d fsDecided, blocked bool) {
	ends := make([]fsEnd, len(h.ends))
	for i := range h.ends {
		ends[i] = fsEnd{p: h.ends[i].path()}
	}
	d = l.liveFS(n, r, op, 0, fsDecided{verdict: record.VerdictAllow}, ends...)
	return d, d.enforce
}

// gateFacts is the decision gateFS scores a held mutation's names on: a rename's RENAME_EXCHANGE, and for a rename or
// a link whose gate scores paths beneath a moved directory, which end the pin found to be no directory (settleFS's
// srcNotDir and dstNotDir, read here from what each name held at the pin).
func (h *heldMutation) gateFacts(c *compiled) fsDecided {
	d := fsDecided{verdict: record.VerdictAllow, exchange: h.q.op == record.FSRename && h.q.args.flags&unix.RENAME_EXCHANGE != 0}
	if (h.q.op == record.FSRename || h.q.op == record.FSLink) && len(h.ends) == 2 && c.pol != nil && c.pol.Rules != nil &&
		c.pol.Rules.Gate.ScoresBeneath() {
		d.srcNotDir = h.ends[0].present && !h.ends[0].leafDir
		d.dstNotDir = d.exchange && h.ends[1].present && !h.ends[1].leafDir
	}
	return d
}

// dirObject reports whether the mutation acts on a directory as such (a mkdir, an rmdir), which no name entry decides
// (ADR 0043 D1): what the advisory verdict of a held mutation's end is asked with.
func (q mutationQuery) dirObject() bool {
	return q.op == record.FSMkdir || (q.op == record.FSUnlink && q.args.flags&unix.AT_REMOVEDIR != 0)
}

// mutationNameRefused is ADR 0043's interface 2 (supervisor R15f) for a held mutation, as heldNameRefused is for a held
// open: the completion is made by this process, outside any plane, so at the tiers whose mechanisms decide name entries
// (cgroup and bpflsm, D7) an approval would otherwise make, remove or move a file at a name an entry covers, or move a
// directory so that files beneath it leave an entry's coverage, which the plane, or tier 2's fallback (fallbackMutation,
// nameMove), refuses the agent itself. It names such a refusal per D8, or path-unresolved where a climb cannot decide.
// A file is decided at each end it is made, removed or moved at (D1), a moved directory by what its move does (D5).
// Asked on the pinned ends before any person is, and again once the answer came, against the table then in force.
func (l *Loop) mutationNameRefused(q mutationQuery, h *heldMutation) (rule string, reason record.Reason, refused bool) {
	c := l.table.Load()
	if t := c.tier(); (t != backend.TierCgroup && t != backend.TierBPFLSM) || !c.fsIx.HasNames() || q.dirObject() || len(h.ends) == 0 {
		return "", "", false
	}
	why := reasonFor(q.op)
	src := &h.ends[0]
	if q.op != record.FSRename {
		// An unlink, a symlink's new name, a link's old and new names: each a file's name.
		for i := range h.ends {
			if rule, reason, refused := c.fsIx.NameRefused(h.ends[i].path(), why); refused {
				return rule, reason, true
			}
		}
		return "", "", false
	}
	if len(h.ends) < 2 {
		return "", "", false
	}
	dst := &h.ends[1]
	exchange := q.args.flags&unix.RENAME_EXCHANGE != 0
	// The source's object leaves its name for the destination's, and under RENAME_EXCHANGE the destination's object
	// moves the other way: a file is decided at both names, a directory by NameMoveRefused.
	moves := []struct {
		from, to *mutationEnd
		dir      bool
	}{{src, dst, src.leafDir}}
	if exchange && dst.present {
		moves = append(moves, struct {
			from, to *mutationEnd
			dir      bool
		}{dst, src, dst.leafDir})
	}
	for _, m := range moves {
		if m.dir {
			if rule, reason, refused := c.fsIx.NameMoveRefused(m.from.path(), m.to.path(), true); refused {
				return rule, reason, true
			}
			continue
		}
		for _, p := range [2]string{m.from.path(), m.to.path()} {
			if rule, reason, refused := c.fsIx.NameRefused(p, why); refused {
				return rule, reason, true
			}
		}
	}
	return "", "", false
}
