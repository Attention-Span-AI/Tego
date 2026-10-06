// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"bytes"
	"cmp"
	"path"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Bounds of the staged argv read of a guarded exec (ADR 0048 (3)).
const (
	// cmdPrefixArgs and cmdPrefixBytes are the first stage: the pointer array and strings up to the located
	// subcommand, read in one batch. Most decisions end here.
	cmdPrefixArgs  = 32
	cmdPrefixBytes = 8 << 10
	// ptrBatch is the pointers one read of the array covers; segBatch the strings one process_vm_readv covers
	// (IOV_MAX); segMax the bytes of a string's first segment. A longer string is completed on its own.
	ptrBatch = 1024
	segBatch = 1024
	segMax   = 256
	// maxShebangDepth is the interpreters a #! chain can stack before the kernel's exec_binprm answers ELOOP.
	maxShebangDepth = 5
)

// ruleInterpUnresolved marks an exec refused because its #! interpreter's walk failed: the kernel's exec would fail
// the same way, with the walk's errno, and no command rule could be decided on an interpreter that cannot be found.
const ruleInterpUnresolved = "interpreter-unresolved"

// ruleImageUnreadable marks an exec refused in a run with command rules because its image's first bytes could not be
// read (an execute-only file at tier 1, where the supervisor runs as the agent's user): the kernel reads them anyway,
// and could run the file as a #! script of any ruled tool, so no command rule could be decided on it.
const ruleImageUnreadable = "image-unreadable"

// ruleLoaderUnresolved marks an exec of a dynamic loader, run as a command in a run with command rules, whose program
// the supervisor cannot read as the loader will: an option neither glibc's nor musl's loader has, a program named
// with no '/' (glibc searches library paths for it), one whose walk failed, or one that is itself a loader. The
// loader runs its program in-process, with no execve of the program's own, so it is decided here or nowhere.
const ruleLoaderUnresolved = "loader-unresolved"

// ruleLoaderProgram marks an exec of a dynamic loader, run as a command in a run whose images are restricted, whose
// program no exec.allow entry grants: the loader maps it PROT_EXEC after an O_RDONLY open, which no EXECUTE right
// governs, so the image floor is applied to it here.
const ruleLoaderProgram = "loader-program-unmatched"

// execCommand is the command-rule half of an exec decision (ADR 0048 (3)).
type execCommand struct {
	res execmatch.Result
	// argv is what the decision read: argv[0] for an unguarded exec, the prefix or the whole vector else.
	argv []string
	// complete says argv is the whole vector; staged says argv is what the staged read of a guarded exec reached,
	// the record's copy too.
	complete, staged bool
	// unreadable: the verdict depends on argv past the budget, or the vector could not be read.
	unreadable bool
	// interpErr is the errno of a #! interpreter walk that failed.
	interpErr error
	// headless: the image's first bytes could not be read, so its form is unknown.
	headless bool
	// decided: a command rule decided (refused, or admitted a constrained tool).
	decided bool
	// loader is the refusal rule of a directly-invoked dynamic loader whose program could not be decided
	// (ruleLoaderUnresolved, ruleLoaderProgram), or whose program lies in a deny-list run's CODEX_HOME
	// (ruleCodexHomeExec) or hook-state directory (ruleHookStateExec); "" otherwise.
	loader string
	// dropped: an image the exec loads beyond its own, as the walk reached it (a #! interpreter, a directly-invoked
	// loader's program), was written during the run under a write entry (droppedImage, R16b).
	dropped bool
	// walked says the image's form was read: form and stages are the #! chain as binfmt_script reads it, kids each
	// stage's identity as the plane holds it in a pinned run (ADR 0048 (3) P2). guarded is Index.Guarded's answer,
	// which a pin carries as its guard bit; an exec decided on its walk alone is taken as guarded.
	walked, guarded bool
	form            execmatch.Form
	stages          []execmatch.Stage
	kids            []fileID
}

// refuses reports whether the command rules refuse the exec.
func (e execCommand) refuses() bool {
	return e.res.Outcome == execmatch.OutcomeRefused || e.unreadable || e.interpErr != nil || e.headless || e.loader != ""
}

// decideCommand applies the command rules to an exec whose image walk reached a file (ADR 0048 (3)). Every exec of
// a run with command rules reads its names and argv[0]; an exec no interpretation guards reads nothing more. A
// guarded exec reads its argv in stages: the prefix up to the located subcommand, then, only when the decision can
// still change, the whole vector within R16's budget, in batched reads. The image's #! line (read through the walk's
// own descriptor) and each interpreter's walk are facts too, for every exec: any ruled tool can be a #! interpreter,
// which the kernel loads inside the same execve. An image whose first bytes could not be read is refused
// image-unreadable. ok is false when the notification is gone. recordExec asks it of every exec whose walk reached a
// file and that has a line, and of one the image floor did not allow keeps only dropped (supervisor R16b): what the exec loads
// is a fact whatever the floor answers, while the command rules decide only an exec the floor allows. walkOnly, for
// such an exec, stops once the loads are walked, before a guarded tool's staged argv reads and the match, whose answer
// would be thrown away.
func (l *Loop) decideCommand(c *compiled, n *notif, r *reader, q pathQuery, raw string, img execImage, argvAddr uint64, walkOnly bool) (out execCommand, ok bool) {
	ix := c.cmds.Index
	f := execmatch.Facts{
		Path:  raw,
		Image: path.Base(strings.TrimSuffix(img.link, deletedSuffix)),
		ID:    execmatch.ID{Dev: img.id.dev, Ino: img.id.ino}, HasID: img.linked,
	}
	if !q.empty && raw != "" {
		f.Requested = path.Base(raw)
	}
	argv0, complete := r.argvBatched(argvAddr, 1, c.argvMax)
	if n.gone {
		return out, false
	}
	if len(argv0) > 0 {
		f.Argv0 = argv0[0]
	}
	f.Argv, f.ArgvComplete = argv0, complete
	form, stages, kids, dropped, err := l.shebangChain(c, n, img, q.root)
	out.dropped = dropped
	if n.gone {
		return out, false
	}
	if err != nil {
		out.interpErr = err
		return out, true
	}
	f.Form, f.Interp = form, stages
	out.walked, out.guarded, out.form, out.stages, out.kids = true, true, form, stages, kids
	out.argv, out.complete = argv0, complete
	if form == execmatch.FormUnknown {
		out.headless = true
		return out, l.valid(n)
	}
	// A dynamic loader run as a command (the image itself, or the last #! interpreter) runs its program in-process:
	// the program is read as the exec's image (ADR 0048 (3)).
	var lp *loaderProgram
	if loaderImage(ix, &f) {
		var ok bool
		if lp, ok = l.loadedProgram(c, n, r, &f, argvAddr, &out, q.root); !ok {
			return out, false
		}
		if out.loader != "" || out.unreadable {
			return out, true
		}
	}
	if walkOnly {
		return out, true
	}
	// argv[0] can add an interpretation, never remove one (ADR 0048 (2)), and a guard answered with no argv[0] has lost
	// them all: the exec's image may be a multicall binary's hard link that reads argv[0] for its applet. So a vector
	// with no argv[0] read, its pointer array or its string unreadable (a PROT_WRITE mapping faults process_vm_readv
	// while the kernel's own copy succeeds) or past the budget, is refused here, before Guarded, because a guarded image
	// can settle on the empty prefix too. A NULL or empty argv is complete and has no argv[0] to lose.
	if len(argv0) == 0 && !complete {
		out.unreadable = true
		return out, l.valid(n)
	}
	if out.guarded = ix.Guarded(&f); !out.guarded {
		out.res = execmatch.Result{K: len(f.Argv), Final: true}
		return out, true
	}
	for _, stage := range [...]struct{ args, bytes int }{{cmdPrefixArgs, cmdPrefixBytes}, {argvEntries, c.argvMax}} {
		argv, whole := r.argvBatched(argvAddr, stage.args, stage.bytes)
		if n.gone {
			return out, false
		}
		f.Argv, f.ArgvComplete = argv, whole
		lp.refresh(&f)
		out.argv, out.complete, out.staged = argv, whole, true
		out.res = decide.ExecCommand(c.pol.Rules, &f)
		if out.res.Final || whole {
			break
		}
	}
	if !l.valid(n) {
		return out, false
	}
	if !out.res.Final && !out.complete {
		out.unreadable = true
	}
	out.decided = out.res.Outcome != execmatch.OutcomeNone
	return out, true
}

// shebangChain reads a script's #! chain as binfmt_script will (ADR 0048 (3)): the interpreter and its optional
// argument from the image's first line, the interpreter walked as the task walks it (absolute, or relative to the
// task's cwd), and again for an interpreter that is itself a script, up to the kernel's depth. A failed interpreter
// walk is that walk's errno. An image whose head could not be read is FormUnknown, and so is one whose interpreter's
// head could not be read: the kernel reads an interpreter's head too, and could run it as a script in turn. dropped
// says an interpreter the chain reached was written during the run under a write entry (droppedImage): the kernel
// loads it inside the same execve, so it is a file that runs (supervisor R16b).
func (l *Loop) shebangChain(c *compiled, n *notif, img execImage, root *taskRoot) (form execmatch.Form, stages []execmatch.Stage, kids []fileID, dropped bool, err error) {
	if img.head == nil {
		return execmatch.FormUnknown, nil, nil, false, nil
	}
	head := img.head
	// unsure: a walk of the chain passed a directory whose search answer for the task was not sure (execImage.unsure).
	// The task may then be refused EACCES on its way to a head this process read, so a later walk's failure is
	// answered EACCES, never its own errno: an ENOENT there told the task that a script it cannot reach names a
	// missing interpreter.
	unsure := img.unsure
	for depth := 0; depth < maxShebangDepth; depth++ {
		interp, arg, emptyArg, ok := parseShebang(head)
		if !ok {
			break
		}
		if !l.valid(n) {
			return execmatch.FormUnknown, nil, nil, false, nil
		}
		q := pathQuery{tid: n.pid, dirfd: atFDCWD, path: interp, joined: interp, head: true, kid: l.pinner != nil, root: root}.as(agent.LookupFollow)
		next, werr := l.k.ExecImage(q)
		if !l.valid(n) {
			return execmatch.FormUnknown, nil, nil, false, nil
		}
		if werr != nil {
			if unsure {
				werr = refusalErrno
			}
			return execmatch.FormUnknown, nil, nil, dropped, werr
		}
		unsure = unsure || next.unsure
		dropped = dropped || l.droppedImage(c, next)
		stages = append(stages, execmatch.Stage{
			Path: interp, Arg: arg, EmptyArg: emptyArg,
			Image: path.Base(strings.TrimSuffix(next.link, deletedSuffix)),
			ID:    execmatch.ID{Dev: next.id.dev, Ino: next.id.ino}, HasID: next.linked,
		})
		kids = append(kids, next.kid)
		if next.head == nil {
			return execmatch.FormUnknown, nil, nil, dropped, nil
		}
		head = next.head
	}
	if len(stages) == 0 {
		return execmatch.FormDirect, nil, nil, false, nil
	}
	return execmatch.FormScript, stages, kids, dropped, nil
}

// loaderImage reports whether the program the kernel finally runs (the image, or a script's last #! interpreter) is a
// dynamic loader run as a command: by a loader's basename (execmatch.LoaderName) as requested, as walked, or as the
// #! line names it, or by the identity of one of the host's loaders (Index.Loader), which a hard link under another
// name keeps (ADR 0048 (3)). An ELF's shape is not read: a static-pie program, a shared library
// and a loader are all ET_DYN with no PT_INTERP, and a static-pie program takes its first word as an operand, never as
// a program to load. A copy of a loader is a new file, R2's copy residual.
func loaderImage(ix *execmatch.Index, f *execmatch.Facts) bool {
	if f.Form == execmatch.FormScript && len(f.Interp) > 0 {
		st := f.Interp[len(f.Interp)-1]
		return execmatch.LoaderName(st.Path) || execmatch.LoaderName(st.Image) || st.HasID && ix.Loader(st.ID)
	}
	return execmatch.LoaderName(f.Image) || execmatch.LoaderName(f.Requested) || f.HasID && ix.Loader(f.ID)
}

// loaderProgram is where a directly-invoked loader's program operand lies in the vector the loader runs with (the
// exec's argv, or a script's ScriptArgv), and the argv[0] the loader gives it.
type loaderProgram struct {
	i      int
	argv0  string
	script bool
}

// loaderArgv is the vector the loader runs with.
func loaderArgv(f *execmatch.Facts) []string {
	if f.Form == execmatch.FormScript {
		return f.ScriptArgv()
	}
	return f.Argv
}

// refresh rebuilds the program's argv from the loader's vector, after a staged read reads more of it.
func (p *loaderProgram) refresh(f *execmatch.Facts) {
	if p == nil || f.Loaded == nil {
		return
	}
	largv := loaderArgv(f)
	prog := []string{p.argv0}
	if p.i+1 <= len(largv) {
		prog = append(prog, largv[p.i+1:]...)
	}
	f.Loaded.Argv = prog
}

// loadedProgram reads the program a directly-invoked dynamic loader runs (ADR 0048 (3)). The
// loader maps its program and jumps to it with no execve of the program's own, so `ld-linux-x86-64.so.2 /usr/bin/rm
// -rf tree` reached rm with only the loader's exec decided, under the loader's name. The loader's vector is read as
// glibc's and musl's loaders read it (execmatch.LoaderProgram) and the program operand walked as the loader's open
// walks it, from the task's cwd; f.Loaded then carries its name, its walked image and identity, and its argv.
//
// It fails closed where the program cannot be read as the loader will (ruleLoaderUnresolved): an option the loader
// may not have, an operand with no '/' (glibc searches library paths for it), one whose walk fails, and one that is
// itself a loader. An operand past the bound is args-unreadable. In a run whose images are restricted the program
// must be granted as an exec of it would be (ruleLoaderProgram): the loader opens it O_RDONLY and maps it PROT_EXEC,
// which no EXECUTE right governs.
func (l *Loop) loadedProgram(c *compiled, n *notif, r *reader, f *execmatch.Facts, argvAddr uint64, out *execCommand, root *taskRoot) (*loaderProgram, bool) {
	var (
		i     int
		prog  []string
		res   execmatch.LoaderOutcome
		whole bool
	)
	for _, stage := range [...]struct{ args, bytes int }{{cmdPrefixArgs, cmdPrefixBytes}, {argvEntries, c.argvMax}} {
		var argv []string
		argv, whole = r.argvBatched(argvAddr, stage.args, stage.bytes)
		if n.gone {
			return nil, false
		}
		f.Argv, f.ArgvComplete = argv, whole
		out.argv, out.complete, out.staged = argv, whole, true
		i, prog, res = execmatch.LoaderProgram(loaderArgv(f))
		if whole || res != execmatch.LoaderExits {
			break // the operand is read, or an option no loader has is: more words change neither
		}
	}
	switch {
	case res == execmatch.LoaderUnknown:
		out.loader = ruleLoaderUnresolved
		return nil, l.valid(n)
	case res == execmatch.LoaderExits && whole:
		return nil, l.valid(n) // --help, --version, or no program: nothing is loaded
	case res == execmatch.LoaderExits:
		out.unreadable = true // the operand lies past the bound
		return nil, l.valid(n)
	}
	operand := loaderArgv(f)[i]
	lp := &loaderProgram{i: i, argv0: prog[0], script: f.Form == execmatch.FormScript}
	f.Loaded = &execmatch.Loaded{Path: operand, Argv: prog}
	if !strings.Contains(operand, "/") {
		out.loader = ruleLoaderUnresolved
		return lp, l.valid(n)
	}
	if !l.valid(n) {
		return nil, false
	}
	q := pathQuery{tid: n.pid, dirfd: atFDCWD, path: operand, joined: r.resolve(atFDCWD, operand), root: root}.as(agent.LookupFollow)
	if n.gone {
		return nil, false
	}
	pimg, err := l.k.ExecImage(q)
	if !l.valid(n) {
		return nil, false
	}
	if err != nil {
		out.loader = ruleLoaderUnresolved
		return lp, true
	}
	out.dropped = out.dropped || l.droppedImage(c, pimg) // the loader maps it and jumps to it: it is what runs
	f.Loaded.Image = path.Base(strings.TrimSuffix(pimg.link, deletedSuffix))
	f.Loaded.ID, f.Loaded.HasID = execmatch.ID{Dev: pimg.id.dev, Ino: pimg.id.ino}, pimg.linked
	if execmatch.LoaderName(f.Loaded.Image) || execmatch.LoaderName(operand) || f.Loaded.HasID && c.cmds.Index.Loader(f.Loaded.ID) {
		out.loader = ruleLoaderUnresolved
		return lp, true
	}
	// The program is judged on its walk's name for a ".." spelling (execImage.name), as an exec is (decideExec), never on
	// the lexical clean, which names a file the loader does not map.
	named := q.joined
	if pimg.name != "" {
		named = pimg.name
	}
	switch {
	case !c.execUnrestricted:
		if _, ok := c.execGranted(named, pimg, true); !ok {
			out.loader = ruleLoaderProgram
		}
	case c.codexHome != nil && c.inCodexHome(imageWhere(named, pimg, true)):
		// A deny-list run's CODEX_HOME is no place to run from (decideExec): the loader would map a file the agent
		// wrote there, a denied program's copy under another name, with no exec of its own. It is
		// judged where the file lies, confirmed in this view or not.
		out.loader = ruleCodexHomeExec
	case c.hookState != nil && inSpellings(c.hookState, imageWhere(named, pimg, true)):
		out.loader = ruleHookStateExec // the hook-state grant, as the CODEX_HOME's (ADR 0062)
	}
	return lp, true
}

// parseShebang reads a #! line exactly as binfmt_script does (agent.ShebangArgv): only spaces and tabs are trimmed
// from its end, so a CRLF line's '\r' is part of the name the kernel opens, and a NUL ends the name. The name may be
// relative (walked from the task's cwd, as the kernel opens it) or empty (ENOENT, as the kernel's open answers).
// emptyArg is an argument that is there and empty, which the kernel maps as an empty element.
func parseShebang(head []byte) (interp, arg string, emptyArg, ok bool) {
	return agent.ShebangArgv(head)
}

// argvBatched reads up to entries argv elements and budget bytes with batched process_vm_readv calls (ADR 0048 (3)):
// the pointer array in reads of up to 1024 pointers, the strings in batches of up to 1024 segments of up to 256
// bytes, a segment never crossing a page (a fault ends a transfer at the segment it hit), then each string longer
// than its first segment on its own. The budget is the vector's bytes, each element's NUL counted (R7): one element
// may take all of it, so the recorder's per-string bound (argMax) is not applied here. complete reports that the
// vector ended within the bounds and every element was read whole; out holds only whole elements. Reads are
// bracketed (R2).
func (r *reader) argvBatched(addr uint64, entries, budget int) (out []string, complete bool) {
	if addr == 0 {
		return nil, true // a NULL argv is an empty vector to the kernel
	}
	if !r.l.valid(r.n) {
		return nil, false
	}
	var ptrs []uint64
	ended, past := false, false
	start := addr
	words := make([]byte, 8*min(ptrBatch, max(entries, 1)+1))
	for len(ptrs) < entries && !r.n.gone {
		want := min(ptrBatch, entries-len(ptrs)+1)
		got := r.read(addr, words[:want*8])
		if got < 8 {
			break
		}
		for i := 0; i+8 <= got; i += 8 {
			p := leU64(words[i : i+8])
			if p == 0 {
				ended = true
				break
			}
			if len(ptrs) == entries {
				past = true // a pointer past the bound
				break
			}
			ptrs = append(ptrs, p)
		}
		if ended || got < want*8 {
			break
		}
		addr += uint64(got)
	}
	if !ended && !past && len(ptrs) == entries && !r.n.gone {
		// A last batch the ptrBatch cap ended on the bound did not read the word after it: a vector of exactly entries
		// pointers ends in its NULL there, and is whole (R7 refuses past the bound, as the record's read does).
		if r.read(start+8*uint64(entries), words[:8]) == 8 && leU64(words[:8]) == 0 {
			ended = true
		}
	}
	left := budget
	cut := false
	for start := 0; start < len(ptrs) && !cut; start += segBatch {
		batch := ptrs[start:min(start+segBatch, len(ptrs))]
		buf, runs, at := r.readSegments(batch)
		for i, p := range batch {
			if left <= 0 {
				cut = true
				break
			}
			var str string
			whole := false
			if rn := at[i]; rn >= 0 {
				run := runs[rn]
				off := run.off + int(p-run.addr)
				end := run.off + min(run.got, int(segEnd(p)-run.addr))
				if off < end {
					if j := bytes.IndexByte(buf[off:end], 0); j >= 0 {
						str, whole = string(buf[off:off+j]), true
					}
				}
			}
			if !whole {
				var trunc bool
				str, trunc = r.cstring(p, left)
				if r.n.gone || trunc {
					cut = true
					break
				}
			}
			left -= len(str) + 1
			if left < 0 {
				cut = true
				break
			}
			out = append(out, str)
		}
	}
	if !r.l.valid(r.n) {
		return out, false
	}
	return out, ended && !cut && len(out) == len(ptrs)
}

// segEnd is where a string's first segment ends: segMax bytes on, or the end of its page, whichever is first.
func segEnd(p uint64) uint64 { return min(p+segMax, p-p%chunk+chunk) }

// readRun is one contiguous range of the target's memory read for several strings.
type readRun struct {
	addr uint64
	n    int
	off  int // where its bytes start in the buffer
	got  int // how many of them were read
}

// maxRun and maxBatchBytes bound one coalesced range and one batch's buffer.
const (
	maxRun        = 64 << 10
	maxBatchBytes = 1 << 20
)

// readSegments reads the first segment of every string of a batch in as few ranges as their layout allows (ADR
// 0048 C8): a caller's argv strings usually sit back to back, so segments within a page of each other are coalesced
// into one range of at most 64 KiB, and the ranges go to the kernel together, up to 1024 per process_vm_readv. A
// range a fault cuts short reads what precedes the fault; at maps each string to its range, or -1.
func (r *reader) readSegments(batch []uint64) (buf []byte, runs []readRun, at []int) {
	idx := make([]int, len(batch))
	for i := range idx {
		idx[i] = i
	}
	slices.SortFunc(idx, func(a, b int) int { return cmp.Compare(batch[a], batch[b]) })
	at = make([]int, len(batch))
	for _, i := range idx {
		p, e := batch[i], segEnd(batch[i])
		if n := len(runs); n > 0 {
			last := &runs[n-1]
			lastEnd := last.addr + uint64(last.n)
			if p >= last.addr && p <= lastEnd+chunk && e-last.addr <= maxRun {
				last.n = int(max(lastEnd, e) - last.addr)
				at[i] = n - 1
				continue
			}
		}
		runs = append(runs, readRun{addr: p, n: int(e - p)})
		at[i] = len(runs) - 1
	}
	total := 0
	for i := range runs {
		runs[i].off = total
		total += runs[i].n
	}
	buf = make([]byte, total)
	for start := 0; start < len(runs) && !r.n.gone; {
		end, bytesIn := start, 0
		for end < len(runs) && end-start < segBatch && (end == start || bytesIn+runs[end].n <= maxBatchBytes) {
			bytesIn += runs[end].n
			end++
		}
		segs := make([]memSeg, 0, end-start)
		for _, rn := range runs[start:end] {
			segs = append(segs, memSeg{addr: rn.addr, n: rn.n})
		}
		got, err := r.l.k.ReadMemV(r.n.pid, segs, buf[runs[start].off:runs[start].off+bytesIn])
		if err != nil {
			got = 0
		}
		for i := start; i < end; i++ {
			runs[i].got = min(max(got, 0), runs[i].n)
			got -= runs[i].n
		}
		start = end
	}
	return buf, runs, at
}

// commandFields are the command-rule fields of an exec line (ADR 0048 (8)). A sentinel refusal (the argv bound, a #!
// interpreter or image that could not be read, a loader whose program could not be resolved) is not a command-rule
// decision: res may hold the stale decision the staged read matched on the prefix (an allow entry, say), so no
// command_rule/command_list/command_match/command_via is written for it. The overflow refusal
// is a command decision (command_via overflow), not one of these sentinels.
func commandFields(e execCommand) (rule, list, match, via, closureOf string) {
	if e.unreadable || e.interpErr != nil || e.headless || e.loader != "" {
		return "", "", "", "", ""
	}
	res := e.res
	switch {
	case res.Pattern != nil:
		rule = res.Pattern.Entry
	case res.ClosureOf != nil:
		rule = res.ClosureOf.Entry
	case res.Unlisted:
		rule = res.Tool
	}
	if res.ClosureOf != nil {
		closureOf = res.ClosureOf.Entry
	}
	if res.Outcome != execmatch.OutcomeNone {
		list, match, via = res.ListName(), res.MatchName(), res.Via.String()
	}
	return rule, list, match, via, closureOf
}

// commandDecision turns a command-rule refusal into the exec's decision: EACCES, exec-not-allowed under the rule
// (exec.deny[...], exec.ask[...], exec.args[<tool>]), or args-unreadable naming the bound, or the interpreter
// walk's own errno.
func commandDecision(e execCommand) execDecision {
	switch {
	case e.interpErr != nil:
		return execDecision{rule: ruleInterpUnresolved, verdict: record.VerdictRefused, reason: record.ReasonExecNotAllowed, answer: respErrno(lookupErrno(e.interpErr))}
	case e.headless:
		return execDecision{rule: ruleImageUnreadable, verdict: record.VerdictRefused, reason: record.ReasonExecNotAllowed, answer: respErrno(refusalErrno)}
	case e.unreadable:
		return execDecision{rule: ruleArgsUnreadable, verdict: record.VerdictRefused, reason: record.ReasonExecNotAllowed, answer: respErrno(refusalErrno)}
	case e.loader != "":
		return execDecision{rule: e.loader, verdict: record.VerdictRefused, reason: record.ReasonExecNotAllowed, answer: respErrno(refusalErrno)}
	}
	d := execDecision{rule: e.res.Rule(), verdict: record.VerdictRefused, reason: record.ReasonExecNotAllowed, answer: respErrno(refusalErrno)}
	if e.res.List == execmatch.ListAsk && !e.res.Unlisted {
		d.unsupported = true
	}
	return d
}
