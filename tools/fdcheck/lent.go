// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strings"
)

// A lent number (ADR 0023 A1, F2, and the 2026-10-19 design-round note) is a descriptor number valid only while
// a lease is out: the parameter of a lender's callback, which the lender's return ends, or a (*sys.Lease).Num()
// in the function that holds the lease. fdcheck does not try to prove that such a number cannot escape, which
// is a question that kept finding new answers. It admits a closed set of uses, and every
// other use is a finding (kind lease):
//
//   - it flows through a conversion, arithmetic, a string concatenation, a field, an index or a slice of what
//     holds it, a slice it bounds, len, cap, min or max, a composite literal, and a pure encoder (strconv's
//     integer formatting, and an x/sys or syscall function that returns no error, such as UnixRights), whose
//     result holds it in turn;
//   - it ends in a comparison, a switch, a read index, an integer parameter of an
//     x/sys or syscall function that returns an error (the kernel uses the number in the call), a parameter in
//     lentSinks (poll's descriptors, sendmsg's rights, a path the kernel resolves at once), a parameter that a
//     module function borrows (its body meets these same rules: a summary), or a call of a lender's own
//     callback parameter (which makes the enclosing function a lender: its callers' callbacks are judged);
//   - it is stored only in a local slot: a variable the function declares, or a field or array element of one
//     reached with no pointer, whose address is never taken and which no function literal captures. A store
//     through a pointer, a slice or a map, into a variable declared outside, into a named result, a return, a
//     send, a goroutine, a function literal that names it, an interface or func value it is passed to, and
//     anything else this list does not name, is a finding.

// lender maps a lender's callback parameter (its index in the signature) to the callback's parameters that
// receive the number.
type lender map[int][]int

// lentState is a world's lenders and borrowed-parameter summaries.
type lentState struct {
	w       *typedWorld
	lease   *types.TypeName // sys.Lease, when the world has sys
	spa     *types.Struct   // syscall.SysProcAttr's struct
	derived map[*types.Func]lender
	changed bool // a derived lender was found or extended since the last look

	final   map[paramKey]bool // settled summaries
	solving map[paramKey]bool // the working set of the summary being solved
}

// paramKey is one parameter of a module function; idx -1 is a method's receiver.
type paramKey struct {
	fn  *types.Func
	idx int
}

type violation struct {
	at   ast.Node
	what string
}

// Root lenders' signatures, built from the universe so that any type with the shape is one: syscall.RawConn's
// Control, Read and Write (and every implementation), and sys's Borrow (on *sys.FD, sys.Lender, and any type that
// wraps one under that name and shape).
var (
	errorType  = types.Universe.Lookup("error").Type()
	controlSig = sigOf(tupleOf(sigOf(tupleOf(types.Typ[types.Uintptr]), nil)), tupleOf(errorType))
	rwSig      = sigOf(tupleOf(sigOf(tupleOf(types.Typ[types.Uintptr]), tupleOf(types.Typ[types.Bool]))), tupleOf(errorType))
	borrowSig  = sigOf(tupleOf(sigOf(tupleOf(types.Typ[types.Int]), tupleOf(errorType))), tupleOf(errorType))
	// sys's ProcPath lends the number as the path "/proc/self/fd/N", which names it as surely.
	procPathSig = sigOf(tupleOf(sigOf(tupleOf(types.Typ[types.String]), tupleOf(errorType))), tupleOf(errorType))
)

func tupleOf(ts ...types.Type) *types.Tuple {
	vs := make([]*types.Var, len(ts))
	for i, t := range ts {
		vs[i] = types.NewParam(token.NoPos, nil, "", t)
	}
	return types.NewTuple(vs...)
}

func sigOf(params, results *types.Tuple) *types.Signature {
	return types.NewSignatureType(nil, nil, nil, params, results, false)
}

// rootFuncLenders are the module's lending functions: sys.FileDo, and internal/bpf's leased cilium borrows.
var rootFuncLenders = map[string]lender{
	pathSys + ".FileDo":                    {1: {0}},
	modulePath + "/internal/bpf.ProgramFD": {1: {0}},
	modulePath + "/internal/bpf.MapFD":     {1: {0}},
}

// lentSinks are the non-integer parameters of the standard library's and x/sys's calls that take a lent number,
// or what encodes one, and keep nothing past the call: poll's descriptors, the SCM_RIGHTS message sendmsg
// passes (the kernel takes the files, not the numbers), and the path of a call that resolves it at once
// (/proc/self/fd/N). A path a call stores (symlink's target) is not one.
var lentSinks = map[string]map[int]bool{
	pathUnix + ".Poll":             {0: true},
	pathUnix + ".Ppoll":            {0: true},
	pathUnix + ".Sendmsg":          {2: true},
	pathUnix + ".SendmsgN":         {2: true},
	pathSyscall + ".Sendmsg":       {2: true},
	pathSyscall + ".SendmsgN":      {2: true},
	"(*net.UnixConn).WriteMsgUnix": {1: true},
	pathUnix + ".Readlink":         {0: true},
	"os.Readlink":                  {0: true}, // not os.Open or os.Stat: a File keeps its name, a FileInfo its base, "N"
	pathUnix + ".Readlinkat":       {1: true},
	pathUnix + ".Open":             {0: true},
	pathUnix + ".Openat":           {1: true},
	pathUnix + ".Openat2":          {1: true},
	pathUnix + ".Stat":             {0: true},
	pathUnix + ".Lstat":            {0: true},
	pathUnix + ".Fstatat":          {1: true},
	pathUnix + ".Statx":            {1: true},
	pathUnix + ".Access":           {0: true},
	pathUnix + ".Faccessat":        {1: true},
	pathUnix + ".Faccessat2":       {1: true},
	pathSyscall + ".Exec":          {0: true}, // execve resolves the path at once: a failed exec returns, kept nothing
	pathUnix + ".Exec":             {0: true},
	"strconv.Itoa":                 nil, // encoders: their result holds the number
	"strconv.FormatInt":            nil,
	"strconv.FormatUint":           nil,
}

func newLentState(w *typedWorld) *lentState {
	ls := &lentState{w: w, derived: map[*types.Func]lender{}, final: map[paramKey]bool{}}
	if p := w.byPath[pathSys]; p != nil {
		ls.lease, _ = p.types.Scope().Lookup("Lease").(*types.TypeName)
	}
	if p := w.std[pathSyscall]; p != nil {
		if tn, ok := p.Scope().Lookup("SysProcAttr").(*types.TypeName); ok {
			ls.spa, _ = tn.Type().Underlying().(*types.Struct)
		}
	}
	return ls
}

// isSysProcAttr is whether st is syscall.SysProcAttr's struct, or one identical to it (fields, names and types;
// tags aside), which a conversion turns into SysProcAttr.
func (ls *lentState) isSysProcAttr(st *types.Struct) bool {
	return ls.spa != nil && st != nil && types.IdenticalIgnoreTags(st, ls.spa)
}

// lenderOf is whether fn lends a number to a callback: a root (by shape or by name) or a derived lender.
func (ls *lentState) lenderOf(fn *types.Func) (lender, bool) {
	fn = fn.Origin()
	if isMethod(fn) {
		switch fn.Name() {
		case "Control":
			if types.Identical(fn.Type(), controlSig) {
				return lender{0: {0}}, true
			}
		case "Read", "Write":
			if types.Identical(fn.Type(), rwSig) {
				return lender{0: {0}}, true
			}
		case "Borrow":
			if types.Identical(fn.Type(), borrowSig) {
				return lender{0: {0}}, true
			}
		case "ProcPath":
			if types.Identical(fn.Type(), procPathSig) {
				return lender{0: {0}}, true
			}
		}
	} else if l, ok := rootFuncLenders[pkgPath(fn)+"."+fn.Name()]; ok {
		return l, true
	}
	if l, ok := ls.derived[fn]; ok {
		return l, true
	}
	// A call through an interface may reach a derived lender: an interface method of a derived lender's name and
	// signature lends what that lender lends (every such lender's, merged), failing closed.
	if isMethod(fn) {
		if _, iface := fn.Type().(*types.Signature).Recv().Type().Underlying().(*types.Interface); iface {
			var out lender
			for d, l := range ls.derived {
				if d.Name() != fn.Name() || !types.Identical(d.Type(), fn.Type()) {
					continue
				}
				if out == nil {
					out = lender{}
				}
				for cb, args := range l {
					for _, a := range args {
						if !containsInt(out[cb], a) {
							out[cb] = append(out[cb], a)
						}
					}
					sort.Ints(out[cb])
				}
			}
			if out != nil {
				return out, true
			}
		}
	}
	return nil, false
}

// note records that fn passes its callback parameter cb the lent number as that callback's parameter arg: fn
// is a lender, and its callers' callbacks are judged.
func (ls *lentState) note(fn *types.Func, cb, arg int) {
	fn = fn.Origin()
	l := ls.derived[fn]
	if l == nil {
		l = lender{}
		ls.derived[fn] = l
	}
	if !containsInt(l[cb], arg) {
		l[cb] = append(l[cb], arg)
		sort.Ints(l[cb])
		ls.changed = true
	}
}

func containsInt(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// derive finds the derived lenders: every lender call's callback is judged (in exempt files too: sys.FileDo's own
// body), and a callback that calls its enclosing function's callback parameter with the number makes that
// function a lender. It repeats over every package until no lender is added, so a lender's wrapper's wrapper is
// found, in any package.
func (ls *lentState) derive(pkgs []*typedPkg) {
	for {
		ls.changed = false
		for _, p := range pkgs {
			ls.deriveIn(p)
		}
		if !ls.changed {
			return
		}
	}
}

// deriveIn judges every lender call in p's function declarations once, for the lenders it derives.
func (ls *lentState) deriveIn(p *typedPkg) {
	for _, f := range p.files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fd, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if fn, _ := calleeIn(p.info, call); fn != nil {
						if l, ok := ls.lenderOf(fn); ok {
							ls.judgeCall(p, call, l, fd)
						}
					}
				}
				return true
			})
		}
	}
}

// judgeCall judges a lender call's callbacks: a function literal by the lent-number rules, a module function or
// concrete method value by its summary, the enclosing function's own callback parameter by making that function a
// lender, and anything else (a func variable, a field, a call's result, an interface method value) as a callback
// fdcheck cannot follow.
func (ls *lentState) judgeCall(p *typedPkg, call *ast.CallExpr, l lender, encl *ast.FuncDecl) []violation {
	shift := 0
	if _, sel := calleeIn(p.info, call); sel != nil && sel.Kind() == types.MethodExpr {
		shift = 1 // T.M(recv, args...): the receiver is the first argument
	}
	var out []violation
	cbs := make([]int, 0, len(l))
	for cb := range l {
		cbs = append(cbs, cb)
	}
	sort.Ints(cbs)
	for _, cb := range cbs {
		if cb+shift >= len(call.Args) {
			continue
		}
		out = append(out, ls.judgeCallback(p, call.Args[cb+shift], l[cb], encl)...)
	}
	return out
}

func (ls *lentState) judgeCallback(p *typedPkg, arg ast.Expr, lent []int, encl *ast.FuncDecl) []violation {
	arg = ast.Unparen(arg)
	if fl, ok := arg.(*ast.FuncLit); ok {
		var seeds []*types.Var
		i := 0
		for _, f := range fl.Type.Params.List {
			n := len(f.Names)
			if n == 0 {
				n = 1
			}
			for k := 0; k < n; k++ {
				if containsInt(lent, i) && k < len(f.Names) {
					if v, ok := p.info.Defs[f.Names[k]].(*types.Var); ok {
						seeds = append(seeds, v)
					}
				}
				i++
			}
		}
		j := ls.newJudge(p, fl.Body, fl.Type, nil, false)
		j.encl = encl
		j.carriers = map[*types.Var]bool{}
		for _, v := range seeds {
			j.carriers[v] = true
		}
		return j.run()
	}
	if fn := staticFunc(p.info, arg); fn != nil {
		if _, ok := ls.w.funcs[fn]; ok {
			for _, i := range lent {
				if !ls.borrowed(fn, i) {
					return []violation{{arg, "the callback " + fn.Name() + " keeps the number it is lent, or passes it where fdcheck cannot follow"}}
				}
			}
			return nil
		}
		return []violation{{arg, "a lender's callback " + fn.Name() + " that has no body in the module, which fdcheck cannot follow"}}
	}
	if encl != nil {
		if q := ls.callbackParam(p.info, arg, encl); q >= 0 {
			if fn, ok := p.info.Defs[encl.Name].(*types.Func); ok {
				for _, i := range lent {
					ls.note(fn, q, i)
				}
				return nil
			}
		}
	}
	return []violation{{arg, "a lender's callback that is not a function literal or a module function, which fdcheck cannot follow"}}
}

// staticFunc is the module or library function a callback expression names: a function, a qualified function,
// or a concrete method value; nil for anything else (a variable, a field, an interface method, a method
// expression, an instantiation).
func staticFunc(info *types.Info, e ast.Expr) *types.Func {
	switch x := e.(type) {
	case *ast.Ident:
		fn, _ := info.Uses[x].(*types.Func)
		if fn != nil && !isMethod(fn) {
			return fn.Origin()
		}
	case *ast.SelectorExpr:
		if sel := info.Selections[x]; sel != nil {
			if sel.Kind() != types.MethodVal {
				return nil
			}
			fn, _ := sel.Obj().(*types.Func)
			if fn == nil {
				return nil
			}
			if _, iface := fn.Type().(*types.Signature).Recv().Type().Underlying().(*types.Interface); iface {
				return nil
			}
			return fn.Origin()
		}
		fn, _ := info.Uses[x.Sel].(*types.Func)
		if fn != nil && !isMethod(fn) {
			return fn.Origin()
		}
	}
	return nil
}

// callbackParam is the index of encl's parameter that e names, when it is a func-typed parameter encl never
// assigns or takes the address of; otherwise -1.
func (ls *lentState) callbackParam(info *types.Info, e ast.Expr, encl *ast.FuncDecl) int {
	id, ok := ast.Unparen(e).(*ast.Ident)
	if !ok {
		return -1
	}
	v, ok := info.Uses[id].(*types.Var)
	if !ok {
		return -1
	}
	if _, fn := v.Type().Underlying().(*types.Signature); !fn {
		return -1
	}
	idx, i := -1, 0
	for _, f := range encl.Type.Params.List {
		n := len(f.Names)
		if n == 0 {
			n = 1
		}
		for k := 0; k < n; k++ {
			if k < len(f.Names) && info.Defs[f.Names[k]] == v {
				idx = i
			}
			i++
		}
	}
	if idx < 0 || encl.Body == nil {
		return -1
	}
	touched := false
	ast.Inspect(encl.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for _, l := range x.Lhs {
				if lid, ok := ast.Unparen(l).(*ast.Ident); ok && info.Uses[lid] == v {
					touched = true
				}
			}
		case *ast.UnaryExpr:
			if uid, ok := ast.Unparen(x.X).(*ast.Ident); ok && x.Op == token.AND && info.Uses[uid] == v {
				touched = true
			}
		}
		return !touched
	})
	if touched {
		return -1
	}
	return idx
}

// borrowed is whether module function fn's parameter idx (-1: the receiver) borrows what it is passed: its uses
// in fn's body meet the lent-number rules. Summaries are solved together as a greatest fixed point: every
// parameter a solve reaches is taken to borrow until its body shows otherwise, so recursion passes and a use that
// keeps the number anywhere along a chain fails the chain.
func (ls *lentState) borrowed(fn *types.Func, idx int) bool {
	k := paramKey{fn.Origin(), idx}
	if v, ok := ls.final[k]; ok {
		return v
	}
	if ls.solving != nil {
		if v, ok := ls.solving[k]; ok {
			return v
		}
		ls.solving[k] = true
		return true
	}
	ls.solving = map[paramKey]bool{k: true}
	for {
		changed, n := false, len(ls.solving)
		var keys []paramKey
		for kk := range ls.solving {
			keys = append(keys, kk)
		}
		for _, kk := range keys {
			if ls.solving[kk] && !ls.judgeParam(kk) {
				ls.solving[kk] = false
				changed = true
			}
		}
		if !changed && len(ls.solving) == n {
			break
		}
	}
	for kk, v := range ls.solving {
		ls.final[kk] = v
	}
	v := ls.solving[k]
	ls.solving = nil
	return v
}

// judgeParam judges one parameter's uses in its function's body (summary mode: any violation decides).
func (ls *lentState) judgeParam(k paramKey) bool {
	d, ok := ls.w.funcs[k.fn]
	if !ok {
		return false
	}
	sig := k.fn.Type().(*types.Signature)
	var v *types.Var
	switch {
	case k.idx < 0:
		v = sig.Recv()
	case k.idx < sig.Params().Len():
		v = sig.Params().At(k.idx)
	default:
		return false
	}
	if v == nil || v.Name() == "" || v.Name() == "_" {
		return true // an unnamed parameter is never used
	}
	j := ls.newJudge(d.pkg, d.decl.Body, d.decl.Type, d.decl.Recv, true)
	j.carriers = map[*types.Var]bool{v: true}
	return len(j.run()) == 0
}

// judge is one function body's lent-number analysis.
type judge struct {
	ls      *lentState
	info    *types.Info
	body    *ast.BlockStmt
	encl    *ast.FuncDecl // callback mode: the declaration a callback literal is in
	summary bool          // a summary: the first violation decides, and no lender is derived
	release bool          // a released number (F3): its one admitted end is a taker's argument
	parents map[ast.Node]ast.Node
	locals  map[*types.Var]bool // the body's own variables and the function's parameters and receiver
	results map[*types.Var]bool // named results, which leave the function
	escaped map[*types.Var]bool // locals whose storage something else may reach
	seeds   map[ast.Node]bool   // expressions that are lent numbers themselves ((*sys.Lease).Num())

	carriers map[*types.Var]bool
	bad      map[ast.Node]string
	order    []ast.Node
	takers   []*ast.CallExpr // release mode: the taker calls the number reaches
}

func (ls *lentState) newJudge(p *typedPkg, body *ast.BlockStmt, ft *ast.FuncType, recv *ast.FieldList, summary bool) *judge {
	j := &judge{ls: ls, info: p.info, body: body, summary: summary, parents: map[ast.Node]ast.Node{},
		locals: map[*types.Var]bool{}, results: map[*types.Var]bool{}, escaped: map[*types.Var]bool{},
		seeds: map[ast.Node]bool{}}
	fields := func(fl *ast.FieldList, into map[*types.Var]bool) {
		if fl == nil {
			return
		}
		for _, f := range fl.List {
			for _, n := range f.Names {
				if v, ok := p.info.Defs[n].(*types.Var); ok {
					into[v] = true
				}
			}
		}
	}
	fields(recv, j.locals)
	if ft != nil {
		fields(ft.Params, j.locals)
		fields(ft.Results, j.results)
	}
	if body == nil {
		return j
	}
	var stack []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) > 0 {
			j.parents[n] = stack[len(stack)-1]
		}
		stack = append(stack, n)
		return true
	})
	// The body's own variables, and those of the callbacks nested in it that a synchronous lender runs before it
	// returns (inline), with their parameters and named results.
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			if !j.inline(x) {
				return false
			}
			fields(x.Type.Params, j.locals)
			fields(x.Type.Results, j.results)
		case *ast.Ident:
			if v, ok := p.info.Defs[x].(*types.Var); ok && !v.IsField() {
				j.locals[v] = true
			}
		}
		return true
	})
	// What another holder can reach: a local a nested literal names (captured, unless the literal is an inline
	// callback), whose address is taken, whose array is sliced, or on which a pointer method is called.
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			if j.inline(x) {
				return true
			}
			ast.Inspect(x.Body, func(m ast.Node) bool {
				if id, ok := m.(*ast.Ident); ok {
					if v, ok := p.info.Uses[id].(*types.Var); ok && j.locals[v] {
						j.escaped[v] = true
					}
				}
				return true
			})
			return false
		case *ast.UnaryExpr:
			if x.Op == token.AND {
				if v := j.root(x.X); v != nil {
					j.escaped[v] = true
				}
			}
		case *ast.SliceExpr:
			if _, arr := typeUnder(p.info, x.X).(*types.Array); arr {
				if v := j.root(x.X); v != nil {
					j.escaped[v] = true
				}
			}
		case *ast.SelectorExpr:
			if sel := p.info.Selections[x]; sel != nil && sel.Kind() == types.MethodVal {
				if fn, ok := sel.Obj().(*types.Func); ok {
					if _, ptrRecv := fn.Type().(*types.Signature).Recv().Type().(*types.Pointer); ptrRecv {
						if _, ptr := typeUnder(p.info, x.X).(*types.Pointer); !ptr {
							if v := j.root(x.X); v != nil {
								j.escaped[v] = true
							}
						}
					}
				}
			}
		}
		return true
	})
	return j
}

func typeUnder(info *types.Info, e ast.Expr) types.Type {
	t := info.TypeOf(e)
	if t == nil {
		return nil
	}
	return t.Underlying()
}

// syncLenders are the lenders whose callback runs before they return, by contract: a RawConn's Control, Read and
// Write, sys's Borrow (*sys.FD's and the sys.Lender interface's), sys.FileDo and internal/bpf's ProgramFD and
// MapFD. A derived lender, or another type of a root's shape, may keep its callback, so it is not one.
func syncLender(fn *types.Func) (cb int, ok bool) {
	fn = fn.Origin()
	switch path, name := pkgPath(fn), fn.Name(); {
	case isMethod(fn) && path == pathSyscall && (name == "Control" || name == "Read" || name == "Write"):
		if n, isNamed := deref(fn.Type().(*types.Signature).Recv().Type()).(*types.Named); isNamed && n.Obj().Name() == "RawConn" {
			return 0, true
		}
	case isMethod(fn) && path == pathSys && (name == "Borrow" || name == "ProcPath"):
		return 0, true
	case !isMethod(fn):
		if l, ok := rootFuncLenders[path+"."+name]; ok {
			for cb := range l {
				return cb, true
			}
		}
	}
	return 0, false
}

// inline is whether a function literal is the callback of a synchronous lender's call: it runs while the
// enclosing function waits, so a lent number it names is used there, not captured (the ADR's loop lease with a
// Borrow per event, or two Borrows nested).
func (j *judge) inline(fl *ast.FuncLit) bool {
	call, ok := j.parents[fl].(*ast.CallExpr)
	if !ok || call.Fun == fl {
		return false
	}
	fn, sel := calleeIn(j.info, call)
	if fn == nil {
		return false
	}
	cb, ok := syncLender(fn)
	if !ok {
		return false
	}
	if sel != nil && sel.Kind() == types.MethodExpr {
		cb++
	}
	return cb < len(call.Args) && ast.Unparen(call.Args[cb]) == fl
}

// root is the local whose own storage e names: the variable, or a field or array element reached from it with no
// pointer; nil otherwise.
func (j *judge) root(e ast.Expr) *types.Var {
	switch x := ast.Unparen(e).(type) {
	case *ast.Ident:
		if v, ok := j.info.ObjectOf(x).(*types.Var); ok && j.locals[v] {
			return v
		}
	case *ast.SelectorExpr:
		sel := j.info.Selections[x]
		if sel == nil || sel.Kind() != types.FieldVal || sel.Indirect() {
			return nil
		}
		if _, ptr := typeUnder(j.info, x.X).(*types.Pointer); ptr {
			return nil
		}
		return j.root(x.X)
	case *ast.IndexExpr:
		if _, arr := typeUnder(j.info, x.X).(*types.Array); arr {
			return j.root(x.X)
		}
	}
	return nil
}

// slot is whether a store's target is a local slot (or the blank identifier), and its root variable.
func (j *judge) slot(t ast.Expr) (*types.Var, bool) {
	if id, ok := ast.Unparen(t).(*ast.Ident); ok && id.Name == "_" {
		return nil, true
	}
	v := j.root(t)
	if v == nil || j.escaped[v] || j.results[v] {
		return nil, false
	}
	return v, true
}

// run judges the body until the carriers settle, and returns the violations in source order.
func (j *judge) run() []violation {
	if j.body == nil {
		return nil
	}
	for {
		n := len(j.carriers)
		j.bad, j.order, j.takers = map[ast.Node]string{}, nil, nil
		j.walk()
		if j.summary && len(j.order) > 0 {
			break
		}
		if len(j.carriers) == n {
			break
		}
	}
	sort.Slice(j.order, func(a, b int) bool { return j.order[a].Pos() < j.order[b].Pos() })
	out := make([]violation, len(j.order))
	for i, n := range j.order {
		out[i] = violation{n, j.bad[n]}
	}
	return out
}

func (j *judge) violate(n ast.Node, what string) {
	if j.release {
		what = strings.Replace(what, "a lent number", "a released number", 1) + " (F3: a released number is only a taker's argument)"
	}
	if _, ok := j.bad[n]; !ok {
		j.bad[n] = what
		j.order = append(j.order, n)
	}
}

func (j *judge) walk() {
	ast.Inspect(j.body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			if j.inline(x) {
				return true // run before the lender returns: its uses are judged as the body's own
			}
			ast.Inspect(x.Body, func(m ast.Node) bool {
				if id, ok := m.(*ast.Ident); ok {
					if v, ok := j.info.Uses[id].(*types.Var); ok && j.carriers[v] {
						j.violate(x, "a lent number captured by a function literal, which may run after the lease")
					}
				}
				return true
			})
			return false
		case *ast.Ident:
			if v, ok := j.info.Uses[x].(*types.Var); ok && j.carriers[v] {
				j.climb(x)
			}
		case *ast.CallExpr:
			if j.seeds[x] {
				j.climb(x)
			}
		}
		return true
	})
}

// climb follows a carrier up the expression it is in until a use ends it.
func (j *judge) climb(e ast.Node) {
	cur := e
	for i := 0; i < 64; i++ {
		next, ok := j.step(j.parents[cur], cur)
		if !ok {
			return
		}
		cur = next
	}
	j.violate(cur, "a lent number in an expression fdcheck does not follow")
}

// step classifies the use of a carrier child in its parent p: it either goes on (the parent holds the number
// too), or ends, as an admitted use or a violation.
func (j *judge) step(p, child ast.Node) (ast.Node, bool) {
	switch x := p.(type) {
	case nil:
		j.violate(child, "a lent number used where fdcheck does not follow it")
	case *ast.ParenExpr, *ast.StarExpr, *ast.TypeAssertExpr, *ast.CompositeLit:
		return p, true
	case *ast.KeyValueExpr:
		if cl, ok := j.parents[x].(*ast.CompositeLit); ok {
			return cl, true
		}
		j.violate(x, "a lent number used where fdcheck does not follow it")
	case *ast.SelectorExpr:
		sel := j.info.Selections[x]
		switch {
		case sel != nil && sel.Kind() == types.FieldVal:
			return p, true
		case sel != nil && sel.Kind() == types.MethodVal:
			if call, ok := j.parents[x].(*ast.CallExpr); ok && call.Fun == x {
				if j.inGo(call) {
					j.violate(call, "a lent number handed to a goroutine, which outlives the lease")
					return nil, false
				}
				fn, _ := sel.Obj().(*types.Func)
				if fn != nil {
					if _, ok := j.ls.w.funcs[fn.Origin()]; ok && j.borrowed(fn, -1) {
						return nil, false
					}
				}
				j.violate(call, "a lent number as the receiver of "+sel.Obj().Name()+", which fdcheck cannot follow")
				return nil, false
			}
			j.violate(x, "a lent number's method taken as a value")
		default:
			j.violate(x, "a lent number used where fdcheck does not follow it")
		}
	case *ast.IndexExpr:
		if x.X == child {
			return p, true
		}
		if j.storeTarget(x) {
			j.violate(x, "a lent number as the key or index of a store, which keeps it")
		}
	case *ast.SliceExpr:
		return p, true // of what holds it, or by a bound: the slice's length or capacity is then the number
	case *ast.UnaryExpr:
		if x.Op == token.AND {
			j.violate(x, "the address of a lent number, through which it outlives the lease")
		} else if carryingUnary[x.Op] {
			return p, true
		}
	case *ast.BinaryExpr:
		if endingBinary[x.Op] {
			return nil, false // a comparison's result is a bool
		}
		return p, true
	case *ast.CallExpr:
		return j.callArg(x, child)
	case *ast.AssignStmt:
		for _, l := range x.Lhs {
			if l == child {
				return nil, false // a store into the carrier's own (local) storage
			}
		}
		var targets []ast.Expr
		if len(x.Lhs) == len(x.Rhs) {
			for i, r := range x.Rhs {
				if r == child {
					targets = append(targets, x.Lhs[i])
				}
			}
		} else {
			targets = x.Lhs // one value for several targets: comma-ok, or a call's results
		}
		for _, t := range targets {
			v, ok := j.slot(t)
			if !ok {
				j.violate(x, "a lent number stored outside its callback, where it outlives the lease")
				return nil, false
			}
			if v != nil {
				j.carriers[v] = true
			}
		}
	case *ast.ValueSpec:
		for i, val := range x.Values {
			if val != child {
				continue
			}
			names := x.Names
			if len(x.Values) == len(x.Names) {
				names = x.Names[i : i+1]
			}
			for _, n := range names {
				if v, ok := j.info.Defs[n].(*types.Var); ok && !j.escaped[v] {
					j.carriers[v] = true
				} else if n.Name != "_" {
					j.violate(x, "a lent number stored where it outlives the lease")
				}
			}
		}
	case *ast.RangeStmt:
		if x.X != child {
			return nil, false // the carrier is the range's own target
		}
		for _, t := range []ast.Expr{x.Key, x.Value} {
			if t == nil {
				continue
			}
			v, ok := j.slot(t)
			if !ok {
				j.violate(x, "a lent number ranged into storage outside its callback, where it outlives the lease")
				return nil, false
			}
			if v != nil {
				j.carriers[v] = true
			}
		}
	case *ast.ReturnStmt:
		j.violate(x, "a lent number returned, where it outlives the lease")
	case *ast.SendStmt:
		j.violate(x, "a lent number sent on a channel, where it outlives the lease")
	case *ast.IncDecStmt, *ast.ExprStmt, *ast.DeferStmt:
	case *ast.SwitchStmt:
		if x.Tag != child {
			j.violate(x, "a lent number used where fdcheck does not follow it")
		}
	case *ast.CaseClause:
	default:
		j.violate(p, "a lent number used where fdcheck does not follow it")
	}
	return nil, false
}

// carryingUnary are the unary operators whose result holds the number; endingBinary the binary ones whose result
// does not (the rest, arithmetic, bitwise, shifts and string concatenation, hold it).
var (
	carryingUnary = map[token.Token]bool{token.ADD: true, token.SUB: true, token.XOR: true, token.ARROW: true}
	endingBinary  = map[token.Token]bool{token.EQL: true, token.NEQ: true, token.LSS: true, token.LEQ: true,
		token.GTR: true, token.GEQ: true, token.LAND: true, token.LOR: true}
)

// storeTarget is whether an index expression is (part of) the target of a store.
func (j *judge) storeTarget(e ast.Node) bool {
	cur := e
	for {
		switch p := j.parents[cur].(type) {
		case *ast.ParenExpr, *ast.StarExpr:
			cur = p
			continue
		case *ast.SelectorExpr:
			if p.X == cur {
				cur = p
				continue
			}
		case *ast.IndexExpr:
			if p.X == cur {
				cur = p
				continue
			}
		case *ast.AssignStmt:
			for _, l := range p.Lhs {
				if l == cur {
					return true
				}
			}
		case *ast.IncDecStmt:
			return true
		case *ast.UnaryExpr:
			return p.Op == token.AND
		case *ast.RangeStmt:
			return p.Key == cur || p.Value == cur
		}
		return false
	}
}

func (j *judge) inGo(call *ast.CallExpr) bool {
	_, ok := j.parents[call].(*ast.GoStmt)
	return ok
}

func (j *judge) borrowed(fn *types.Func, idx int) bool { return j.ls.borrowed(fn, idx) }

// callArg classifies a carrier passed to a call.
func (j *judge) callArg(call *ast.CallExpr, child ast.Node) (ast.Node, bool) {
	if call.Fun == child {
		j.violate(call, "a lent number called as a function")
		return nil, false
	}
	if j.inGo(call) {
		j.violate(call, "a lent number handed to a goroutine, which outlives the lease")
		return nil, false
	}
	if tv := j.info.Types[call.Fun]; tv.IsType() {
		return call, true // a conversion
	}
	if id, ok := ast.Unparen(call.Fun).(*ast.Ident); ok {
		if b, ok := j.info.Uses[id].(*types.Builtin); ok {
			switch b.Name() {
			case "len", "cap", "min", "max":
				return call, true // a slice a lent bound cut has the number for its length
			}
			j.violate(call, "a lent number passed to "+b.Name()+", which keeps it")
			return nil, false
		}
	}
	idx := -1
	for i, a := range call.Args {
		if a == child {
			idx = i
		}
	}
	fn, sel := calleeIn(j.info, call)
	if j.release {
		if fn != nil && !isMethod(fn) && taker(pkgPath(fn), fn.Name()) && idx == 0 {
			j.takers = append(j.takers, call)
		} else {
			j.violate(call, "a lent number passed to a call")
		}
		return nil, false
	}
	if fn == nil {
		if q := j.lenderParam(call.Fun); q >= 0 {
			if fn, ok := j.info.Defs[j.encl.Name].(*types.Func); ok {
				j.ls.note(fn, q, idx)
				return nil, false
			}
		}
		j.violate(call, "a lent number passed to a function value fdcheck cannot follow")
		return nil, false
	}
	pidx := idx
	if sel != nil && sel.Kind() == types.MethodExpr {
		pidx = idx - 1 // T.M(recv, args...)
	}
	sig := fn.Type().(*types.Signature)
	full := fn.FullName()
	path := pkgPath(fn)
	switch {
	case isUnix(path) && !isMethod(fn) && syscallFamily[fn.Name()]:
		return nil, false // a raw syscall's arguments are the kernel's to use in the call
	case isUnix(path) && !isMethod(fn) && returnsError(sig):
		if t := paramType(sig, pidx, call.Ellipsis.IsValid()); (t != nil && isInteger(t)) || lentSinks[full][pidx] {
			return nil, false
		}
		j.violate(call, "a lent number passed to "+pkgName(path)+"."+fn.Name()+" as data the kernel may keep")
		return nil, false
	case isUnix(path) && !isMethod(fn):
		return call, true // a pure helper: its result holds the number
	}
	if sinks, ok := lentSinks[full]; ok {
		if sinks == nil {
			return call, true // an encoder
		}
		if sinks[pidx] {
			return nil, false
		}
	}
	if _, ok := j.ls.w.funcs[fn]; ok && pidx >= -1 {
		if pidx >= sig.Params().Len() && sig.Variadic() {
			pidx = sig.Params().Len() - 1
		}
		if j.borrowed(fn, pidx) {
			return nil, false
		}
		j.violate(call, "a lent number passed to "+fn.Name()+", which keeps it or passes it where fdcheck cannot follow")
		return nil, false
	}
	j.violate(call, "a lent number passed to "+full+", which fdcheck cannot follow")
	return nil, false
}

// lenderParam is, in callback mode, the index of the enclosing declaration's callback parameter that fun names
// (the declaration lends to it), or -1.
func (j *judge) lenderParam(fun ast.Expr) int {
	if j.summary || j.encl == nil {
		return -1
	}
	return j.ls.callbackParam(j.info, fun, j.encl)
}

func returnsError(sig *types.Signature) bool {
	r := sig.Results()
	return r.Len() > 0 && types.Identical(r.At(r.Len()-1).Type(), errorType)
}

// paramType is the type parameter i of sig takes (a variadic one's element, unless the call spreads a slice).
func paramType(sig *types.Signature, i int, spread bool) types.Type {
	ps := sig.Params()
	if i < 0 || ps.Len() == 0 {
		return nil
	}
	if sig.Variadic() && i >= ps.Len()-1 {
		t := ps.At(ps.Len() - 1).Type()
		if spread {
			return t
		}
		if s, ok := t.Underlying().(*types.Slice); ok {
			return s.Elem()
		}
		return t
	}
	if i >= ps.Len() {
		return nil
	}
	return ps.At(i).Type()
}

// released judges a ReleaseNumber's number, held in v, in the function it is released in (F3), and returns the
// violations and the taker calls it reaches.
func (ls *lentState) released(p *typedPkg, body *ast.BlockStmt, ft *ast.FuncType, recv *ast.FieldList, v *types.Var) ([]violation, []*ast.CallExpr) {
	j := ls.newJudge(p, body, ft, recv, false)
	j.release = true
	j.carriers = map[*types.Var]bool{v: true}
	vs := j.run()
	return vs, j.takers
}

// numSeeds judges the (*sys.Lease).Num() calls of one function body: the number is valid while the lease is out,
// which the Hold's function (or its hand-off goroutine) bounds, so it is held to the same uses as a callback's.
func (ls *lentState) numSeeds(p *typedPkg, body *ast.BlockStmt, ft *ast.FuncType, recv *ast.FieldList, calls []*ast.CallExpr) []violation {
	j := ls.newJudge(p, body, ft, recv, false)
	j.carriers = map[*types.Var]bool{}
	for _, c := range calls {
		j.seeds[c] = true
	}
	return j.run()
}
