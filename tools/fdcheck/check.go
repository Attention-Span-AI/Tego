// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
	"sort"
	"strings"
)

// Finding is one raw site or rule violation in a non-exempt file.
type Finding struct {
	Pkg  string // the package's directory, relative to the root
	File string // relative to the root
	Line int
	Func string // the enclosing function ("Type.Method"), or at package level "<package>:name" (funcName)
	Kind string
	What string
	off  int // the byte offset in File: a site found under several build configurations is one site
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: [%s] %s (in %s): %s", f.File, f.Line, f.Kind, f.What, f.Func, kindHelp[f.Kind])
}

func (f Finding) key() string { return fmt.Sprintf("%s:%d:%s:%s", f.File, f.off, f.Kind, f.What) }

// analyzeWorld runs every rule on the world's packages and returns the findings in non-exempt files. The lenders
// every package derives are found first, so a call is judged knowing every lender of the world (one reached
// through an interface another package implements included). The exempt files are type-checked with their
// package, and the lent-number check follows into them (sys.FileDo's body), but no finding is reported in them
// (A7).
func analyzeWorld(w *typedWorld, prod Producers) []Finding {
	ls := newLentState(w)
	ls.derive(w.pkgs)
	var out []Finding
	for _, p := range w.pkgs {
		for i := range p.files {
			if Exempt(p.names[i]) {
				continue
			}
			c := newFileCheck(w, p, i, prod, ls)
			c.run()
			out = append(out, c.out...)
		}
	}
	return out
}

// fileCheck is one file's analysis.
type fileCheck struct {
	w         *typedWorld
	p         *typedPkg
	f         *ast.File
	name      string
	info      *types.Info
	prod      Producers
	ls        *lentState
	hooksOnly bool // the file builds only with tegotesthooks
	parents   map[ast.Node]ast.Node
	done      map[ast.Node]bool // calls already judged: an owner's birth by its Own, a ReleaseNumber by releases
	takers    map[ast.Node]bool // F3's sanctioned taker calls, which a released number reaches
	f3Lines   map[int]bool      // lines holding F3's sanctioned taker call, which forbidigo cannot judge
	decls     []declSpan
	nums      []*ast.CallExpr // (*sys.Lease).Num() calls: lent numbers, judged in their function (lent.go)
	out       []Finding
}

// declSpan is a top-level declaration's extent and the name a site inside it carries (funcName).
type declSpan struct {
	pos, end token.Pos
	name     string
}

func newFileCheck(w *typedWorld, p *typedPkg, i int, prod Producers, ls *lentState) *fileCheck {
	c := &fileCheck{w: w, p: p, f: p.files[i], name: p.names[i], info: p.info, prod: prod, ls: ls,
		parents: parentsOf(p.files[i]), done: map[ast.Node]bool{}, takers: map[ast.Node]bool{}, f3Lines: map[int]bool{}}
	c.hooksOnly = hooksOnly(c.f)
	c.decls = declSpans(c.f)
	return c
}

// parentsOf maps each node of f to its parent.
func parentsOf(f *ast.File) map[ast.Node]ast.Node {
	parents := map[ast.Node]ast.Node{}
	var stack []ast.Node
	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) > 0 {
			parents[n] = stack[len(stack)-1]
		}
		stack = append(stack, n)
		return true
	})
	return parents
}

// declSpans names f's top-level declarations: "Type.Method" or "name" for a function, and at package level the
// declaration a site is in, "<package>:closeHook" for `var closeHook = func...`, "<package>:a,b" for one spec of
// two names, "<package>:T" in a type. A site's identity across packages is built from it (moveCheck).
func declSpans(f *ast.File) []declSpan {
	var out []declSpan
	for _, d := range f.Decls {
		switch x := d.(type) {
		case *ast.FuncDecl:
			name := x.Name.Name
			if x.Recv != nil && len(x.Recv.List) > 0 {
				name = recvName(x.Recv.List[0].Type) + "." + name
			}
			out = append(out, declSpan{x.Pos(), x.End(), name})
		case *ast.GenDecl:
			for _, sp := range x.Specs {
				switch s := sp.(type) {
				case *ast.ValueSpec:
					names := make([]string, len(s.Names))
					for i, id := range s.Names {
						names[i] = id.Name
					}
					out = append(out, declSpan{s.Pos(), s.End(), "<package>:" + strings.Join(names, ",")})
				case *ast.TypeSpec:
					out = append(out, declSpan{s.Pos(), s.End(), "<package>:" + s.Name.Name})
				}
			}
		}
	}
	return out
}

// declAfter names the first declaration that starts at or after pos.
func (c *fileCheck) declAfter(pos token.Pos) string {
	for _, d := range c.decls {
		if d.pos >= pos {
			return d.name
		}
	}
	return "<package>"
}

func (c *fileCheck) funcName(n ast.Node) string {
	pos := n.Pos()
	for _, d := range c.decls {
		if d.pos <= pos && pos < d.end {
			return d.name
		}
	}
	return "<package>"
}

// hooksOnly is whether the file's build constraint needs tegotesthooks: false with the tag off, whatever the
// other tags are, and true for some setting with it on.
func hooksOnly(f *ast.File) bool {
	for _, cg := range f.Comments {
		if cg.Pos() > f.Package {
			break
		}
		for _, cm := range cg.List {
			if !constraint.IsGoBuild(cm.Text) {
				continue
			}
			expr, err := constraint.Parse(cm.Text)
			if err != nil {
				return false
			}
			eval := func(hooks, others bool) bool {
				return expr.Eval(func(tag string) bool {
					if tag == "tegotesthooks" {
						return hooks
					}
					return others
				})
			}
			return !eval(false, true) && !eval(false, false) && (eval(true, true) || eval(true, false))
		}
	}
	return false
}

func (c *fileCheck) add(n ast.Node, kind, what string) {
	pos := c.w.fset.Position(n.Pos())
	c.out = append(c.out, Finding{Pkg: c.p.dir, File: c.name, Line: pos.Line, Func: c.funcName(n), Kind: kind,
		What: what, off: pos.Offset})
}

func recvName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return recvName(x.X)
	case *ast.IndexExpr:
		return recvName(x.X)
	case *ast.IndexListExpr:
		return recvName(x.X)
	case *ast.Ident:
		return x.Name
	}
	return "?"
}

// pkgPath is the import path of the package that declares o, or "".
func pkgPath(o types.Object) string {
	if o == nil || o.Pkg() == nil {
		return ""
	}
	return o.Pkg().Path()
}

func isMethod(fn *types.Func) bool { return fn.Type().(*types.Signature).Recv() != nil }

func isUnix(path string) bool { return path == pathUnix || path == pathSyscall }

func pkgName(path string) string { return path[strings.LastIndex(path, "/")+1:] }

// deref is a pointer type's element, or t.
func deref(t types.Type) types.Type {
	if p, ok := t.Underlying().(*types.Pointer); ok {
		return p.Elem()
	}
	return t
}

// isInteger is whether t's underlying type is an integer.
func isInteger(t types.Type) bool {
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Info()&types.IsInteger != 0
}

// fdShaped is whether o is a method, or a func-typed field, named Fd or FD that takes nothing and answers an
// integer: (*os.File).Fd, cilium's FD, an interface{ Fd() uintptr }, one promoted through embedding (F5).
func fdShaped(o types.Object) bool {
	if o == nil || (o.Name() != "Fd" && o.Name() != "FD") {
		return false
	}
	sig, ok := o.Type().Underlying().(*types.Signature)
	return ok && sig.Params().Len() == 0 && sig.Results().Len() > 0 && isInteger(sig.Results().At(0).Type())
}

// calleeOf is the function or method a call reaches statically (a generic one's origin), with the selection
// for a method; nil for a conversion, a builtin or a func value's call.
func (c *fileCheck) calleeOf(call *ast.CallExpr) (*types.Func, *types.Selection) {
	return calleeIn(c.info, call)
}

func calleeIn(info *types.Info, call *ast.CallExpr) (*types.Func, *types.Selection) {
	fun := ast.Unparen(call.Fun)
	switch x := fun.(type) {
	case *ast.IndexExpr:
		fun = ast.Unparen(x.X)
	case *ast.IndexListExpr:
		fun = ast.Unparen(x.X)
	}
	var id *ast.Ident
	var sel *types.Selection
	switch x := fun.(type) {
	case *ast.Ident:
		id = x
	case *ast.SelectorExpr:
		id, sel = x.Sel, info.Selections[x]
	default:
		return nil, nil
	}
	fn, _ := info.Uses[id].(*types.Func)
	if fn == nil {
		return nil, nil
	}
	return fn.Origin(), sel
}

// isCallee is whether the identifier is the function a call names (pkg.F, x.M, F, F[T], through parentheses).
func (c *fileCheck) isCallee(id *ast.Ident) bool {
	var n ast.Node = id
	if sel, ok := c.parents[n].(*ast.SelectorExpr); ok && sel.Sel == id {
		n = sel
	}
	for {
		switch p := c.parents[n].(type) {
		case *ast.ParenExpr:
			n = p
			continue
		case *ast.IndexExpr:
			if p.X == n {
				n = p
				continue
			}
		case *ast.IndexListExpr:
			if p.X == n {
				n = p
				continue
			}
		case *ast.CallExpr:
			return p.Fun == n
		}
		return false
	}
}

func (c *fileCheck) run() {
	c.releases()
	ast.Inspect(c.f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Ident:
			c.ref(x)
		case *ast.StructType:
			for _, fl := range x.Fields.List {
				if leaseIn(c.ls.lease, c.info.TypeOf(fl.Type), 0) {
					c.add(fl, kLease, "a *sys.Lease stored in a struct field")
				}
			}
		case *ast.ChanType:
			if leaseIn(c.ls.lease, c.info.TypeOf(x.Value), 0) {
				c.add(x, kLease, "a *sys.Lease sent on a channel")
			}
		case *ast.GenDecl:
			if x.Tok == token.VAR && c.parents[x] == c.f {
				for _, sp := range x.Specs {
					vs := sp.(*ast.ValueSpec)
					for _, id := range vs.Names {
						if o := c.info.Defs[id]; o != nil && leaseIn(c.ls.lease, o.Type(), 0) {
							c.add(vs, kLease, "a *sys.Lease in a package-level variable")
							break
						}
					}
				}
			}
			if x.Tok == token.TYPE {
				for _, sp := range x.Specs {
					c.apiType(sp.(*ast.TypeSpec))
				}
			}
		case *ast.FuncDecl:
			c.apiFunc(x)
			if x.Body == nil {
				c.add(x.Name, kOpaque, x.Name.Name+" has no Go body (assembly or a linkname), which fdcheck cannot read")
			}
		case *ast.CompositeLit:
			c.pidfdLiteral(x)
		case *ast.CallExpr:
			c.call(x)
			c.pidfdUnsafe(x)
		case *ast.UnaryExpr:
			// &x.PidFD lets anything write SysProcAttr's pointer, so it is a producer as the assignment is.
			if sel, ok := ast.Unparen(x.X).(*ast.SelectorExpr); ok && x.Op == token.AND && c.isPidFD(sel) {
				c.add(x, kProducer, "the address of SysProcAttr.PidFD (the start writes a pidfd no owner holds)")
			}
		case *ast.AssignStmt:
			// x.PidFD = e: SysProcAttr's PidFD is a pointer the start writes a number through, so any value but nil
			// or a constant is a producer.
			for i, l := range x.Lhs {
				if sel, ok := ast.Unparen(l).(*ast.SelectorExpr); ok && c.isPidFD(sel) {
					if len(x.Lhs) != len(x.Rhs) || x.Tok != token.ASSIGN || !c.constOrNil(x.Rhs[i]) {
						c.add(x, kProducer, "SysProcAttr.PidFD (the start writes a pidfd no owner holds)")
					}
				}
			}
		}
		return true
	})
	c.judgeNums()
	// A //nolint that silences forbidigo hides its reports from golangci-lint. One form is admitted:
	// `//nolint:forbidigo // ADR 0023 F3` on the line of F3's sanctioned link.NewFromFD(x.ReleaseNumber()), which
	// forbidigo reports and cannot judge.
	for _, g := range c.f.Comments {
		for _, cm := range g.List {
			if c.f3Lines[c.w.fset.Position(cm.Pos()).Line] && f3Nolint.MatchString(cm.Text) {
				continue
			}
			if nolintSilencesForbidigo(cm.Text) {
				c.add(cm, kNolint, "a nolint directive that silences forbidigo")
			}
			if strings.HasPrefix(cm.Text, "//go:linkname ") {
				c.add(cm, kOpaque, "a //go:linkname, whose symbol fdcheck cannot read")
				c.out[len(c.out)-1].Func = c.declAfter(cm.Pos()) // the declaration the directive names
			}
		}
	}
}

// judgeNums holds each (*sys.Lease).Num() to the lent-number rules in the function it is called in, which the
// Hold's defer (or the hand-off goroutine's) bounds.
func (c *fileCheck) judgeNums() {
	groups := map[ast.Node][]*ast.CallExpr{}
	var order []ast.Node
	for _, call := range c.nums {
		var fn ast.Node
		for p := c.parents[call]; p != nil && fn == nil; p = c.parents[p] {
			switch p.(type) {
			case *ast.FuncLit, *ast.FuncDecl:
				fn = p
			}
		}
		if fn == nil {
			continue
		}
		if groups[fn] == nil {
			order = append(order, fn)
		}
		groups[fn] = append(groups[fn], call)
	}
	for _, fn := range order {
		var vs []violation
		switch f := fn.(type) {
		case *ast.FuncLit:
			vs = c.ls.numSeeds(c.p, f.Body, f.Type, nil, groups[fn])
		case *ast.FuncDecl:
			vs = c.ls.numSeeds(c.p, f.Body, f.Type, f.Recv, groups[fn])
		}
		for _, v := range vs {
			c.add(v.at, kLease, v.what)
		}
	}
}

// f3Nolint is the one nolint directive F3's sanctioned form carries.
var f3Nolint = regexp.MustCompile(`^//nolint:forbidigo // ADR 0023 F3\b`)

// nolintRE is golangci-lint's nolint directive, case folded: "nolint" then a space, a colon or the end.
var nolintRE = regexp.MustCompile(`(?i)^nolint( |:|$)`)

// nolintSilencesForbidigo is whether a comment is a nolint directive for every linter, for all, or for forbidigo.
func nolintSilencesForbidigo(text string) bool {
	t := strings.TrimLeft(text, "/* \t")
	if !nolintRE.MatchString(t) {
		return false
	}
	t = t[len("nolint"):]
	if !strings.HasPrefix(t, ":") {
		return true
	}
	// The list runs to a "//" reason; every word before it is read as a name, so a space after a comma hides none.
	list, _, _ := strings.Cut(t[1:], "//")
	for _, name := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if n := strings.ToLower(name); n == "all" || strings.HasPrefix(n, "forbidigo") {
			return true
		}
	}
	return false
}

// call judges a call by the function it reaches.
func (c *fileCheck) call(x *ast.CallExpr) {
	if c.done[x] {
		return // an owner's birth or a sanctioned ReleaseNumber, judged by the enclosing call
	}
	fn, _ := c.calleeOf(x)
	if fn == nil {
		return
	}
	path, name := pkgPath(fn), fn.Name()
	method := isMethod(fn)
	switch {
	case isUnix(path) && !method:
		c.unixCall(x, path, name)
	case path == pathSys && !method:
		c.sysCall(x, name)
	case path == pathOS && name == "NewFile" && !method:
		c.add(x, kNewFile, "os.NewFile")
	case taker(path, name) && !method:
		if !c.takers[x] {
			c.add(x, kFromFD, name+" over a number no owner released")
		}
	case path == pathSys && method:
		switch {
		case name == "Abandon":
			c.add(x, kAbandon, "Abandon()")
		case name == "Hold":
			c.lease(x)
		case name == "Num" && c.ls.lease != nil && types.Identical(deref(fn.Type().(*types.Signature).Recv().Type()), c.ls.lease.Type()):
			c.nums = append(c.nums, x)
		case strings.HasSuffix(name, "ForTest") && !c.hooksOnly:
			c.add(x, kForTest, "the method "+name+" outside tests and tegotesthooks files")
		}
	}
	if l, ok := c.ls.lenderOf(fn); ok {
		for _, v := range c.ls.judgeCall(c.p, x, l, c.enclosingFunc(x)) {
			c.add(v.at, kLease, v.what)
		}
	}
}

// releases judges each ReleaseNumber (F3): its number is assigned to a local variable, reaches exactly one taker's
// argument (link.NewFromFD, ebpf.NewMapFromFD, ebpf.NewProgramFromFD) through local slots only, and is used
// nowhere else; the taker call it reaches is F3's sanctioned one. `taker(x.ReleaseNumber())`, the form the C3 note
// named, does not compile: ReleaseNumber answers (int, error).
func (c *fileCheck) releases() {
	ast.Inspect(c.f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn, _ := c.calleeOf(call)
		if fn == nil || !isMethod(fn) || pkgPath(fn) != pathSys || fn.Name() != "ReleaseNumber" {
			return true
		}
		c.done[call] = true
		body, ft, recv := c.enclosingBody(call)
		v := c.releasedVar(call)
		if v == nil || body == nil || v.Pos() < body.Pos() && (ft == nil || v.Pos() < ft.Pos()) || v.Pos() > body.End() {
			c.add(call, kRelease, "ReleaseNumber() whose number is not assigned to a local variable")
			return true
		}
		vs, takers := c.ls.released(c.p, body, ft, recv, v)
		for _, x := range vs {
			c.add(x.at, kRelease, x.what)
		}
		switch {
		case len(vs) > 0:
		case len(takers) == 0:
			c.add(call, kRelease, "ReleaseNumber() whose number reaches no taker, so no one owns it")
		default:
			c.takers[takers[0]] = true
			if c.takerPlaced(call, takers[0]) {
				c.f3Lines[c.w.fset.Position(takers[0].Pos()).Line] = true
			} else {
				c.add(takers[0], kRelease, "a released number's taker that is not the statement after the ReleaseNumber "+
					"and its error check, in its block, so it may run twice (two owners) or never (a leak)")
			}
			for _, t := range takers[1:] {
				c.add(t, kRelease, "a released number given to a second taker, so two would own it")
			}
		}
		return true
	})
}

// takerPlaced is whether F3's one taker call runs exactly once after its ReleaseNumber: it is in the statement
// that follows the ReleaseNumber's in their block, past only the release's own error check, and reached from that
// statement through expressions alone (no loop, branch, label, function literal or right operand of && or ||), so
// the number has one owner on every path.
func (c *fileCheck) takerPlaced(release, taker *ast.CallExpr) bool {
	var stmt ast.Stmt
	var errID ast.Expr
	switch p := c.parents[release].(type) {
	case *ast.AssignStmt:
		stmt, errID = p, p.Lhs[1]
	case *ast.ValueSpec:
		if ds, ok := c.parents[c.parents[p]].(*ast.DeclStmt); ok {
			stmt, errID = ds, p.Names[1]
		}
	}
	if stmt == nil {
		return false
	}
	next := c.nextStmt(stmt, c.identObj(errID), nil)
	return next != nil && c.reachedBy(taker, next)
}

// identObj is the object an identifier names, or nil (for the blank identifier, or another expression).
func (c *fileCheck) identObj(e ast.Expr) types.Object {
	if id, ok := ast.Unparen(e).(*ast.Ident); ok && id.Name != "_" {
		return c.info.ObjectOf(id)
	}
	return nil
}

// nextStmt is the statement after s in its statement list (a block, a case or a select clause), past the failure
// checks of s's own results that only return (`if err != nil { return ... }`, `if l == nil || err != nil { return
// }`, see failCheck); nil when s is in no list or nothing follows.
func (c *fileCheck) nextStmt(s ast.Stmt, errV, leaseV types.Object) ast.Stmt {
	var list []ast.Stmt
	switch p := c.parents[s].(type) {
	case *ast.BlockStmt:
		list = p.List
	case *ast.CaseClause:
		list = p.Body
	case *ast.CommClause:
		list = p.Body
	}
	for i, st := range list {
		if st != s {
			continue
		}
		for _, next := range list[i+1:] {
			if !c.failCheck(next, errV, leaseV) {
				return next
			}
		}
	}
	return nil
}

// failCheck is whether st is `if <test> { return ... }` with no init or else, whose test is true only on failure:
// terms `errV != nil` and `leaseV == nil` (either operand order) joined by ||. A test that returns on success (`err
// == nil`, `l != nil`) or on another variable would leave the success path before the defer or the taker, which
// leaks the lease or the number there. errV or leaseV may be nil (the blank identifier,
// or no lease), and then no term names it.
func (c *fileCheck) failCheck(st ast.Stmt, errV, leaseV types.Object) bool {
	is, ok := st.(*ast.IfStmt)
	if !ok || is.Init != nil || is.Else != nil || len(is.Body.List) != 1 {
		return false
	}
	if _, ok := is.Body.List[0].(*ast.ReturnStmt); !ok {
		return false
	}
	var test func(e ast.Expr) bool
	test = func(e ast.Expr) bool {
		b, ok := ast.Unparen(e).(*ast.BinaryExpr)
		if !ok {
			return false
		}
		if b.Op == token.LOR {
			return test(b.X) && test(b.Y)
		}
		v, n := b.X, b.Y
		if c.info.Types[v].IsNil() {
			v, n = n, v
		}
		o := c.identObj(v)
		if o == nil || !c.info.Types[n].IsNil() {
			return false
		}
		return o == errV && b.Op == token.NEQ || o == leaseV && b.Op == token.EQL
	}
	return test(is.Cond)
}

// reachedBy is whether n is inside stmt through expressions alone (and a var declaration's spec): no statement, and
// no function literal, between them; and stmt is a plain statement that evaluates its expressions once, where it
// stands: an expression statement, an assignment, a var declaration or a return. A for statement's condition runs
// per iteration, and an if or switch condition, a go or a defer statement is not the plain call F3 sanctions. n is
// not in the right operand of a && or ||, which runs only when the left one does not settle the
// result.
func (c *fileCheck) reachedBy(n ast.Node, stmt ast.Stmt) bool {
	switch stmt.(type) {
	case *ast.ExprStmt, *ast.AssignStmt, *ast.DeclStmt, *ast.ReturnStmt:
	default:
		return false
	}
	for child, p := n, c.parents[n]; p != nil; child, p = p, c.parents[p] {
		switch q := p.(type) {
		case *ast.FuncLit:
			return false
		case *ast.BinaryExpr:
			if (q.Op == token.LAND || q.Op == token.LOR) && q.Y == child {
				return false
			}
			continue
		case ast.Expr, *ast.ValueSpec, *ast.GenDecl:
			continue
		}
		return p == stmt
	}
	return false
}

// releasedVar is the variable a ReleaseNumber's number is assigned to: `n, err := x.ReleaseNumber()`, `n, err =
// ...` or `var n, err = ...`; nil otherwise.
func (c *fileCheck) releasedVar(call *ast.CallExpr) *types.Var {
	var id ast.Expr
	switch p := c.parents[call].(type) {
	case *ast.AssignStmt:
		if len(p.Rhs) == 1 && len(p.Lhs) == 2 {
			id = p.Lhs[0]
		}
	case *ast.ValueSpec:
		if len(p.Values) == 1 && len(p.Names) == 2 {
			id = p.Names[0]
		}
	}
	if x, ok := id.(*ast.Ident); ok {
		v, _ := c.info.ObjectOf(x).(*types.Var)
		return v
	}
	return nil
}

// enclosingBody is the innermost function (literal or declaration) a node is in.
func (c *fileCheck) enclosingBody(n ast.Node) (*ast.BlockStmt, *ast.FuncType, *ast.FieldList) {
	for p := c.parents[n]; p != nil; p = c.parents[p] {
		switch f := p.(type) {
		case *ast.FuncLit:
			return f.Body, f.Type, nil
		case *ast.FuncDecl:
			return f.Body, f.Type, f.Recv
		}
	}
	return nil, nil, nil
}

// enclosingFunc is the function declaration a node is in, or nil at package level.
func (c *fileCheck) enclosingFunc(n ast.Node) *ast.FuncDecl {
	for p := c.parents[n]; p != nil; p = c.parents[p] {
		if fd, ok := p.(*ast.FuncDecl); ok {
			return fd
		}
	}
	return nil
}

func (c *fileCheck) sysCall(x *ast.CallExpr, name string) {
	arg := func() (*ast.CallExpr, bool) {
		if len(x.Args) != 1 {
			return nil, false
		}
		a, ok := ast.Unparen(x.Args[0]).(*ast.CallExpr)
		return a, ok
	}
	switch {
	case name == "Own":
		if a, ok := arg(); ok {
			if f, _ := c.calleeOf(a); f != nil && !isMethod(f) && c.producer(pkgPath(f), f.Name()) {
				c.done[a] = true
				c.cloexec(a, f.Name())
				return
			}
		}
		c.add(x, kOwn, "sys.Own around something other than a producer's call")
	case name == "Strict":
		if a, ok := arg(); ok {
			if f, _ := c.calleeOf(a); f != nil && pkgPath(f) == pathSys &&
				((!isMethod(f) && sysConstructors[f.Name()]) || (isMethod(f) && ownerMethods[f.Name()])) {
				return
			}
		}
		c.add(x, kStrict, "sys.Strict around something other than a constructor's call")
	case name == "OwnSyscall":
		if a, ok := arg(); ok {
			if f, _ := c.calleeOf(a); f != nil && !isMethod(f) && isUnix(pkgPath(f)) && syscallFamily[f.Name()] {
				c.done[a] = true
				if trap, ok := c.admitted(a); ok {
					if r, ok := ownSyscallCloexec[trap]; ok {
						c.cloexecArg(a, trap, r)
					}
					return
				}
			}
		}
		c.add(x, kOwnSyscall, "sys.OwnSyscall around a call that is not an admitted producer")
	case name == "Adopt":
		c.add(x, kAdopt, "sys.Adopt")
	case name == "Inherited":
		c.add(x, kInherited, "sys.Inherited")
	case name == "Stdio":
		c.add(x, kStdio, "sys.Stdio")
	case name == sweepFunc:
		c.add(x, kSweep, "sys."+sweepFunc)
	case name == "InertForTest":
		c.add(x, kForTest, "sys.InertForTest outside a _test.go file")
	case strings.HasSuffix(name, "ForTest"):
		if !c.hooksOnly {
			c.add(x, kForTest, "sys."+name+" outside tests and tegotesthooks files")
		}
	case sysIntProducers[name]:
		c.add(x, kProducer, "sys."+name+" (an int number; use its ...FD owner form)")
	}
}

func (c *fileCheck) producer(path, name string) bool {
	switch path {
	case pathUnix:
		return c.prod.Unix[name]
	case pathSyscall:
		return c.prod.Syscall[name]
	case pathSys:
		return sysIntProducers[name]
	}
	return false
}

func (c *fileCheck) unixCall(x *ast.CallExpr, path, name string) {
	if k, ok := forbiddenCall[name]; ok {
		c.add(x, k, pkgName(path)+"."+name)
		return
	}
	if c.producer(path, name) {
		c.add(x, kProducer, pkgName(path)+"."+name+" outside sys.Own")
		return
	}
	switch {
	case syscallFamily[name]:
		c.syscall(x)
	case strings.HasPrefix(name, "Fcntl"):
		if len(x.Args) >= 2 {
			c.fcntl(x, x.Args[1])
		}
	case name == "Unshare":
		if len(x.Args) >= 1 {
			c.unshare(x, x.Args[0])
		}
	case recvRules[name] != recvRule{}:
		c.recvmsg(x, pkgName(path)+"."+name, recvRules[name])
	case ioctlReqWrappers[name]:
		if len(x.Args) >= 2 {
			c.ioctl(x, x.Args[1])
		}
	case strings.HasPrefix(name, "Ioctl") && !ioctlFixed[name]:
		c.add(x, kIoctl, pkgName(path)+"."+name+" (an ioctl wrapper fdcheck does not classify)")
	}
}

// ioctl judges an ioctl whose request is an argument (a raw SYS_IOCTL, an x/sys wrapper that takes one): the
// request is a named constant from the allowlist, since some requests answer a fresh descriptor (F5).
func (c *fileCheck) ioctl(x *ast.CallExpr, req ast.Expr) {
	switch name, ok := c.constName(req); {
	case !ok:
		c.add(x, kIoctl, "an ioctl whose request is not a named constant")
	case !ioctlAllowed[name]:
		c.add(x, kIoctl, "ioctl "+name+" (it may answer a descriptor)")
	}
}

// syscall judges a raw Syscall* outside sys.OwnSyscall.
func (c *fileCheck) syscall(x *ast.CallExpr) {
	if len(x.Args) == 0 {
		return
	}
	trap, ok := c.constName(x.Args[0])
	if !ok || !strings.HasPrefix(trap, "SYS_") {
		c.add(x, kTrap, "a syscall whose trap is not a SYS_ constant")
		return
	}
	if _, forbidden := forbiddenConst(trap); forbidden {
		return // counted where a constant names it (ref): the x/sys constant, and each module constant's use
	}
	switch trap {
	case "SYS_FCNTL", "SYS_FCNTL_NOCANCEL":
		if len(x.Args) >= 3 {
			c.fcntl(x, x.Args[2])
		}
		return
	case "SYS_UNSHARE":
		if len(x.Args) >= 2 {
			c.unshare(x, x.Args[1])
		}
		return
	case "SYS_IOCTL":
		if len(x.Args) >= 3 {
			c.ioctl(x, x.Args[2])
		}
		return
	}
	switch {
	case producerTraps[trap] && c.makesFD(x, trap):
		c.add(x, kProducer, "a raw "+trap+" outside sys.OwnSyscall")
	case c.w.cfg.goos != "linux" && !producerTraps[trap]:
		// producerTraps was written from Linux's syscall table; another system's trap it does not name may
		// answer a descriptor (fail closed).
		c.add(x, kTrap, "a raw "+trap+" under the "+c.w.cfg.goos+" build, which fdcheck does not classify")
	}
}

// makesFD is whether a raw call of a producer trap answers a descriptor; when its command or flags cannot be
// read it is taken to (fail closed).
func (c *fileCheck) makesFD(x *ast.CallExpr, trap string) bool {
	arg := func(i int) ast.Expr {
		if i < len(x.Args) {
			return x.Args[i]
		}
		return nil
	}
	switch trap {
	case "SYS_BPF":
		if cmd, ok := c.constName(arg(1)); ok {
			return bpfFDCommands[cmd]
		}
	case "SYS_SECCOMP":
		if op, ok := c.constName(arg(1)); ok && op != "SECCOMP_SET_MODE_FILTER" {
			return false
		}
		if has, constant := c.flag(arg(2), "SECCOMP_FILTER_FLAG_NEW_LISTENER"); constant {
			return has
		}
	case "SYS_LANDLOCK_CREATE_RULESET":
		v, cv := c.flag(arg(3), "LANDLOCK_CREATE_RULESET_VERSION")
		e, ce := c.flag(arg(3), "LANDLOCK_CREATE_RULESET_ERRATA")
		if cv && ce {
			return !v && !e
		}
	case "SYS_CLONE":
		if has, constant := c.flag(arg(1), "CLONE_PIDFD"); constant {
			return has
		}
	}
	return true
}

// admitted is whether a Syscall call is a pair sys.OwnSyscall admits (A10 F1, F10): its trap and, where the
// result depends on them, its command and flags are named constants.
func (c *fileCheck) admitted(x *ast.CallExpr) (string, bool) {
	if len(x.Args) == 0 {
		return "", false
	}
	trap, ok := c.constName(x.Args[0])
	if !ok {
		return "", false
	}
	arg := func(i int) ast.Expr {
		if i < len(x.Args) {
			return x.Args[i]
		}
		return nil
	}
	switch {
	case ownSyscallTraps[trap]:
		return trap, true
	case trap == "SYS_BPF":
		cmd, ok := c.constName(arg(1))
		return trap, ok && bpfFDCommands[cmd]
	case trap == "SYS_SECCOMP":
		op, ok := c.constName(arg(1))
		has, _ := c.flag(arg(2), "SECCOMP_FILTER_FLAG_NEW_LISTENER")
		return trap, ok && op == "SECCOMP_SET_MODE_FILTER" && has
	case trap == "SYS_LANDLOCK_CREATE_RULESET":
		v, cv := c.flag(arg(3), "LANDLOCK_CREATE_RULESET_VERSION")
		e, ce := c.flag(arg(3), "LANDLOCK_CREATE_RULESET_ERRATA")
		return trap, cv && ce && !v && !e
	}
	return trap, false
}

func (c *fileCheck) fcntl(x *ast.CallExpr, cmd ast.Expr) {
	name, ok := c.constName(cmd)
	switch {
	case !ok:
		c.add(x, kFcntl, "fcntl with a command that is not a named constant (F_DUPFD is 0)")
	case name == "F_DUPFD" || name == "F_DUPFD_CLOEXEC":
		// counted where a constant names it (ref)
	case !fcntlAllowed[name]:
		c.add(x, kFcntl, "fcntl "+name)
	}
}

// recvmsg checks a recvmsg wrapper whose control buffer can receive descriptors: its flags carry MSG_CMSG_CLOEXEC
// (F9).
func (c *fileCheck) recvmsg(x *ast.CallExpr, name string, r recvRule) {
	if r.flags >= len(x.Args) || c.info.Types[x.Args[r.oob]].IsNil() {
		return
	}
	switch has, constant := c.flag(x.Args[r.flags], "MSG_CMSG_CLOEXEC"); {
	case has:
	case !constant:
		c.add(x, kCloexec, name+" with a control buffer and flags that are not a constant expression carrying MSG_CMSG_CLOEXEC")
	default:
		c.add(x, kCloexec, name+" with a control buffer and without MSG_CMSG_CLOEXEC")
	}
}

func (c *fileCheck) unshare(x *ast.CallExpr, flags ast.Expr) {
	has, constant := c.flag(flags, "CLONE_FILES")
	switch {
	case !constant:
		c.add(x, kUnshare, "unshare with flags that are not a constant expression")
	case has:
		c.add(x, kUnshare, "unshare(CLONE_FILES)")
	}
}

// cloexec checks an owned producer call's flags (F9).
func (c *fileCheck) cloexec(x *ast.CallExpr, name string) {
	r, ok := cloexecRules[name]
	if !ok {
		if contains(otherShapes, name) {
			return // cannot be an Own argument; the compiler refuses it
		}
		c.add(x, kCloexec, "no close-on-exec rule is known for "+name)
		return
	}
	c.cloexecArg(x, name, r)
}

func (c *fileCheck) cloexecArg(x *ast.CallExpr, name string, r cloexecRule) {
	switch {
	case r.kernel:
		return
	case r.unread != "":
		c.add(x, kCloexec, r.unread)
		return
	case r.arg < 0:
		c.add(x, kCloexec, name+" cannot make its number close-on-exec")
		return
	case r.arg >= len(x.Args):
		c.add(x, kCloexec, name+" without its flags argument")
		return
	}
	e := x.Args[r.arg]
	if r.how {
		e = c.howFlags(e)
		if e == nil {
			c.add(x, kCloexec, name+"'s OpenHow is not a literal whose Flags can be read")
			return
		}
	}
	switch has, constant := c.flag(e, r.flag); {
	case has:
	case !constant:
		c.add(x, kCloexec, name+" with flags that are not a constant expression carrying "+r.flag)
	default:
		c.add(x, kCloexec, name+" without "+r.flag)
	}
}

// howFlags is the Flags field of an &unix.OpenHow{...} or unix.OpenHow{...} literal.
func (c *fileCheck) howFlags(e ast.Expr) ast.Expr {
	e = ast.Unparen(e)
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND {
		e = ast.Unparen(u.X)
	}
	cl, ok := e.(*ast.CompositeLit)
	if !ok {
		return nil
	}
	for _, el := range cl.Elts {
		if kv, ok := el.(*ast.KeyValueExpr); ok {
			if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "Flags" {
				return kv.Value
			}
		}
	}
	return nil
}

// constName resolves e to the name of the unix or syscall constant it names, through parentheses, conversions
// and the module's constants whose declared value names one (in any package of the module).
func (c *fileCheck) constName(e ast.Expr) (string, bool) { return c.w.constName(c.info, e, 0) }

func (w *typedWorld) constName(info *types.Info, e ast.Expr, depth int) (string, bool) {
	if e == nil || depth > 8 {
		return "", false
	}
	e = ast.Unparen(e)
	if call, ok := e.(*ast.CallExpr); ok && len(call.Args) == 1 && info.Types[call.Fun].IsType() {
		return w.constName(info, call.Args[0], depth+1)
	}
	var id *ast.Ident
	switch x := e.(type) {
	case *ast.Ident:
		id = x
	case *ast.SelectorExpr:
		id = x.Sel
	default:
		return "", false
	}
	k, ok := info.Uses[id].(*types.Const)
	if !ok {
		return "", false
	}
	if isUnix(pkgPath(k)) {
		return k.Name(), true
	}
	if v, ok := w.consts[k]; ok {
		if dp := w.pkgOf(k); dp != nil {
			return w.constName(dp.info, v, depth+1)
		}
	}
	return "", false
}

// flag reports whether e sets the bit of the unix (or syscall) constant want, and whether e is constant: a
// constant carries the bit by its value; anything else carries it only when it is ORed in at the top level
// (through parentheses and conversions), since any other operator could clear it.
func (c *fileCheck) flag(e ast.Expr, want string) (has, isConst bool) {
	if e == nil {
		return false, false
	}
	bit := c.w.unixConst(want)
	if tv := c.info.Types[e]; tv.Value != nil {
		v := constant.ToInt(tv.Value)
		if bit == nil || v.Kind() != constant.Int {
			return false, true
		}
		return constant.Sign(constant.BinaryOp(v, token.AND, bit)) != 0, true
	}
	switch x := ast.Unparen(e).(type) {
	case *ast.BinaryExpr:
		if x.Op == token.OR {
			lh, _ := c.flag(x.X, want)
			rh, _ := c.flag(x.Y, want)
			return lh || rh, false
		}
	case *ast.CallExpr:
		if len(x.Args) == 1 && c.info.Types[x.Fun].IsType() {
			h, _ := c.flag(x.Args[0], want)
			return h, false
		}
	}
	return false, false
}

// unixConst is the value of x/sys/unix's (or else syscall's) constant name under the world's configuration.
func (w *typedWorld) unixConst(name string) constant.Value {
	for _, p := range []string{pathUnix, pathSyscall} {
		if pk := w.std[p]; pk != nil {
			if k, ok := pk.Scope().Lookup(name).(*types.Const); ok {
				return constant.ToInt(k.Val())
			}
		}
	}
	return nil
}

// constOrNil is whether e is nil or a constant.
func (c *fileCheck) constOrNil(e ast.Expr) bool {
	tv := c.info.Types[e]
	return tv.IsNil() || tv.Value != nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// ref judges a reference that is not the function of a judged call: a forbidden constant, a function or method
// taken as a value, a lender taken as a value, and every use of an Fd or FD method.
func (c *fileCheck) ref(id *ast.Ident) {
	obj := c.info.Uses[id]
	if obj == nil {
		return
	}
	var node ast.Node = id
	var sel *types.Selection
	if se, ok := c.parents[id].(*ast.SelectorExpr); ok && se.Sel == id {
		node, sel = se, c.info.Selections[se]
	}
	callee := c.isCallee(id)
	path := pkgPath(obj)
	if fdShaped(obj) && (sel != nil || obj.Pkg() != nil) {
		switch {
		case callee && obj.Name() == "FD":
			c.add(node, kFd, "a call of FD() (a number borrowed without a lease)")
		case callee:
			c.add(node, kFd, "a call of Fd()")
		case sel != nil && sel.Kind() == types.MethodExpr:
			c.add(node, kFd, "the method expression ."+obj.Name()+" (a number borrowed without a lease)")
		default:
			c.add(node, kFd, "the method value ."+obj.Name()+" (a number borrowed without a lease)")
		}
		return
	}
	switch o := obj.(type) {
	case *types.Const:
		// A forbidden x/sys constant is a site where it is named, and so is every use of a module constant that
		// names one, in any package: one declaration pays for no other close, dup or rights decode.
		if isUnix(path) {
			if k, ok := forbiddenConst(o.Name()); ok {
				c.add(node, k, pkgName(path)+"."+o.Name())
			}
		} else if name, ok := c.constName(node.(ast.Expr)); ok {
			if k, ok := forbiddenConst(name); ok {
				c.add(node, k, o.Name()+", a module constant naming "+name)
			}
		}
		return
	case *types.Func:
		if callee {
			return // judged by call
		}
		fn := o.Origin()
		name := fn.Name()
		method := isMethod(fn)
		switch {
		case isUnix(path) && !method:
			if k, ok := c.unixValueKind(path, name); ok {
				c.add(node, k, pkgName(path)+"."+name+" taken as a value")
			}
		case path == pathOS && name == "NewFile" && !method:
			c.add(node, kNewFile, "os.NewFile taken as a value")
		case taker(path, name) && !method:
			c.add(node, kFromFD, name+" taken as a value")
		case path == pathSys && !method:
			switch {
			case sysIntProducers[name]:
				c.add(node, kProducer, "sys."+name+" taken as a value")
			case sysConstructors[name] || name == "Strict" || name == "InertForTest" || name == sweepFunc:
				c.add(node, kFuncValue, "sys."+name+" taken as a value")
			}
		case path == pathSys && method && (name == "ReleaseNumber" || name == "Abandon" || name == "Hold" || name == "Num"):
			c.add(node, kFuncValue, "the method value ."+name+" (its later call escapes F2 and F3)")
		}
		if _, ok := c.ls.lenderOf(fn); ok {
			c.add(node, kLease, "the lender "+name+" taken as a value (its later call hides the callback)")
		}
	}
}

// unixValueKind is the kind of a unix or syscall function taken as a value: call() judges each of these by
// its arguments, which the value's later call hides.
func (c *fileCheck) unixValueKind(path, name string) (string, bool) {
	if k, ok := forbiddenCall[name]; ok {
		return k, true
	}
	switch {
	case c.producer(path, name):
		return kProducer, true
	case syscallFamily[name]:
		return kTrap, true
	case strings.HasPrefix(name, "Fcntl"):
		return kFcntl, true
	case name == "Unshare":
		return kUnshare, true
	case recvRules[name] != recvRule{}:
		return kCloexec, true
	case strings.HasPrefix(name, "Ioctl") && !ioctlFixed[name]:
		return kIoctl, true
	}
	return "", false
}

// isPidFD is whether a selector is the PidFD field of syscall.SysProcAttr, or of any struct type identical to
// it (a defined type of it, an alias, or a mirror struct that converts to it): the struct the field is declared
// in decides, through embedding too.
func (c *fileCheck) isPidFD(se *ast.SelectorExpr) bool {
	sel := c.info.Selections[se]
	if sel == nil || sel.Kind() != types.FieldVal || sel.Obj().Name() != "PidFD" {
		return false
	}
	t := sel.Recv()
	var st *types.Struct
	for _, i := range sel.Index() {
		st, _ = deref(t).Underlying().(*types.Struct)
		if st == nil {
			return false
		}
		t = st.Field(i).Type()
	}
	return c.ls.isSysProcAttr(st)
}

// pidfdLiteral judges a composite literal of SysProcAttr, or of a struct type identical to it, whatever the
// literal's type syntax says (elided, an alias, a defined type, a mirror): a PidFD that is not nil or a constant,
// keyed or by position, makes the start write a pidfd no owner holds.
func (c *fileCheck) pidfdLiteral(x *ast.CompositeLit) {
	st, ok := deref(c.info.TypeOf(x)).Underlying().(*types.Struct)
	if !ok || !c.ls.isSysProcAttr(st) {
		return
	}
	for i, el := range x.Elts {
		if kv, ok := el.(*ast.KeyValueExpr); ok {
			if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "PidFD" && !c.constOrNil(kv.Value) {
				c.add(kv, kProducer, "SysProcAttr.PidFD (the start writes a pidfd no owner holds)")
			}
			continue
		}
		if i < st.NumFields() && st.Field(i).Name() == "PidFD" && !c.constOrNil(el) {
			c.add(el, kProducer, "SysProcAttr.PidFD by position (the start writes a pidfd no owner holds)")
		}
	}
}

// pidfdUnsafe judges a conversion of an unsafe.Pointer to SysProcAttr (or a struct identical to it, or a pointer
// to one): memory fdcheck cannot see written becomes the attributes a start reads, PidFD included.
func (c *fileCheck) pidfdUnsafe(x *ast.CallExpr) {
	if len(x.Args) != 1 || !c.info.Types[x.Fun].IsType() {
		return
	}
	st, ok := deref(c.info.TypeOf(x.Fun)).Underlying().(*types.Struct)
	if !ok || !c.ls.isSysProcAttr(st) {
		return
	}
	if b, ok := c.info.TypeOf(x.Args[0]).Underlying().(*types.Basic); ok && b.Kind() == types.UnsafePointer {
		c.add(x, kProducer, "a SysProcAttr made from an unsafe.Pointer (its PidFD is written where fdcheck cannot see)")
	}
}

// leaseIn is whether t holds a *sys.Lease: the type itself, or a pointer, slice, array, map, channel, function
// or unnamed struct of one. A named type's own declaration is judged where it is declared.
func leaseIn(lease *types.TypeName, t types.Type, depth int) bool {
	if lease == nil || t == nil || depth > 16 {
		return false
	}
	t = types.Unalias(t)
	switch x := t.(type) {
	case *types.Named:
		return x.Obj() == lease
	case *types.Pointer:
		return leaseIn(lease, x.Elem(), depth+1)
	case *types.Slice:
		return leaseIn(lease, x.Elem(), depth+1)
	case *types.Array:
		return leaseIn(lease, x.Elem(), depth+1)
	case *types.Chan:
		return leaseIn(lease, x.Elem(), depth+1)
	case *types.Map:
		return leaseIn(lease, x.Key(), depth+1) || leaseIn(lease, x.Elem(), depth+1)
	case *types.Struct:
		for i := 0; i < x.NumFields(); i++ {
			if leaseIn(lease, x.Field(i).Type(), depth+1) {
				return true
			}
		}
	case *types.Signature:
		for _, tu := range []*types.Tuple{x.Params(), x.Results()} {
			for i := 0; i < tu.Len(); i++ {
				if leaseIn(lease, tu.At(i).Type(), depth+1) {
					return true
				}
			}
		}
	}
	return false
}

// lease checks a Hold (F2). Its result is assigned to a local variable, and the statement after the Hold in its
// block, past only the Hold's own check (`if err != nil { return }`, `if l == nil || err != nil { return }`), is
// one of two forms: (a) `defer l.Return()`, with the Hold in no loop of its function, since a deferred Return runs
// only when the function returns; or (b) `go func(p *sys.Lease) { defer p.Return(); ... }(l)`, its hand-off. A
// defer or hand-off anywhere else (on a branch, after an early return, in a loop) can leak the lease, which blocks
// its owner's close for the life of the process. In form (a) the lease is used only
// by its Num, that deferred Return and a nil comparison: an explicit Return ends the numbers its Num lent while
// the holder still has them. In form (b) the holding function uses it only by a nil comparison and
// the hand-off, since the goroutine may return it at once, and the goroutine uses its parameter only by its Num,
// its first statement's Return and a nil comparison. The lease is never captured by another function literal.
func (c *fileCheck) lease(x *ast.CallExpr) {
	as, ok := c.parents[x].(*ast.AssignStmt)
	if !ok || len(as.Rhs) != 1 || len(as.Lhs) != 2 {
		c.add(x, kLease, "a Hold whose lease is not assigned to a variable")
		return
	}
	lv, ok := as.Lhs[0].(*ast.Ident)
	if !ok || lv.Name == "_" {
		c.add(x, kLease, "a Hold whose lease is not assigned to a local variable")
		return
	}
	obj := c.info.ObjectOf(lv)
	body, _, _ := c.enclosingBody(as)
	if v, isVar := obj.(*types.Var); body == nil || !isVar || v.Pos() < body.Pos() || v.Pos() > body.End() {
		c.add(x, kLease, "a Hold whose lease is not assigned to a local variable")
		return
	}
	isL := func(e ast.Expr) bool {
		id, ok := ast.Unparen(e).(*ast.Ident)
		return ok && c.info.Uses[id] == obj
	}
	var ret *ast.CallExpr // form (a)'s deferred Return
	var handoff *ast.FuncLit
	var handoffCall *ast.CallExpr
	switch y := c.nextStmt(as, c.identObj(as.Lhs[1]), obj).(type) {
	case *ast.DeferStmt:
		if returnOf(y.Call, isL) {
			ret = y.Call
		}
	case *ast.GoStmt:
		if fl, ok := y.Call.Fun.(*ast.FuncLit); ok {
			for i, a := range y.Call.Args {
				if isL(a) && c.handsOff(fl, i) {
					handoff, handoffCall = fl, y.Call
				}
			}
		}
	}
	switch {
	case ret == nil && handoff == nil:
		c.add(x, kLease, "a Hold not followed in its block, past its own error check, by `defer "+lv.Name+
			".Return()` or its hand-off goroutine, so some path leaks the lease")
		return
	case ret != nil && (c.inLoop(as) || gotoAround(body, as)):
		c.add(x, kLease, "a Hold in a loop: its deferred Return runs only when the function returns, so every "+
			"iteration's lease stays out until then")
		return
	}
	bad := ""
	// The walk does not descend into a function literal, so a use there is a capture, but for the hand-off's own
	// literal, whose parameter is held to the goroutine's uses.
	ast.Inspect(body, func(n ast.Node) bool {
		switch y := n.(type) {
		case *ast.FuncLit:
			if y != handoff {
				ast.Inspect(y.Body, func(m ast.Node) bool {
					if id, ok := m.(*ast.Ident); ok && isL(id) && bad == "" {
						bad = "the lease is captured by a function literal"
					}
					return bad == ""
				})
			} else if p := c.handoffParam(y, handoffCall, isL); p != nil && bad == "" {
				bad = c.leaseUses(y, p)
			}
			return false
		case *ast.Ident:
			switch {
			case !isL(y) || bad != "" || c.leaseUse(y, handoffCall, ret):
			case handoff != nil:
				bad = "the holding function uses the lease besides handing it off, and the goroutine may already have returned it"
			default:
				bad = "the lease is used other than by its Num and its deferred Return, where a number it lent may outlive it"
			}
		}
		return true
	})
	if bad != "" {
		c.add(x, kLease, bad)
	}
}

// returnOf is whether call is `l.Return()` on the lease isL names.
func returnOf(call *ast.CallExpr, isL func(ast.Expr) bool) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Return" && isL(sel.X) && len(call.Args) == 0
}

// inLoop is whether n is inside a for or range statement of its own function.
func (c *fileCheck) inLoop(n ast.Node) bool {
	for p := c.parents[n]; p != nil; p = c.parents[p] {
		switch p.(type) {
		case *ast.ForStmt, *ast.RangeStmt:
			return true
		case *ast.FuncLit, *ast.FuncDecl:
			return false
		}
	}
	return false
}

// gotoAround is whether a goto in body (outside its function literals, which have labels of their own) jumps
// back across n: the goto is after n and its label before it, so n may run again before the function returns, a
// loop that inLoop does not see.
func gotoAround(body *ast.BlockStmt, n ast.Node) bool {
	labels := map[string]token.Pos{}
	var gotos []*ast.BranchStmt
	ast.Inspect(body, func(m ast.Node) bool {
		switch y := m.(type) {
		case *ast.FuncLit:
			return false
		case *ast.LabeledStmt:
			labels[y.Label.Name] = y.Pos()
		case *ast.BranchStmt:
			if y.Tok == token.GOTO && y.Label != nil {
				gotos = append(gotos, y)
			}
		}
		return true
	})
	for _, g := range gotos {
		if at, ok := labels[g.Label.Name]; ok && g.Pos() > n.Pos() && at < n.Pos() {
			return true
		}
	}
	return false
}

// leaseUse is whether a use of a lease is one F2 admits: a comparison (with nil), the argument of its hand-off go
// statement, and, when it is not handed off, the receiver of a call of its Num or of ret, the one Return F2
// admits.
func (c *fileCheck) leaseUse(id *ast.Ident, handoff, ret *ast.CallExpr) bool {
	switch p := c.parents[id].(type) {
	case *ast.SelectorExpr:
		call, ok := c.parents[p].(*ast.CallExpr)
		if !ok || call.Fun != p || p.X != id || handoff != nil {
			return false
		}
		return p.Sel.Name == "Num" || (p.Sel.Name == "Return" && call == ret)
	case *ast.BinaryExpr:
		return p.Op == token.EQL || p.Op == token.NEQ
	case *ast.CallExpr:
		return handoff != nil && p == handoff
	}
	return false
}

// handoffParam is the hand-off goroutine's parameter that receives the lease.
func (c *fileCheck) handoffParam(fl *ast.FuncLit, call *ast.CallExpr, isL func(ast.Expr) bool) types.Object {
	i := 0
	for _, f := range fl.Type.Params.List {
		n := len(f.Names)
		if n == 0 {
			n = 1
		}
		for k := 0; k < n; k++ {
			if i < len(call.Args) && isL(call.Args[i]) && k < len(f.Names) {
				return c.info.Defs[f.Names[k]]
			}
			i++
		}
	}
	return nil
}

// leaseUses holds the hand-off goroutine's lease p to the same uses: its Num and the Return its first statement
// defers (handsOff), never captured.
func (c *fileCheck) leaseUses(fl *ast.FuncLit, p types.Object) string {
	ret := fl.Body.List[0].(*ast.DeferStmt).Call
	bad := ""
	ast.Inspect(fl.Body, func(n ast.Node) bool {
		switch y := n.(type) {
		case *ast.FuncLit:
			ast.Inspect(y.Body, func(m ast.Node) bool {
				if id, ok := m.(*ast.Ident); ok && c.info.Uses[id] == p && bad == "" {
					bad = "the handed-off lease is captured by a function literal"
				}
				return bad == ""
			})
			return false
		case *ast.Ident:
			if c.info.Uses[y] == p && bad == "" && !c.leaseUse(y, nil, ret) {
				bad = "the handed-off lease is used other than by its Num and its deferred Return, where a number it lent may outlive it"
			}
		}
		return bad == ""
	})
	return bad
}

// handsOff is whether a goroutine's literal takes the lease as parameter i and returns it by defer in its first
// statement.
func (c *fileCheck) handsOff(fl *ast.FuncLit, i int) bool {
	var params []*ast.Ident
	for _, f := range fl.Type.Params.List {
		if len(f.Names) == 0 {
			params = append(params, nil)
		}
		params = append(params, f.Names...)
	}
	if i >= len(params) || params[i] == nil || len(fl.Body.List) == 0 {
		return false
	}
	d, ok := fl.Body.List[0].(*ast.DeferStmt)
	if !ok {
		return false
	}
	sel, ok := d.Call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Return" || len(d.Call.Args) != 0 {
		return false
	}
	id, ok := ast.Unparen(sel.X).(*ast.Ident)
	return ok && c.info.Uses[id] != nil && c.info.Uses[id] == c.info.Defs[params[i]]
}

// apiFunc checks an exported function or method (F8).
func (c *fileCheck) apiFunc(fd *ast.FuncDecl) {
	if !fd.Name.IsExported() {
		return
	}
	name := fd.Name.Name
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		rn := recvName(fd.Recv.List[0].Type)
		if !ast.IsExported(rn) {
			return
		}
		name = rn + "." + name
	}
	if what, bad := numberShape(c.info, fd.Name.Name, fd.Type); bad {
		c.add(fd.Name, kAPI, name+" "+what)
	}
}

// apiType checks an exported interface's exported methods (F8).
func (c *fileCheck) apiType(ts *ast.TypeSpec) {
	it, ok := ts.Type.(*ast.InterfaceType)
	if !ok || !ts.Name.IsExported() {
		return
	}
	for _, m := range it.Methods.List {
		ft, ok := m.Type.(*ast.FuncType)
		if !ok {
			continue
		}
		for _, n := range m.Names {
			if !n.IsExported() {
				continue
			}
			if what, bad := numberShape(c.info, n.Name, ft); bad {
				c.add(n, kAPI, ts.Name.Name+"."+n.Name+" "+what)
			}
		}
	}
}

// numberShape is whether a signature takes or returns a bare descriptor number: an int, int32 or uintptr (by
// its type, through the package's own names for them) named fd or ending in fd or FD, or an unnamed one
// returned by a function whose name ends in FD or Fd.
func numberShape(info *types.Info, name string, ft *ast.FuncType) (string, bool) {
	isNum := func(e ast.Expr) bool {
		t := info.TypeOf(e)
		if t == nil {
			return false
		}
		b, ok := t.Underlying().(*types.Basic)
		return ok && (b.Kind() == types.Int || b.Kind() == types.Int32 || b.Kind() == types.Uintptr)
	}
	fdName := func(n string) bool {
		return n == "fd" || strings.HasSuffix(n, "fd") || strings.HasSuffix(n, "FD") || strings.HasSuffix(n, "Fd")
	}
	check := func(fl *ast.FieldList, what string) (string, bool) {
		if fl == nil {
			return "", false
		}
		for _, f := range fl.List {
			if !isNum(f.Type) {
				continue
			}
			for _, n := range f.Names {
				if fdName(n.Name) {
					return what + " " + n.Name + " is a bare number", true
				}
			}
			if len(f.Names) == 0 && what == "returns" && (strings.HasSuffix(name, "FD") || strings.HasSuffix(name, "Fd")) {
				return "returns a bare number", true
			}
		}
		return "", false
	}
	if s, bad := check(ft.Params, "takes"); bad {
		return s, true
	}
	return check(ft.Results, "returns")
}

// sortedKeys is a map's keys, sorted.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
