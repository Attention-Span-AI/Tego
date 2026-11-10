// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// MaxContractSize is the byte cap on a contract or profile file (E25).
const MaxContractSize = 1 << 20

// MaxExtendsDepth bounds the extends chain (E15).
const MaxExtendsDepth = 8

// ProfileSource resolves `extends: <name>` to bytes, rooted under the
// machine's profiles directory or a registry namespace. Implemented by
// internal/cli; this package never touches the filesystem for extends itself.
// An implementation must refuse to resolve outside its root (E7) and wrap
// os.ErrNotExist on a miss.
type ProfileSource interface {
	Resolve(name string) (path string, data []byte, err error)
}

// ProfileLocator is a ProfileSource that can also say which file it reads a
// profile name from, so an extends-not-found diagnostic names the file to
// create. It is optional: a source that cannot say (a registry) is told to
// add the profile in general terms.
type ProfileLocator interface {
	// Location is the file Resolve reads name from, "" when the name
	// resolves to no file of this source (E7).
	Location(name string) string
}

// Load reads path, decodes it with every known field checked, merges the
// extends chain through profiles and validates every §5 rule. err is nil iff
// every diagnostic is a warning; on any error diagnostic the contract is nil.
// A missing or unreadable top file is a wrapped I/O error with no diagnostic.
// profiles may be nil only when the file has no extends:.
func Load(path string, profiles ProfileSource) (*Contract, []Diagnostic, error) {
	if path == "" {
		return nil, nil, errors.New("agent: Load: empty path")
	}
	data, err := readCapped(path)
	if err != nil {
		return nil, nil, err
	}
	return LoadBytes(path, data, profiles)
}

// LoadBytes is Load for bytes already in memory (stdin, tests, fuzzing);
// path is used only to label diagnostics and the implicit contract entry.
func LoadBytes(path string, data []byte, profiles ProfileSource) (*Contract, []Diagnostic, error) {
	l := &loader{profiles: profiles, top: path}
	c, _, _ := l.load(path, data, "", nil)
	if c != nil {
		c.profiles = l.used
		l.denyReadSwitch(c)
		l.nullExecAllow(c)
		validateMerged(&l.ds, c, path)
	}
	SortDiagnostics(l.ds.list, path)
	if err := firstError(l.ds.list); err != nil {
		return nil, l.ds.list, err
	}
	c.loaded = true
	return c, l.ds.list, nil
}

// OpenFlags are the flags a contract, profile or test table is opened with. O_NONBLOCK makes opening
// a FIFO return at once instead of waiting for a writer that may never come; the read then sees end
// of file, or the writer's bytes, so `tego compile <(generate)` still works.
const OpenFlags = os.O_RDONLY | syscall.O_NONBLOCK

// readCapped opens path with OpenFlags and reads it with ReadCapped, once the file it opened passes the one-name
// rule (config.CheckOneName, R10, ADR 0059): a contract with a second name could be rewritten through it by a run
// whose write entry no R10 target is compared with, and the next run would load what that run wrote.
func readCapped(path string) ([]byte, error) {
	f, err := os.OpenFile(path, OpenFlags, 0)
	if err != nil {
		return nil, fmt.Errorf("agent: %w", err)
	}
	defer func() { _ = f.Close() }()
	uid, _ := config.InvokingUID()
	if err := config.CheckOneName(f, path, uid); err != nil {
		var ue *config.UntrustedError
		if errors.As(err, &ue) {
			return nil, untrustedContract{ue}
		}
		return nil, fmt.Errorf("agent: %w", err)
	}
	return ReadCapped(f, path)
}

// untrustedContract is a contract file the one-name rule refused, said in the contract's words (the error's own text
// names the machine config); errors.Is finds config.ErrUntrusted through it.
type untrustedContract struct{ ue *config.UntrustedError }

func (e untrustedContract) Error() string {
	return fmt.Sprintf("agent: contract %s untrusted: uid=%d mode=%04o (%s); %s", e.ue.Path, e.ue.Owner, e.ue.Mode&fs.ModePerm, e.ue.Reason, e.ue.Fix())
}

func (e untrustedContract) Unwrap() error { return e.ue }

// ReadCapped reads an input opened with OpenFlags, at most MaxContractSize+1 bytes so a YAML bomb
// never reaches the decoder (E25), and only from a regular file, a pipe or a socket: a device or a
// directory is refused by name rather than read (a tty would wait forever). A socket is standard input
// handed over as a stream, as a pipe is: Node's child_process stdio 'pipe' is a socketpair. A path names
// no socket that open(2) can read, so only a descriptor reaches here as one.
func ReadCapped(f *os.File, name string) ([]byte, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("agent: %w", err)
	}
	if m := st.Mode(); !m.IsRegular() && m.Type() != fs.ModeNamedPipe && m.Type() != fs.ModeSocket {
		return nil, fmt.Errorf("agent: %s: %w", name, ErrNotAFile)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxContractSize+1))
	if err != nil {
		return nil, fmt.Errorf("agent: read %s: %w", name, err)
	}
	return data, nil
}

type loader struct {
	profiles ProfileSource
	top      string
	ds       diags
	// emptyDenyRead is where each file of the chain wrote `deny_read: []`,
	// held for denyReadSwitch: what the switch does depends on the merge.
	emptyDenyRead []Pos
	// nullAllow is where each file of the chain wrote `exec.allow:` with no value, held for nullExecAllow.
	nullAllow []Pos
	// visited is every profile name the walk has reached (parent).
	visited map[string]*profileVisit
	// file is, for every profile file the walk has read, the first name that served it (keyed by the source's kind,
	// the path it reported and the sha256 of the bytes); same is, for every name the walk has resolved, that first
	// name. Two names one source serves from one file, a preset and its pin to the revision it is (ADR 0068), are
	// one profile: the file merges once.
	file map[string]string
	same map[string]string
	// used is every profile merged, in merge order, each once (Contract.Profiles).
	used []ProfileUse
}

// load parses one file and lays it over the profiles its extends: names (R5, ADR 0066): each parent is loaded
// beneath it first, merged with its own parents, then the parents are combined left to right by the classes of
// ADR 0065 D4, and the file goes on top. Errors are collected; the returned contract is nil only when the file
// itself could not be decoded at all. chain is the names on the path from the top file to this one (E5). kind is
// the kind of source that served the file, empty for the top file. Besides the merged file it returns the file's
// whole view (mergeScalars), what a list naming the file is checked against, and the longest chain of names beneath
// the file (E15).
func (l *loader) load(file string, data []byte, kind ProfileKind, chain []string) (merged, whole *Contract, below []string) {
	isProfile := kind != ""
	c := l.parse(file, data, isProfile)
	if c != nil && isProfile {
		contractTable.profileRules(reflect.ValueOf(c).Elem(), c.origins, &l.ds)
	}
	if c == nil || len(c.Extends) == 0 {
		return c, c, nil
	}
	// wholes is every parent the list names, each resolved in full, every ancestor counted, for the conflict check
	// and the assurance warnings: what a profile's own list means never depends on what an earlier entry reached
	// first (ADR 0066 D3). fresh is those merged here; a parent the walk merged already stays at its first position.
	var wholes, fresh []*Contract
	// listed is the profile each entry of this list named (parent's same), so a second name for a file the list
	// already named merges once with one warning at its line, as a repeated name does.
	var listed []string
	for i, name := range c.Extends {
		pos := c.origins["extends"]
		if p, ok := c.origins["extends."+strconv.Itoa(i)]; ok {
			pos = p
		}
		if slices.Contains(c.Extends[:i], name) {
			l.ds.warnf(pos, CodeRedundantRule, "extends names profile %q twice; it merges once, at its first position", name).
				fix("remove the second %s", name)
			continue
		}
		if kind == ProfileBuiltin && !IsBuiltinName(name) {
			// A built-in profile is the binary's own: a parent from a profiles directory would let a file anyone who
			// can write that directory supply part of the preset, under the preset's name (ADR 0066 D2).
			l.ds.errorf(pos, CodeExtendsNotFound, "built-in profile %s extends %q, which is not a built-in profile: a built-in profile extends only built-in profiles (%s names)", file, name, BuiltinPrefix).
				fix("this is a fault in tego's built-in profiles; extend %s from the contract instead", name)
			continue
		}
		v, again, same := l.parent(pos, name, chain)
		if same != name && slices.Contains(listed, same) {
			l.ds.warnf(pos, CodeRedundantRule, "extends names profile %q, the same file as %q; it merges once, at its first position", name, same).
				fix("remove %s: the list names that file already", name)
			continue
		}
		listed = append(listed, same)
		if len(v.below) >= len(below) {
			below = append([]string{name}, v.below...)
		}
		if v.whole != nil {
			wholes = append(wholes, v.whole)
			if !again {
				fresh = append(fresh, v.merged)
			}
		}
	}
	if len(wholes) == 0 {
		return c, c, below
	}
	base, conflicts := checkParents(wholes)
	l.fsAssuranceOutvoted(base, c)
	l.execAssuranceOutvoted(base, c)
	var written map[string]bool
	if len(conflicts) > 0 {
		written = map[string]bool{}
	}
	whole = mergeScalars(base, c, written)
	for _, x := range conflicts {
		if !written[x.path] {
			l.extendsConflict(x, file)
		}
	}
	if len(fresh) == 0 {
		return c, whole, below
	}
	return merge(combineParents(fresh), c), whole, below
}

// profileVisit is a profile the walk has reached: merged, the profile merged with those of its parents the walk had
// not merged before, and whole, its whole view (both nil when it could not be read). A profile reached twice merges
// once, at its first position (ADR 0066), while its whole view still takes part in a later list's conflict check,
// and below, the longest chain of names beneath it, still counts toward a later reach's depth.
type profileVisit struct {
	merged, whole *Contract
	below         []string
}

// parent resolves and loads the profile name, written at pos by the file at the end of chain. It returns the
// profile's visit, whether an earlier reach merged it already, and the name that first served its file (name
// itself unless an earlier reach read the same file under another name).
func (l *loader) parent(pos Pos, name string, chain []string) (profileVisit, bool, string) {
	v, again := l.parentVisit(pos, name, chain)
	if same := l.same[name]; same != "" {
		return v, again, same
	}
	return v, again, name
}

func (l *loader) parentVisit(pos Pos, name string, chain []string) (profileVisit, bool) {
	path := append(slices.Clone(chain), name)
	tooDeep := func(names []string) {
		l.ds.errorf(pos, CodeExtendsTooDeep, "extends chain deeper than %d: %s", MaxExtendsDepth, strings.Join(names, " -> ")).
			fix("flatten the profiles; each contract may extend at most %d levels", MaxExtendsDepth)
	}
	switch {
	case len(chain) >= MaxExtendsDepth:
		tooDeep(path)
		return profileVisit{}, false
	case slices.Contains(chain, name):
		l.ds.errorf(pos, CodeExtendsCycle, "extends cycle: %s", strings.Join(path, " -> ")).
			fix("remove the extends: that closes the cycle")
		return profileVisit{}, false
	}
	if v, ok := l.visited[name]; ok {
		if len(path)+len(v.below) > MaxExtendsDepth {
			tooDeep(append(path, v.below...))
		}
		return *v, true
	}
	if l.profiles == nil {
		l.ds.errorf(pos, CodeExtendsNotFound, "profile %q cannot be resolved: no profile source", name).
			fix("configure profiles: in the machine config or drop extends:")
		return profileVisit{}, false
	}
	if l.visited == nil {
		l.visited = map[string]*profileVisit{}
	}
	r := resolveProfile(l.profiles, name)
	if r.shadowed != "" {
		// The reserved namespace is never read from a profiles directory (ADR 0066 D2): a file there would read
		// as the profile its author meant to extend, and it is not.
		l.visited[name] = &profileVisit{}
		l.ds.errorf(pos, CodeShadowedBuiltin, "profile %q is in the reserved built-in namespace %s: %s in the profiles directory is never read", name, BuiltinPrefix, r.shadowed).
			fix("move %s out of %s and extend it by its new name, or remove it to use the built-in profile", r.shadowed, BuiltinPrefix)
		return profileVisit{}, false
	}
	if r.err != nil {
		l.visited[name] = &profileVisit{}
		l.notFound(pos, name, r.err)
		return profileVisit{}, false
	}
	if len(r.data) > MaxContractSize {
		l.visited[name] = &profileVisit{}
		l.ds.errorf(Pos{File: r.path, Line: 1}, CodeSchema, "%v", ErrTooLarge)
		return profileVisit{}, false
	}
	key := fmt.Sprintf("%s\x00%s\x00%x", r.kind, r.path, sha256.Sum256(r.data))
	if l.file == nil {
		l.file, l.same = map[string]string{}, map[string]string{}
	}
	if first, ok := l.file[key]; ok {
		// The file an earlier name served: once that name's load has finished, this name is that profile. A name
		// reached while the first is still loading (a profile extending its own pin) loads on, and the chain
		// reports the cycle by name.
		if v, done := l.visited[first]; done {
			l.visited[name], l.same[name] = v, first
			return *v, true
		}
	} else {
		l.file[key] = name
	}
	v := &profileVisit{}
	v.merged, v.whole, v.below = l.load(r.path, r.data, r.kind, path)
	l.visited[name] = v
	if v.merged != nil {
		l.used = append(l.used, profileUse(name, r))
	}
	return *v, false
}

// notFound reports a profile name its source could not serve, at pos.
func (l *loader) notFound(pos Pos, name string, err error) {
	var ue *config.UntrustedError
	if errors.As(err, &ue) {
		// The profile exists but fails the machine config's trust rule (R20): say so, and name what
		// failed, rather than calling it not found.
		l.ds.errorf(pos, CodeExtendsNotFound, "profile %q untrusted: %s uid=%d mode=%04o (%s)",
			name, ue.Path, ue.Owner, ue.Mode&fs.ModePerm, ue.Reason).fix("%s", ue.Fix())
		return
	}
	if IsBuiltinName(name) && errors.Is(err, os.ErrNotExist) {
		d := l.ds.errorf(pos, CodeExtendsNotFound, "built-in profile %q not found: names under %s are tego's own profiles, and this binary has none by that name", name, BuiltinPrefix)
		var known []string
		if c, ok := l.profiles.(*ProfileChain); ok {
			known = c.builtinNames()
		}
		if len(known) > 0 {
			d.fix("the built-in profiles are %s; name one of them, or remove it from extends:", strings.Join(known, ", "))
		} else {
			d.fix("check the name against tego's built-in profiles, or remove it from extends:")
		}
		return
	}
	d := l.ds.errorf(pos, CodeExtendsNotFound, "profile %q not found", name)
	if !errors.Is(err, os.ErrNotExist) {
		d.fix("%v", err)
		return
	}
	// A profile is a file its author writes. The fix used to name `tego init --profile`, a
	// flag init has never had (E6); it names the file to create instead.
	where := ""
	if loc, ok := l.profiles.(ProfileLocator); ok {
		where = loc.Location(name)
	}
	if where != "" {
		d.fix("create %s, or remove extends:; profiles: in the machine config names the directory profiles are read from", where)
	} else {
		d.fix("add a profile named %s where profiles: in the machine config points, or remove extends:", name)
	}
}

// extendsConflict reports, at both parents' lines, a contract-wins key two parents of file's extends list wrote
// with different values and file did not settle (ADR 0065 D4): a later profile never silently wins over an earlier
// one, since for command that would run a program neither author chose over the other's.
func (l *loader) extendsConflict(x extendsConflict, file string) {
	at := func(p Pos) string { return p.File + ":" + strconv.Itoa(p.Line) }
	for _, p := range []Pos{x.first, x.then} {
		l.ds.errorf(p, CodeExtendsConflict, "%s is set to different values by two profiles %s extends (%s and %s)", x.path, file, at(x.first), at(x.then)).
			fix("set %s in %s, which then decides, or make the two profiles agree", x.path, file)
	}
}

// yamlLineRE extracts the line yaml.v3 puts in its own messages.
var yamlLineRE = regexp.MustCompile(`^(?:yaml: )?line (\d+): (.*)$`)

// parse decodes one document: size cap, BOM strip (E2), YAML parse, schema
// walk (R1 and every scalar rule), then the typed decode with KnownFields.
func (l *loader) parse(file string, data []byte, isProfile bool) *Contract {
	if len(data) > MaxContractSize {
		l.ds.errorf(Pos{File: file, Line: 1}, CodeSchema, "%v", ErrTooLarge)
		return nil
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		l.yamlError(file, err, data)
		return nil
	}
	// A contract is one document. yaml.Unmarshal reads the first and ignores the rest, so a second document
	// after `---` was silently dropped, whatever rules it held.
	if n := config.YAMLDocuments(data); n > 1 {
		l.ds.errorf(Pos{File: file, Line: 1}, CodeSchema, "%s holds %d YAML documents; a contract is one", file, n).
			fix("remove every '---' separator after the first document")
		return nil
	}
	if root.Kind == 0 || len(root.Content) == 0 || isNull(root.Content[0]) {
		what := "contract"
		if isProfile {
			what = "profile"
		}
		l.ds.errorf(Pos{File: file, Line: 1}, CodeSchema, "%s is empty", what).fix("start with version: 0, name: and command:")
		return nil
	}
	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		l.ds.errorf(Pos{File: file, Line: doc.Line, Col: doc.Column}, CodeSchema, "document must be a mapping, got %s", describe(doc))
		return nil
	}
	// Aliases make the walk visit an aliased subtree once per alias, before yaml.v3's own aliasing limit in
	// the typed decode is reached: a 20 KB contract of 4000 aliases to a 4000-entry list took 12 s and 2.5 GB.
	// A contract has no use for thousands of expanded nodes, so the expansion is bounded first.
	if n := expandedNodes(doc, maxExpandedNodes); n > maxExpandedNodes {
		l.ds.errorf(Pos{File: file, Line: 1}, CodeSchema, "the document expands to more than %d YAML nodes through aliases", maxExpandedNodes).
			fix("write the values out instead of repeating an alias")
		return nil
	}
	w := walker{file: file, ds: &l.ds, origins: origins{}}
	before := len(l.ds.list)
	w.walk(doc, contractSchema, "")
	c := &Contract{file: file, origins: w.origins}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := config.GuardYAML(func() error { return dec.Decode(c) }); err != nil {
		if len(l.ds.list) == before {
			// The walk accepted the document, so this is a value the typed
			// decode could not represent; report it rather than swallow it.
			l.yamlError(file, err, data)
		}
		return nil
	}
	if len(l.ds.list) > before {
		return nil
	}
	if pos, err := normalizeSchemaOnly(c); err != nil {
		l.ds.errorf(Pos{File: file, Line: pos.Line, Col: pos.Col}, CodeSchema, "%v", err).
			fix("write the values out instead of repeating an alias")
		return nil
	}
	if c.FS != nil && c.FS.DenyRead != nil && len(c.FS.DenyRead) == 0 {
		l.emptyDenyRead = append(l.emptyDenyRead, w.origins["fs.deny_read"])
	}
	if pos, ok := w.nulls["exec."+execAllowKey]; ok {
		l.nullAllow = append(l.nullAllow, pos)
	}
	return c
}

// nullExecAllow refuses, at each file that wrote `exec.allow:` with no value (every entry commented out), a null
// allow that the merge read as absent in a section that is then a deny-list: every image may run there, though an
// allow key, even `allow: []`, restricts images (ADR 0048 (1)). The deny or ask key may be in the same file or in
// another file of the extends chain, so only the merged section can say. A null allow in a section that still
// restricts images reads as absent, as it did before ADR 0048: alone it is `exec: {}`, which restricts every image.
func (l *loader) nullExecAllow(c *Contract) {
	if !c.Exec.DenyList() {
		return
	}
	for _, pos := range l.nullAllow {
		l.ds.errorf(pos, CodeSchema, "exec.allow: has no value and reads as if absent, which with the deny or ask key in this exec: section makes it a deny-list where every image may run, not an empty list").
			fix("write `allow: []` to restrict every image, list the images, or remove the key")
	}
}

// denyReadSwitch reports, at each file that wrote `deny_read: []`, what that
// switch did to the merged contract. It runs after the merge because only the
// merged list can say: R6's tri-state is read off the Contract that Compile
// and Canonical see, and R5 unions deny_read over the chain, so a `[]` beside
// a declared entry anywhere else in the chain leaves the list populated and
// the built-in list on. A per-file "disables" warning, issued before the
// merge, would tell that author the credential list is off while it is on.
//
// The list stays on in that case rather than honouring the `[]` because
// "declared entries without the built-in list" has no spelling in agent.yaml
// (a populated deny_read always keeps it, R6), so Canonical could not write
// that merged contract down: contract_hash and the ledger's contract.yaml
// would have described a run with the list on while the run had it off (R13).
func (l *loader) denyReadSwitch(c *Contract) {
	off := c.FS != nil && c.FS.DenyRead != nil && len(c.FS.DenyRead) == 0
	for _, pos := range l.emptyDenyRead {
		if off {
			l.ds.warnf(pos, CodeDenyReadDisabled, "deny_read: [] disables the built-in list (~/.ssh, ~/.aws, ~/.netrc, ~/.gnupg, npm/git/gh/docker/kube/gcloud credentials, browser profiles, .env files)").
				fix("remove deny_read: to keep the built-in list")
			continue
		}
		l.ds.warnf(pos, CodeRedundantRule, "deny_read: [] does not disable the built-in list here: another file in the extends chain declares deny_read entries, which are never removed, and a populated deny_read keeps the built-in list").
			fix("remove deny_read: []; the built-in list can be disabled only when no file in the extends chain declares a deny_read entry")
	}
}

// fsAssuranceOutvoted warns at a file's `fs.assurance: best-effort` that the profile beneath it outvotes with
// kernel: the merge keeps the stricter value (ADR 0041 D1 (a)), and the file would otherwise read as lowering it.
func (l *loader) fsAssuranceOutvoted(base, c *Contract) {
	if base.FS == nil || base.FS.Assurance != FSAssuranceKernel || c.FS == nil || c.FS.Assurance != FSAssuranceBestEffort {
		return
	}
	l.ds.warnf(c.origins["fs.assurance"], CodeRedundantRule, "fs.assurance: best-effort does not lower the profile's fs.assurance: kernel: across extends the stricter value stands").
		fix("remove fs.assurance: here, or drop it from the profiles extends: names (%s)", strings.Join(c.Extends, ", "))
}

// execAssuranceOutvoted is fsAssuranceOutvoted for exec.assurance (ADR 0048 (3) P2).
func (l *loader) execAssuranceOutvoted(base, c *Contract) {
	if base.Exec == nil || base.Exec.Assurance != ExecAssuranceKernel || c.Exec == nil ||
		c.Exec.Assurance != ExecAssuranceBestEffort {
		return
	}
	l.ds.warnf(c.origins["exec.assurance"], CodeRedundantRule, "exec.assurance: best-effort does not lower the profile's exec.assurance: kernel: across extends the stricter value stands").
		fix("remove exec.assurance: here, or drop it from the profiles extends: names (%s)", strings.Join(c.Extends, ", "))
}

// yamlError converts a yaml.v3 error into schema diagnostics with line numbers.
func (l *loader) yamlError(file string, err error, data []byte) {
	yamlDiagnostics(&l.ds, file, err, data)
}

// yamlDiagnostics converts a yaml.v3 error in data into schema diagnostics with the line (and, for a bad
// encoding, the column) each names. A contract and a test table both parse through it, so the two report
// the same positions.
func yamlDiagnostics(ds *diags, file string, err error, data []byte) {
	var te *yaml.TypeError
	msgs := []string{err.Error()}
	if errors.As(err, &te) {
		msgs = te.Errors
	}
	for _, m := range msgs {
		line, col := 0, 0
		if sm := yamlLineRE.FindStringSubmatch(m); sm != nil {
			line, _ = strconv.Atoi(sm[1])
			m = sm[2]
		}
		if line == 0 && strings.Contains(m, "UTF-8") {
			// yaml.v3's reader reports a bad encoding with no position, and line 1 named the wrong line
			// for a byte further down: the first invalid sequence is found here.
			line, col = invalidUTF8At(data)
		}
		if line == 0 {
			line = 1
		}
		ds.errorf(Pos{File: file, Line: line, Col: col}, CodeSchema, "%s", strings.TrimPrefix(m, "yaml: "))
	}
}

// invalidUTF8At is the 1-based line and column (in bytes) of the first byte of data that does not begin a
// valid UTF-8 sequence, 0, 0 when data is valid UTF-8.
func invalidUTF8At(data []byte) (line, col int) {
	line, start := 1, 0
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size <= 1 {
			return line, i - start + 1
		}
		if data[i] == '\n' {
			line, start = line+1, i+1
		}
		i += size
	}
	return 0, 0
}

// normalizeSchemaOnly strips comments, styles and positions from the
// schema-only yaml.Node fields so Canonical() depends on structure alone, and
// zeroes an explicitly empty value so it is indistinguishable from absence (R2).
//
// Each alias in such a field is first replaced by a copy of the node it names (expandAliases). The typed decode
// does that for every other field, but these keep the parser's nodes, and stripNode then cleared the anchor and
// kept the alias: Canonical wrote `- *r` with no `&r`, so the run's contract.yaml did not load back ("unknown
// anchor"), and `rules: [&r {a: 10}, {b: 90}, *r]` and `rules: [{a: 10}, &r {b: 90}, *r]` wrote the same bytes
// and contract_hash while their gates scored the third rule differently (R13). On an error it returns the
// position of the field it could not expand.
func normalizeSchemaOnly(c *Contract) (Pos, error) {
	for _, n := range []*yaml.Node{&c.Gate, &c.Docker, &c.Ask} {
		if n.Kind != 0 {
			e, err := expandAliases(n, maxExpandedNodes)
			if err != nil {
				return Pos{Line: n.Line, Col: n.Column}, err
			}
			*n = *e
		}
		if nodeEmpty(n) {
			*n = yaml.Node{}
			continue
		}
		stripNode(n)
	}
	return Pos{}, nil
}

// expandAliases returns a copy of n in which every alias is a copy of the node it names, followed through
// aliases inside that node too, so the copy holds no alias and shares no node with n. An anchor stays (stripNode
// clears it). Parse bounds a whole document's expansion at maxExpandedNodes before the typed decode
// (expandedNodes), and yaml.v3 refuses an anchor whose node holds an alias of itself; the copy is bounded again
// by limit, by maxAliasDepth hops per alias and by nesting depth, so a node built some other way cannot make it
// run away either.
func expandAliases(n *yaml.Node, limit int) (*yaml.Node, error) {
	count := 0
	var cp func(*yaml.Node, int) (*yaml.Node, error)
	cp = func(n *yaml.Node, depth int) (*yaml.Node, error) {
		for hops := 0; n.Kind == yaml.AliasNode; hops++ {
			if n.Alias == nil || hops >= maxAliasDepth {
				return nil, fmt.Errorf("an alias chain is too deep or names no node")
			}
			n = n.Alias
		}
		if depth > maxAliasDepth*64 {
			return nil, fmt.Errorf("a value nests more than %d levels deep", maxAliasDepth*64)
		}
		if count++; count > limit {
			return nil, fmt.Errorf("the document expands to more than %d YAML nodes through aliases", limit)
		}
		out := *n
		out.Alias = nil
		if n.Content != nil {
			out.Content = make([]*yaml.Node, len(n.Content))
			for i, c := range n.Content {
				e, err := cp(c, depth+1)
				if err != nil {
					return nil, err
				}
				out.Content[i] = e
			}
		}
		return &out, nil
	}
	return cp(n, 0)
}

// nodeEmpty reports whether a schema-only node carries no value: unset, null,
// or an empty mapping or list.
func nodeEmpty(n *yaml.Node) bool {
	switch n.Kind {
	case 0:
		return true
	case yaml.ScalarNode:
		return n.ShortTag() == "!!null" || n.Value == ""
	case yaml.MappingNode, yaml.SequenceNode:
		return len(n.Content) == 0
	case yaml.DocumentNode:
		return len(n.Content) == 0 || nodeEmpty(n.Content[0])
	}
	return false
}

func stripNode(n *yaml.Node) {
	n.HeadComment, n.LineComment, n.FootComment = "", "", ""
	n.Line, n.Column = 0, 0
	n.Style = 0
	n.Anchor = ""
	for _, c := range n.Content {
		stripNode(c)
	}
}

// maxExpandedNodes bounds the YAML nodes a contract or profile may expand to through aliases. The largest
// real contract is a few hundred nodes; the bound only stops an alias fan-out.
const maxExpandedNodes = 100_000

// expandedNodes counts n's nodes with every alias followed, and stops counting past limit.
func expandedNodes(n *yaml.Node, limit int) int {
	count := 0
	var visit func(*yaml.Node, int)
	visit = func(n *yaml.Node, depth int) {
		if n == nil || count > limit || depth > maxAliasDepth*64 {
			return
		}
		count++
		if n.Kind == yaml.AliasNode {
			visit(n.Alias, depth+1)
			return
		}
		for _, c := range n.Content {
			visit(c, depth+1)
		}
	}
	visit(n, 0)
	return count
}
