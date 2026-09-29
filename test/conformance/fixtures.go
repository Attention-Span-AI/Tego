// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"bytes"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"

	tables "github.com/attention-span-ai/tego/spec/policy/conformance"
)

// TableVersion is the schema the handwritten tables are written in (spec/policy/conformance/README.md).
const TableVersion = 2

// Fixtures returns the handwritten fixtures: every table in spec/policy/conformance (table schema v2, its README),
// in file order, then each fixture's declared variants. An invalid table panics: it is a construction error of the
// suite, which TestParseTableIsStrict and TestCellTableIsWellFormed hold the tables to.
func Fixtures() []Fixture {
	fs, _, err := LoadTables()
	if err != nil {
		panic(err)
	}
	return fs
}

// DeferredCell is a cell a table names and does not run, with the reason, so the later spaces of ADR 0017 find it.
type DeferredCell struct{ Name, Why string }

// Deferred lists every table's deferred cells, each named fixture/name.
func Deferred() []DeferredCell {
	_, d, err := LoadTables()
	if err != nil {
		panic(err)
	}
	return d
}

// LoadTables reads every embedded table, checks it against schema v2 and builds its fixtures, variants included.
func LoadTables() ([]Fixture, []DeferredCell, error) {
	names, err := tables.List()
	if err != nil {
		return nil, nil, err
	}
	var base []Fixture
	var variants [][]string
	var deferred []DeferredCell
	seen := map[string]string{}
	for _, name := range names {
		data, err := tables.Read(name)
		if err != nil {
			return nil, nil, err
		}
		fx, vs, d, err := parseTable(data)
		if err != nil {
			return nil, nil, fmt.Errorf("spec/policy/conformance/%s: %w", name, err)
		}
		if prev, dup := seen[fx.Name]; dup {
			return nil, nil, fmt.Errorf("spec/policy/conformance/%s: fixture %q is also %s's", name, fx.Name, prev)
		}
		seen[fx.Name] = name
		base, variants, deferred = append(base, fx), append(variants, vs), append(deferred, d...)
	}
	out := append([]Fixture(nil), base...)
	for i := range base {
		for _, v := range variants[i] {
			fx, err := variantOf(base[i], v)
			if err != nil {
				return nil, nil, fmt.Errorf("spec/policy/conformance: %s: %w", base[i].Name, err)
			}
			out = append(out, fx)
		}
	}
	return out, deferred, nil
}

// table is one file of schema v2: one fixture.
type table struct {
	Version  int
	Name     string
	Contract string
	Dirs     []string
	Files    map[string]string
	Scripts  map[string]string
	Actors   []string
	// ExecOnlyActors: Fixture.ExecOnlyActors.
	ExecOnlyActors []string `yaml:"exec_only_actors"`
	Links          map[string]string
	HardLinks      map[string]string `yaml:"hard_links"`
	Fifos          []string
	// ThirdPartyDeny: Fixture.ThirdPartyDeny.
	ThirdPartyDeny []string `yaml:"third_party_deny"`
	// Later: Fixture.Later.
	Later  map[string]string
	Mounts []struct {
		Kind, At, From, Lower, Upper, Work string
		Subvolumes                         []string
		Files                              map[string]string
	}
	Listeners bool
	Model     struct {
		Write       []string
		DenyRead    []string `yaml:"deny_read"`
		ExecAllow   []string `yaml:"exec_allow"`
		NetDeclared bool     `yaml:"net_declared"`
		NetAllow    []string `yaml:"net_allow"`
		NetRuntime  []string `yaml:"net_runtime"`
		DenyWrite   []string `yaml:"deny_write"`
		// DenyWriteDeclared: the members of deny_write the contract declares in fs.deny_write (ADR 0071).
		DenyWriteDeclared []string `yaml:"deny_write_declared"`
		ExecDeny          []string `yaml:"exec_deny"`
		// ExecAllowCommands: the exec.allow entries with words, as `<command> <words...>` (ADR 0048 (1)).
		ExecAllowCommands []string `yaml:"exec_allow_commands"`
		// ExecAnonymous: the contract sets exec: {anonymous: true} (SEMANTICS §4).
		ExecAnonymous bool `yaml:"exec_anonymous"`
		// Keyring: the contract says keyring: true (SEMANTICS §1).
		Keyring bool
		// HostSockets: the contract says host_sockets: true (SEMANTICS §1, ADR 0070).
		HostSockets bool `yaml:"host_sockets"`
		// Reads: the contract's fs.reads (ADR 0069), "" for the default.
		Reads string
		// Names: Model.Names.
		Names []NameEntry
	}
	Variants []string
	Cells    []struct {
		Name, Op, Path, Dest, Canon, Addr string
		Target                            string
		Script                            string
		ScriptArg                         string `yaml:"script_arg"`
		Argv                              []string
		Runs                              string
		Want                              map[string]tableWant
		WantWhere                         []tableCond `yaml:"want_where"`
		Unasked                           map[string]string
		Source                            string
		NoCompile                         string `yaml:"no_compile"`
		Finding                           string
		FindingAt                         Tier `yaml:"finding_at"`
		Exception                         string
		ExceptionAt                       Tier `yaml:"exception_at"`
	}
	Deferred []struct{ Name, Why string }
}

// columns maps a want key to the expectations it sets: the three columns, and the shorthands root (tier cgroup
// on the listener and the plane, which SEMANTICS gives one answer unless it says otherwise) and all.
var columns = map[string][]Key{
	"landlock":        {{TierLandlock, ModeNone}},
	"cgroup/fanotify": {{TierCgroup, ModeFanotify}},
	// The plane column answers tier cgroup in the plane modes fmod_ret and lsm and tier bpflsm: one set of hooks
	// and one row compiler decide them (ADR 0019, ADR 0024), and compile --test's bpflsm column is its answer.
	"plane": {{TierBPFLSM, ModeLSM}},
	"root":  {{TierCgroup, ModeFanotify}, {TierBPFLSM, ModeLSM}},
	"all":   {{TierLandlock, ModeNone}, {TierCgroup, ModeFanotify}, {TierBPFLSM, ModeLSM}},
}

// ops are the actions a cell may take (cells.go).
var ops = map[string]bool{
	OpRead: true, OpWriteOpen: true, OpCreate: true, OpCreat: true, OpOpenTrunc: true, OpTruncate: true, OpUnlink: true, OpRmdir: true,
	OpMkdir: true, OpRename: true, OpExchange: true, OpSymlink: true, OpLink: true, OpChmod: true, OpExec: true,
	OpMapExec: true, OpConnectTCP: true, OpConnectUDP: true, OpSendUDP: true, OpConnectUnix: true,
	OpExecLoader: true, OpExecveatFD: true, OpExecProcFD: true, OpMemfdCreate: true, OpMemfdExec: true, OpMemfdMapExec: true,
	OpMapExecRIE: true, OpMprotectExec: true, OpMprotectRIE: true, OpExecmod: true, OpExecmem: true,
	OpChown: true, OpSetxattr: true, OpSetfacl: true, OpMknod: true, OpRaceSymlinkRead: true, OpRaceSymlinkWrite: true,
	OpRaceArgvExec: true, OpPtraceAttach: true, OpPtraceTraceme: true, OpKeyctl: true, OpAddKey: true, OpRequestKey: true, OpBPF: true,
}

func parseTable(data []byte) (Fixture, []string, []DeferredCell, error) {
	var doc table
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if err := d.Decode(&doc); err != nil {
		return Fixture{}, nil, nil, err
	}
	switch {
	case doc.Version != TableVersion:
		return Fixture{}, nil, nil, fmt.Errorf("version %d, the tables are schema %d", doc.Version, TableVersion)
	case doc.Name == "" || strings.Contains(doc.Name, "/"):
		return Fixture{}, nil, nil, fmt.Errorf("fixture name %q", doc.Name)
	case doc.Contract == "":
		return Fixture{}, nil, nil, fmt.Errorf("no contract")
	case len(doc.Cells) == 0:
		return Fixture{}, nil, nil, fmt.Errorf("no cells")
	}
	m := doc.Model
	fx := Fixture{Name: doc.Name, Contract: doc.Contract, Dirs: doc.Dirs, Files: doc.Files, Scripts: doc.Scripts,
		Actors: doc.Actors, ExecOnlyActors: doc.ExecOnlyActors, Links: doc.Links, HardLinks: doc.HardLinks, Fifos: doc.Fifos, Net: doc.Listeners, ThirdPartyDeny: doc.ThirdPartyDeny,
		Model: Model{Write: m.Write, DenyRead: m.DenyRead, ExecAllow: m.ExecAllow, NetDeclared: m.NetDeclared,
			NetAllow: m.NetAllow, NetRuntime: m.NetRuntime, DenyWrite: m.DenyWrite, DenyWriteDeclared: m.DenyWriteDeclared, ExecDeny: m.ExecDeny, ExecAnonymous: m.ExecAnonymous,
			ExecAllowCommands: m.ExecAllowCommands, Keyring: m.Keyring, HostSockets: m.HostSockets,
			Reads: m.Reads}, Later: doc.Later}
	for i, mt := range doc.Mounts {
		where := fmt.Sprintf("mounts[%d]", i)
		ok := mt.At != ""
		switch mt.Kind {
		case MountBind:
			ok = ok && mt.From != "" && mt.Lower+mt.Upper+mt.Work == "" && len(mt.Subvolumes) == 0
		case MountOverlay:
			ok = ok && mt.From == "" && mt.Lower != "" && mt.Upper != "" && mt.Work != "" && len(mt.Subvolumes) == 0
		case MountBtrfs, MountTmpfs:
			ok = ok && mt.From+mt.Lower+mt.Upper+mt.Work == "" && (mt.Kind == MountBtrfs || len(mt.Subvolumes) == 0)
		default:
			return Fixture{}, nil, nil, fmt.Errorf("%s: kind %q is none of bind, overlay, btrfs, tmpfs", where, mt.Kind)
		}
		if !ok {
			return Fixture{}, nil, nil, fmt.Errorf("%s: a %s mount names at, and from (bind), lower, upper and work (overlay) or subvolumes (btrfs) as its kind has them", where, mt.Kind)
		}
		fx.Mounts = append(fx.Mounts, Mount{Kind: mt.Kind, At: mt.At, From: mt.From, Lower: mt.Lower, Upper: mt.Upper, Work: mt.Work,
			Subvolumes: mt.Subvolumes, Files: mt.Files})
	}
	if err := laterAndNames(&fx, m.Names); err != nil {
		return Fixture{}, nil, nil, err
	}
	// The keyring invariant reads the model's flag, so it must say what the contract says (a contract that opts in
	// unmodelled would turn every keyring allow into a false fail-open; one modelled but not opted in would hide one).
	if says := slices.Contains(strings.Split(doc.Contract, "\n"), "keyring: true"); says != m.Keyring {
		return Fixture{}, nil, nil, fmt.Errorf("model.keyring is %v, but the contract's keyring: true is %v", m.Keyring, says)
	}
	if says := slices.Contains(strings.Split(doc.Contract, "\n"), "host_sockets: true"); says != m.HostSockets {
		return Fixture{}, nil, nil, fmt.Errorf("model.host_sockets is %v, but the contract's host_sockets: true is %v", m.HostSockets, says)
	}
	names := map[string]bool{}
	for _, c := range doc.Cells {
		where := fmt.Sprintf("cell %q", c.Name)
		switch {
		case c.Name == "" || strings.Contains(c.Name, "/") || names[c.Name]:
			return Fixture{}, nil, nil, fmt.Errorf("%s: a cell name is unique in its table and has no slash", where)
		case !ops[c.Op]:
			return Fixture{}, nil, nil, fmt.Errorf("%s: unknown op %q", where, c.Op)
		case c.Source == "":
			return Fixture{}, nil, nil, fmt.Errorf("%s: no source (the SEMANTICS section or spec rule it is written from)", where)
		case len(c.Want) == 0:
			return Fixture{}, nil, nil, fmt.Errorf("%s: no want", where)
		case (c.Finding == "") != (c.FindingAt == ""), c.FindingAt != "" && !knownTier(c.FindingAt):
			return Fixture{}, nil, nil, fmt.Errorf("%s: a finding names its tier (finding_at), and only with a finding", where)
		case (c.Exception == "") != (c.ExceptionAt == ""), c.ExceptionAt != "" && !knownTier(c.ExceptionAt):
			return Fixture{}, nil, nil, fmt.Errorf("%s: an exception names its tier (exception_at), and only with an exception", where)
		}
		if raceOps[c.Op] && c.Op != OpRaceArgvExec && (c.Dest == "" || c.Canon != c.Dest) {
			return Fixture{}, nil, nil, fmt.Errorf("%s: a race cell names its target as dest and as canon", where)
		}
		if c.Op == OpRaceArgvExec && (c.Path == "" || len(c.Argv) != 2 || len(c.Argv[1]) != len(RaceArgvBenign) || c.Argv[1] == RaceArgvBenign) {
			return Fixture{}, nil, nil, fmt.Errorf("%s: an argv race names its copy as path and its argv as [tool, word], the word of %d letters other than %q",
				where, len(RaceArgvBenign), RaceArgvBenign)
		}
		if targets, named := targetOps[c.Op]; (named && !slices.Contains(targets, c.Target)) || (!named && c.Target != "") {
			return Fixture{}, nil, nil, fmt.Errorf("%s: target %q: a ptrace cell names one of its op's targets %v, no other cell names one", where, c.Target, targets)
		}
		if _, control := controlOps[c.Op]; control && c.Path+c.Dest+c.Canon+c.Addr != "" {
			return Fixture{}, nil, nil, fmt.Errorf("%s: a process or control op names no path, dest, canon or addr", where)
		}
		names[c.Name] = true
		cell := Cell{Name: c.Name, Op: c.Op, Path: c.Path, Dest: c.Dest, Canon: c.Canon, Addr: c.Addr, Target: c.Target, Source: c.Source,
			NoCompile: c.NoCompile, Finding: c.Finding, FindingAt: c.FindingAt, Exception: c.Exception, ExceptionAt: c.ExceptionAt,
			Script: c.Script, ScriptArg: c.ScriptArg, Argv: c.Argv, Runs: c.Runs, Want: map[Key]Want{}}
		if err := columnWants(c.Want, cell.Want); err != nil {
			return Fixture{}, nil, nil, fmt.Errorf("%s: want %w", where, err)
		}
		for col, why := range c.Unasked {
			keys, ok := columns[col]
			if !ok || why == "" {
				return Fixture{}, nil, nil, fmt.Errorf("%s: unasked %q: a column, with the reason it is not asked", where, col)
			}
			for _, k := range keys {
				if _, asked := cell.Want[k]; asked {
					return Fixture{}, nil, nil, fmt.Errorf("%s: %v is both wanted and unasked", where, k)
				}
				if cell.Unasked == nil {
					cell.Unasked = map[Key]string{}
				}
				cell.Unasked[k] = why
			}
		}
		for i, tc := range c.WantWhere {
			cw, err := tc.cond()
			if err != nil {
				return Fixture{}, nil, nil, fmt.Errorf("%s: want_where[%d]: %w", where, i, err)
			}
			for k := range cw.Want {
				if _, ok := cell.Want[k]; !ok {
					return Fixture{}, nil, nil, fmt.Errorf("%s: want_where[%d] sets %v, which the cell's want does not", where, i, k)
				}
			}
			cell.WantWhere = append(cell.WantWhere, cw)
		}
		fx.Cells = append(fx.Cells, cell)
	}
	for _, v := range doc.Variants {
		if _, ok := variantMakers[v]; !ok {
			return Fixture{}, nil, nil, fmt.Errorf("unknown variant %q", v)
		}
	}
	var deferred []DeferredCell
	for _, dc := range doc.Deferred {
		if dc.Name == "" || dc.Why == "" || names[dc.Name] {
			return Fixture{}, nil, nil, fmt.Errorf("deferred %q: a deferred cell has a name no cell has and a reason", dc.Name)
		}
		deferred = append(deferred, DeferredCell{Name: doc.Name + "/" + dc.Name, Why: dc.Why})
	}
	return fx, doc.Variants, deferred, nil
}

func knownTier(t Tier) bool { return t == TierLandlock || t == TierCgroup || t == TierBPFLSM }

// columnWants sets out's expectations from a want's columns, each key once.
func columnWants(in map[string]tableWant, out map[Key]Want) error {
	for col, w := range in {
		keys, ok := columns[col]
		if !ok {
			return fmt.Errorf("key %q is none of landlock, cgroup/fanotify, plane, root, all", col)
		}
		for _, k := range keys {
			if _, dup := out[k]; dup {
				return fmt.Errorf("sets %v twice", k)
			}
			out[k] = w.Want
		}
	}
	return nil
}

// tableCond is one want_where entry: the machines it holds on and the columns it changes there (Cell.WantWhere).
type tableCond struct {
	KernelMin       string `yaml:"kernel_min"`
	KernelMax       string `yaml:"kernel_max"`
	BPFLSM          *bool  `yaml:"bpf_lsm"`
	MemfdNoexecSeal *bool  `yaml:"memfd_noexec_seal"`
	PlaneFirst      *bool  `yaml:"plane_first"`
	SupervisorRoot  *bool  `yaml:"supervisor_root"`
	UnixDiag        *bool  `yaml:"unix_diag"`
	Want            map[string]tableWant
}

func (tc tableCond) cond() (CondWant, error) {
	cw := CondWant{Where: Where{KernelMin: tc.KernelMin, KernelMax: tc.KernelMax, BPFLSM: tc.BPFLSM}, MemfdNoexecSeal: tc.MemfdNoexecSeal,
		PlaneFirst: tc.PlaneFirst, SupervisorRoot: tc.SupervisorRoot, UnixDiag: tc.UnixDiag, Want: map[Key]Want{}}
	switch err := cw.Where.Validate(); {
	case err != nil:
		return CondWant{}, err
	case tc.KernelMin == "" && tc.KernelMax == "" && tc.BPFLSM == nil && tc.MemfdNoexecSeal == nil && tc.PlaneFirst == nil && tc.SupervisorRoot == nil &&
		tc.UnixDiag == nil:
		return CondWant{}, fmt.Errorf("names no condition (kernel_min, kernel_max, bpf_lsm, memfd_noexec_seal, plane_first, supervisor_root, unix_diag)")
	case len(tc.Want) == 0:
		return CondWant{}, fmt.Errorf("no want")
	}
	return cw, columnWants(tc.Want, cw.Want)
}

// tableWant is one expectation, written "verdict" or "verdict rule" (the rule is the rest of the line), or as a
// mapping {verdict, rule, no_line, errno} where it needs more.
type tableWant struct{ Want }

// errnos are the errno names a want may carry.
var errnos = map[string]int{"EPERM": int(unix.EPERM), "EACCES": int(unix.EACCES), "EXDEV": int(unix.EXDEV), "ENOSYS": int(unix.ENOSYS)}

func (w *tableWant) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		w.Verdict, w.Rule, _ = strings.Cut(n.Value, " ")
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			var err error
			switch k.Value {
			case "verdict":
				err = v.Decode(&w.Verdict)
			case "rule":
				err = v.Decode(&w.Rule)
			case "no_line":
				err = v.Decode(&w.NoLine)
			case "ledger":
				if err = v.Decode(&w.Ledger); err == nil && w.Ledger != Allow && w.Ledger != Refused && w.Ledger != Observed {
					err = fmt.Errorf("line %d: ledger %q is none of %s, %s, %s", v.Line, w.Ledger, Allow, Refused, Observed)
				}
			case "errno":
				var name string
				if err = v.Decode(&name); err == nil {
					var ok bool
					if w.Errno, ok = errnos[name]; !ok {
						err = fmt.Errorf("line %d: errno %q is none of EPERM, EACCES, EXDEV, ENOSYS", v.Line, name)
					}
				}
			default:
				err = fmt.Errorf("line %d: field %s not found in a want", k.Line, k.Value)
			}
			if err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("line %d: a want is a scalar or a mapping", n.Line)
	}
	if w.Verdict != Allow && w.Verdict != Refused {
		return fmt.Errorf("line %d: verdict %q is neither %s nor %s", n.Line, w.Verdict, Allow, Refused)
	}
	return nil
}

// variantMakers derive a fixture from a table's: the same cells and expectations under a contract that changes
// how the run is carried out and not what it decides.
var variantMakers = map[string]func(Fixture) (Fixture, error){
	"held":             heldVariant,
	"assurance-kernel": assuranceKernel,
}

func variantOf(fx Fixture, name string) (Fixture, error) {
	v, err := variantMakers[name](fx)
	if err != nil {
		return Fixture{}, fmt.Errorf("variant %s: %w", name, err)
	}
	v.Cells = make([]Cell, len(fx.Cells))
	for i, c := range fx.Cells {
		c.Want = maps.Clone(c.Want)
		v.Cells[i] = c
	}
	return v, nil
}

// assuranceKernel is fx under fs.assurance: kernel (ADR 0041 D1 (a)), named fx-kernel: the same contract, cells
// and expectations, the plane's included, with the key added after the contract's write entries. compile --test
// answers each cell as for the default, since the key changes which runs start, not what a started run decides;
// the kernel runner checks the cells where a decision plane decides the run (the plane axes, tier bpflsm), and on
// the Landlock and listener axes that the run is refused, exit 125, before the actor performs any action.
func assuranceKernel(fx Fixture) (Fixture, error) {
	k := fx
	k.Name = fx.Name + "-kernel"
	lines := strings.SplitAfter(fx.Contract, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "  write: ") {
			k.Contract = strings.Join(lines[:i+1], "") + "  assurance: kernel\n" + strings.Join(lines[i+1:], "")
			break
		}
	}
	if k.Contract == fx.Contract {
		return Fixture{}, fmt.Errorf("the contract has no fs.write line to add fs.assurance beside")
	}
	k.Model.FSAssuranceKernel = true
	return k, nil
}

// footer ends every table's contract that takes the held gate: the actor's environment and record: full.
const footer = `env:
  pass: ["PATH"]
record: full
`

// heldGate is a gate whose fs rules can score to allow or above and score none of the fixtures' actions: a read
// pattern no cell's file matches, and a write rule for outside the worktree, the run's project directory, which every cell's
// path lies in. Under completion: held every open of the run is then held and completed by the open deputy (ADR 0041
// Stage B) while no cell's verdict changes.
const heldGate = `gate:
  completion: held
  rules:
    - 'fs.read matches "*.held-never"': 90
    - fs.write outside worktree: 90
`

// heldVariant is fx with every open completed by the run's open deputy (ADR 0041 Step 8's conformance cells), named
// fx-held: the same cells and expectations, since the gate scores none of them, so the kernel runner checks that a
// held open never exceeds, nor falls short of, the kernel path's answer on every axis, symlinked spellings (link),
// the hard link out of a protected tree and the deny_write targets (denywrite) included.
func heldVariant(fx Fixture) (Fixture, error) {
	h := fx
	h.Name = fx.Name + "-held"
	if !strings.HasSuffix(fx.Contract, footer) {
		return Fixture{}, fmt.Errorf("a contract that does not end with the common footer (env.pass, record: full) cannot take the held gate")
	}
	h.Contract = strings.TrimSuffix(fx.Contract, footer) + heldGate + footer
	h.Model.HeldOpens = true
	return h, nil
}

// laterAndNames checks a table's later files and copies its model's name entries (ADR 0043). A later file is written
// into a directory the table declares, never with mounts (the mount namespace's helper runs that run, and the await
// handshake does not reach it). A name entry is exact or a prefix, the exceptions a prefix's, beneath at least one
// scope; and no declared directory is under a name one covers: a name entry never decides a directory (D1), and the
// name invariant reads a cell's names alone, so a directory under a covered name would read to it as a covered file.
func laterAndNames(fx *Fixture, names []NameEntry) error {
	if len(fx.Later) > 0 && len(fx.Mounts) > 0 {
		return fmt.Errorf("later files and mounts: the await handshake does not reach a mount namespace's run")
	}
	for rel := range fx.Later {
		parent := filepath.Dir(rel)
		_, file := fx.Files[rel]
		if filepath.IsAbs(rel) || rel != filepath.Clean(rel) || file || (parent != "." && !slices.Contains(fx.Dirs, parent)) {
			return fmt.Errorf("later %q: a clean relative path no other key names, in a directory dirs declares", rel)
		}
	}
	for i, n := range names {
		if (n.Exact == "") == (n.Prefix == "") || len(n.Scopes) == 0 || (n.Exact != "" && len(n.Except) > 0) {
			return fmt.Errorf("model.names[%d]: exact or prefix, the exceptions a prefix's, and at least one scope", i)
		}
		fx.Model.Names = append(fx.Model.Names, n)
	}
	for _, d := range fx.Dirs {
		for p := d; p != "." && p != "/"; p = filepath.Dir(p) {
			if nameMatches(fx.Model.Names, filepath.Base(p)) {
				return fmt.Errorf("dirs %q: a directory under the name %q a model name entry covers", d, filepath.Base(p))
			}
		}
	}
	return nil
}
