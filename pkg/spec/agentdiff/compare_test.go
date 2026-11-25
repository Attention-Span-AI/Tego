// SPDX-License-Identifier: Apache-2.0

package agentdiff

import (
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// A field must be assigned explicitly. In particular Contract is a container,
// not a catch-all row that could hide a newly added authority-bearing flag.
func TestFamilyCoverage(t *testing.T) {
	for _, issue := range familyCoverageIssues(reflect.TypeFor[agent.RuleTable](), Rows()) {
		t.Error(issue)
	}
}

func familyCoverageIssues(typ reflect.Type, rows []Row) []string {
	var issues []string
	assigned := map[string]string{}
	for _, row := range rows {
		for _, path := range row.Fields {
			if old := assigned[path]; old != "" {
				issues = append(issues, path+" belongs to both "+old+" and "+row.Family)
			}
			assigned[path] = row.Family
		}
	}
	var walk func(reflect.Type, string)
	walk = func(typ reflect.Type, prefix string) {
		for _, name := range allFieldNames(typ) {
			f, _ := typ.FieldByName(name)
			path := prefix + f.Name
			if path == "Contract" {
				walk(f.Type.Elem(), "Contract.")
				continue
			}
			if assigned[path] == "" {
				issues = append(issues, path+" has no family row")
			}
			delete(assigned, path)
		}
	}
	walk(typ, "")
	for path := range assigned {
		issues = append(issues, "matrix field "+path+" does not exist")
	}
	slices.Sort(issues)
	return issues
}

func allFieldNames(typ reflect.Type) []string {
	names := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		names = append(names, typ.Field(i).Name)
	}
	return names
}

func unreviewedFields(typ reflect.Type, reviewed string) []string {
	var unknown []string
	for _, name := range allFieldNames(typ) {
		if !slices.Contains(strings.Fields(reviewed), name) {
			unknown = append(unknown, name)
		}
	}
	return unknown
}

func TestFamilyCoverageRejectsPrivateAuthority(t *testing.T) {
	type contract struct {
		Known           bool
		hiddenAuthority bool
	}
	type compiled struct {
		Contract        *contract
		Known           bool
		hiddenAuthority bool
	}
	value := compiled{Contract: &contract{hiddenAuthority: true}, hiddenAuthority: true}
	issues := familyCoverageIssues(reflect.TypeOf(value), []Row{{Family: "known", Fields: []string{"Known", "Contract.Known"}}})
	want := []string{"Contract.hiddenAuthority has no family row", "hiddenAuthority has no family row"}
	if !value.hiddenAuthority || !value.Contract.hiddenAuthority || !slices.Equal(issues, want) {
		t.Fatalf("private authority escaped ownership: %v; want %v", issues, want)
	}
}

func TestClassifiedFieldCoverageRejectsPrivateAuthority(t *testing.T) {
	type nestedClassified struct {
		Known           bool
		hiddenAuthority bool
	}
	value := nestedClassified{hiddenAuthority: true}
	unknown := unreviewedFields(reflect.TypeOf(value), "Known")
	if !value.hiddenAuthority || !slices.Equal(unknown, []string{"hiddenAuthority"}) {
		t.Fatalf("private nested classifier authority escaped review: %v", unknown)
	}
}

// These types have custom field-by-field ordering or normalization. New fields
// must force an explicit decision even if a parent already has a family row.
func TestClassifiedFieldCoverage(t *testing.T) {
	for _, tc := range []struct {
		typ    reflect.Type
		fields string
	}{
		{reflect.TypeFor[agent.FSRule](), "BuiltinRule Path Kind Access Raw Pos Resolved Mount Filesystem Device IsMountPoint Overlay Btrfs Missing Unenforced BuiltIn AskRead Regular Nlink FileMountPoint DirCaseExact Runtime RuntimeDev RuntimeIno Fence AliasOf StdDevice"},
		{reflect.TypeFor[agent.ExecRule](), "Raw Path Resolved Basename ByName Interp Verdict Source IsDir Pos Runtime Fence FenceEntry"},
		{reflect.TypeFor[agent.NetRule](), "Raw Host Port Proto Verdict IPs CIDR UnixPath Abstract UnixResolved Static Denied PublicAnswer Runtime MCP ResolvedAt TTL ExpiresAt Pos Fence"},
		{reflect.TypeFor[agent.NetworkLimits](), "Connections PendingConnects Bytes DatagramsPerSecond"},
		{reflect.TypeFor[agent.ResolvedLimits](), "CPU CPUWeight MemoryB MemoryHigh Pids Tokens CostUSD Wall StallAfter Repeats Window Set"},
		{reflect.TypeFor[agent.AskConfig](), "Hold Timeout MaxPending OnTimeout"},
		{reflect.TypeFor[agent.Credential](), "Name Env Allow BaseURLEnv"},
		{reflect.TypeFor[agent.EnvSection](), "Pass Deny Mask Set"},
		{reflect.TypeFor[agent.ReasonSection](), "Reads"},
		{reflect.TypeFor[agent.FSSection](), "Write Ask DenyRead AskRead Watch DenyWrite Assurance Reads AppArmorAssumeRootNamespace"},
		{reflect.TypeFor[agent.ExecSection](), "Allow Deny Ask Privileged Anonymous Assurance"},
		{reflect.TypeFor[agent.NetSection](), "Assurance Allow Ask HTTP Listen Ingress Limits DNS Proxy"},
	} {
		t.Run(tc.typ.Name(), func(t *testing.T) {
			got := allFieldNames(tc.typ)
			want := strings.Fields(tc.fields)
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("custom classifier fields %v; reviewed %v", got, want)
			}
		})
	}
}

func rowResult(t *testing.T, family string, a, b *agent.RuleTable) Result {
	t.Helper()
	for _, r := range Compare(a, b) {
		if r.Family == family {
			return r
		}
	}
	t.Fatalf("missing family %s", family)
	return Result{}
}

func table() *agent.RuleTable {
	return &agent.RuleTable{Contract: &agent.Contract{Exec: &agent.ExecSection{}, Net: &agent.NetSection{}}, Env: []string{}}
}

func ptr[T any](v T) *T { return &v }

func TestNetworkLimitsNilZeroAndMixed(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b *uint64
		want Direction
	}{
		{"zero to finite", ptr(uint64(0)), ptr(uint64(100)), Widened},
		{"finite to zero", ptr(uint64(100)), ptr(uint64(0)), Narrowed},
		{"zero to unbounded", ptr(uint64(0)), nil, Widened},
		{"unbounded to zero", nil, ptr(uint64(0)), Narrowed},
		{"same", ptr(uint64(12)), ptr(uint64(12)), Unchanged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := table(), table()
			a.NetLimits.Connections, b.NetLimits.Connections = tc.a, tc.b
			r := rowResult(t, "network limits", a, b)
			if r.Direction != tc.want || tc.want == Widened && len(r.NewlyAllowed) == 0 {
				t.Fatalf("%+v, want %s", r, tc.want)
			}
		})
	}
	a, b := table(), table()
	a.NetLimits = agent.NetworkLimits{Connections: ptr(uint64(0)), Bytes: ptr(agent.ByteSize(100)), PendingConnects: ptr(uint64(1)), DatagramsPerSecond: ptr(uint64(1))}
	b.NetLimits = agent.NetworkLimits{Connections: ptr(uint64(100)), Bytes: ptr(agent.ByteSize(0)), PendingConnects: ptr(uint64(2)), DatagramsPerSecond: ptr(uint64(2))}
	if r := rowResult(t, "network limits", a, b); r.Direction != Widened || len(r.NewlyAllowed) != 3 {
		t.Fatalf("mixed: %+v", r)
	}
}

func TestApprovalConfigurationOrdering(t *testing.T) {
	base := agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Minute), MaxPending: 2, OnTimeout: agent.AskOnTimeoutRefuseAlways}
	for _, tc := range []struct {
		name   string
		mutate func(*agent.AskConfig)
		want   Direction
	}{
		{"longer response", func(v *agent.AskConfig) { v.Timeout *= 2 }, Widened},
		{"shorter response", func(v *agent.AskConfig) { v.Timeout /= 2 }, Narrowed},
		{"more pending", func(v *agent.AskConfig) { v.MaxPending++ }, Widened},
		{"less pending", func(v *agent.AskConfig) { v.MaxPending-- }, Narrowed},
		{"timeout retry", func(v *agent.AskConfig) { v.OnTimeout = agent.AskOnTimeoutRefuse }, Widened},
		{"hold transition", func(v *agent.AskConfig) { v.Hold = agent.AskHoldRequest }, CannotClassify},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := table(), table()
			x, y := base, base
			tc.mutate(&y)
			a.AskConfig, b.AskConfig = &x, &y
			r := rowResult(t, "approval configuration", a, b)
			if r.Direction != tc.want {
				t.Fatalf("%+v", r)
			}
		})
	}
	a, b := table(), table()
	a.AskConfig = &base
	if r := rowResult(t, "approval configuration", a, b); r.Direction != Narrowed {
		t.Fatalf("broker removal: %+v", r)
	}
}

func TestCredentialAuthorityOrdering(t *testing.T) {
	a, b := table(), table()
	a.Contract.Credentials = []agent.Credential{{Name: "provider", Env: "KEY", Allow: []string{"api.example:443"}}}
	b.Contract.Credentials = []agent.Credential{{Name: "provider", Env: "KEY", Allow: []string{"api.example", "other.example:443"}}}
	r := rowResult(t, "credentials", a, b)
	if r.Direction != Widened || len(r.NewlyAllowed) != 1 || !strings.Contains(r.NewlyAllowed[0], "other.example:443") {
		t.Fatalf("added credential destination: %+v", r)
	}
	if r := rowResult(t, "credentials", b, a); r.Direction != Narrowed {
		t.Fatalf("removed credential destination: %+v", r)
	}
	b.Contract.Credentials[0].Allow = []string{"api.example"}
	if r := rowResult(t, "credentials", a, b); r.Direction != Unchanged {
		t.Fatalf("canonical authority: %+v", r)
	}
	b.Contract.Credentials[0].Env = "OTHER_KEY"
	if r := rowResult(t, "credentials", a, b); r.Direction != Widened {
		t.Fatalf("new injection variable: %+v", r)
	}
}

func TestSimpleFamiliesOrdering(t *testing.T) {
	for _, tc := range []struct {
		family string
		mutate func(*agent.RuleTable)
		text   string
	}{
		{"filesystem", func(v *agent.RuleTable) {
			v.FS = []agent.FSRule{{Kind: agent.FSWrite, Path: "/work/out", Resolved: "/work/out", Access: agent.AccessWriteSet}}
		}, "Write /work/out"},
		{"programs", func(v *agent.RuleTable) {
			v.Exec = []agent.ExecRule{{Path: "/usr/bin/tool", Resolved: "/usr/bin/tool", Verdict: agent.VerdictAllow}}
		}, "Run /usr/bin/tool"},
		{"destinations", func(v *agent.RuleTable) {
			v.Net = []agent.NetRule{{Host: "api.example", Port: 443, Proto: "tcp", Verdict: agent.VerdictAllow}}
		}, "Connect to tcp://api.example:443"},
		{"destination approvals", func(v *agent.RuleTable) {
			v.NetAsk = []agent.NetRule{{Host: "api.example", Port: 443, Proto: "tcp", Verdict: agent.VerdictAsk}}
		}, "Ask to connect to tcp://api.example:443"},
		{"filesystem approvals", func(v *agent.RuleTable) { v.FSAsk = []agent.FSRule{{Path: "/work/out", Kind: agent.FSAsk}} }, "Ask to write /work/out"},
		{"environment", func(v *agent.RuleTable) { v.Env = []string{"PATH"} }, "Pass environment variable PATH"},
	} {
		t.Run(tc.family, func(t *testing.T) {
			a, b := table(), table()
			tc.mutate(b)
			r := rowResult(t, tc.family, a, b)
			if r.Direction != Widened || !slices.Contains(r.NewlyAllowed, tc.text) {
				t.Fatalf("added: %+v", r)
			}
			if r := rowResult(t, tc.family, b, a); r.Direction != Narrowed {
				t.Fatalf("removed: %+v", r)
			}
		})
	}
	a, b := table(), table()
	a.Limits.Wall, b.Limits.Wall = time.Hour, 2*time.Hour
	if r := rowResult(t, "run limits", a, b); r.Direction != Widened {
		t.Fatalf("wall: %+v", r)
	}
	if r := rowResult(t, "run limits", b, a); r.Direction != Narrowed {
		t.Fatalf("wall: %+v", r)
	}
	a.ReasonReads, b.ReasonReads = agent.ReasonReadsOn, agent.ReasonReadsOff
	if r := rowResult(t, "read recording", a, b); r.Direction != Widened {
		t.Fatalf("reads: %+v", r)
	}
}

func TestCompleteRangesAndPathCoverage(t *testing.T) {
	a, b := table(), table()
	a.Net = []agent.NetRule{{CIDR: ptr(netip.MustParsePrefix("192.0.2.0/24")), Port: 443, Proto: "tcp"}}
	b.Net = []agent.NetRule{{CIDR: ptr(netip.MustParsePrefix("192.0.2.0/25")), Port: 443, Proto: "tcp"}}
	if r := rowResult(t, "destinations", a, b); r.Direction != Narrowed {
		t.Fatalf("CIDR narrowed: %+v", r)
	}
	if r := rowResult(t, "destinations", b, a); r.Direction != Widened {
		t.Fatalf("CIDR widened: %+v", r)
	}
	a.FS = []agent.FSRule{{Kind: agent.FSWrite, Path: "/work", Resolved: "/work", Access: agent.AccessWriteSet}}
	b.FS = []agent.FSRule{{Kind: agent.FSWrite, Path: "/work/out", Resolved: "/work/out", Access: agent.AccessWriteSet}}
	if r := rowResult(t, "filesystem", a, b); r.Direction != Narrowed {
		t.Fatalf("path narrowed: %+v", r)
	}
	b.FS[0].Path, b.FS[0].Resolved = "/work-other", "/work-other"
	if r := rowResult(t, "filesystem", a, b); r.Direction != Widened {
		t.Fatalf("component boundary: %+v", r)
	}
}

func TestFilesystemApprovalSubtreeOrdering(t *testing.T) {
	a, b := table(), table()
	a.FSAsk = []agent.FSRule{{Kind: agent.FSAsk, Path: "/work", Resolved: "/work", Access: agent.AccessWriteSet}}
	b.FSAsk = []agent.FSRule{{Kind: agent.FSAsk, Path: "/work/out", Resolved: "/work/out", Access: agent.AccessWriteSet}}
	if r := rowResult(t, "filesystem approvals", a, b); r.Direction != Narrowed {
		t.Fatalf("smaller approval scope: %+v", r)
	}
	if r := rowResult(t, "filesystem approvals", b, a); r.Direction != Widened {
		t.Fatalf("larger approval scope: %+v", r)
	}
}

func TestFilesystemEmptyWriteSentinel(t *testing.T) {
	a, b := table(), table()
	a.FS = []agent.FSRule{{Kind: agent.FSWrite, Path: "/work/out", Resolved: "/work/out", Access: agent.AccessWriteSet}}
	b.FS = []agent.FSRule{{Kind: agent.FSImplicit, Path: "/", Resolved: "/"}}
	if r := rowResult(t, "filesystem", a, b); r.Direction != Narrowed {
		t.Fatalf("last write removed: %+v", r)
	}
	if r := rowResult(t, "filesystem", b, a); r.Direction != Widened {
		t.Fatalf("first write added: %+v", r)
	}
	// A row of another kind is not the empty-write sentinel, even at the same root.
	b.FS[0].Kind = agent.FSWatch
	if r := rowResult(t, "filesystem", a, b); r.Direction != CannotClassify {
		t.Fatalf("non-write change hidden: %+v", r)
	}
}

func TestProgramDirectoryAndBasenameOrdering(t *testing.T) {
	a, b := table(), table()
	a.Exec = []agent.ExecRule{{Path: "/opt/tools", Resolved: "/opt/tools", Basename: "tools", IsDir: true, Verdict: agent.VerdictAllow}}
	b.Exec = []agent.ExecRule{{Path: "/opt/tools/tool", Resolved: "/opt/tools/tool", Basename: "tool", Verdict: agent.VerdictAllow}}
	if r := rowResult(t, "programs", a, b); r.Direction != Narrowed {
		t.Fatalf("directory to one image: %+v", r)
	}
	b.Exec[0].ByName = true
	if r := rowResult(t, "programs", a, b); r.Direction != Widened {
		t.Fatalf("new basename scope outside directory: %+v", r)
	}
}

func TestNetworkTransportOrdering(t *testing.T) {
	a, b := table(), table()
	a.Net = []agent.NetRule{{Host: "api.example", Port: 443, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow}}
	b.Net = []agent.NetRule{{Host: "api.example", Port: 443, Proto: agent.ProtoTCP, Verdict: agent.VerdictAllow}}
	if r := rowResult(t, "destinations", a, b); r.Direction != Narrowed {
		t.Fatalf("TCP only: %+v", r)
	}
	if r := rowResult(t, "destinations", b, a); r.Direction != Widened {
		t.Fatalf("TCP and UDP: %+v", r)
	}
}

func TestNetworkExpiryDifferenceNeedsReview(t *testing.T) {
	a, b := table(), table()
	a.Net = []agent.NetRule{{Host: "api.example", Port: 443, Proto: agent.ProtoTCP, Verdict: agent.VerdictAllow, ExpiresAt: time.Unix(1, 0)}}
	b.Net = slices.Clone(a.Net)
	b.Net[0].ExpiresAt = time.Unix(2, 0)
	if r := rowResult(t, "destinations", a, b); r.Direction != CannotClassify {
		t.Fatalf("changed authority deadline: %+v", r)
	}
}

func TestNetworkUnionCoverage(t *testing.T) {
	a, b := table(), table()
	a.Net = []agent.NetRule{
		{CIDR: ptr(netip.MustParsePrefix("192.0.2.0/25")), Port: 443, Proto: agent.ProtoTCP},
		{CIDR: ptr(netip.MustParsePrefix("192.0.2.128/25")), Port: 443, Proto: agent.ProtoTCP},
	}
	b.Net = []agent.NetRule{{CIDR: ptr(netip.MustParsePrefix("192.0.2.0/24")), Port: 443, Proto: agent.ProtoTCP}}
	if r := rowResult(t, "destinations", a, b); r.Direction != Unchanged {
		t.Fatalf("two halves cover the complete range: %+v", r)
	}
	a.Net = a.Net[:1]
	if r := rowResult(t, "destinations", a, b); r.Direction != Widened {
		t.Fatalf("missing half adds addresses: %+v", r)
	}
	a.Net = []agent.NetRule{
		{Host: "api.example", Port: 443, Proto: agent.ProtoTCP},
		{Host: "api.example", Port: 443, Proto: agent.ProtoUDP},
	}
	b.Net = []agent.NetRule{{Host: "api.example", Port: 443, Proto: agent.ProtoInet}}
	// A bare endpoint retains the legacy protocol wildcard (ProtocolMatches),
	// including raw sockets that another port-0 entry made available. TCP and
	// UDP together must not be treated as covering that extra authority.
	if r := rowResult(t, "destinations", a, b); r.Direction != Widened {
		t.Fatalf("inet adds a protocol wildcard: %+v", r)
	}
	for _, prefixes := range [][]string{
		{"2001:db8::/65", "2001:db8:0:0:8000::/65", "2001:db8::/64"},
		{"0.0.0.0/1", "128.0.0.0/1", "0.0.0.0/0"},
		{"::/1", "8000::/1", "::/0"},
	} {
		t.Run(prefixes[2], func(t *testing.T) {
			a.Net = []agent.NetRule{{CIDR: ptr(netip.MustParsePrefix(prefixes[0])), Proto: agent.ProtoTCP}, {CIDR: ptr(netip.MustParsePrefix(prefixes[1])), Proto: agent.ProtoTCP}}
			b.Net = []agent.NetRule{{CIDR: ptr(netip.MustParsePrefix(prefixes[2])), Proto: agent.ProtoTCP}}
			if r := rowResult(t, "destinations", a, b); r.Direction != Unchanged {
				t.Fatalf("complete prefix union: %+v", r)
			}
		})
	}
}

func TestNetworkResolutionFactsNeedReview(t *testing.T) {
	a, b := table(), table()
	a.Net = []agent.NetRule{{Host: "api.example", Port: 443, Proto: agent.ProtoTCP, Verdict: agent.VerdictAllow, IPs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}}
	b.Net = slices.Clone(a.Net)
	b.Net[0].IPs = []netip.Addr{netip.MustParseAddr("192.0.2.2")}
	if r := rowResult(t, "destinations", a, b); r.Direction != CannotClassify {
		t.Fatalf("changed resolution guarantees: %+v", r)
	}
	first, second := netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1")
	a.Net[0].IPs, b.Net[0].IPs = []netip.Addr{first, second}, []netip.Addr{second, first}
	if r := rowResult(t, "destinations", a, b); r.Direction != Unchanged {
		t.Fatalf("same resolved-address set: %+v", r)
	}
	if a.Net[0].IPs[0] != first || b.Net[0].IPs[0] != second {
		t.Fatal("comparison mutated its immutable compiler inputs")
	}
	a.Net[0].IPs, b.Net[0].IPs = nil, nil
	a.Net[0].ExpiresAt = time.Unix(100, 0).UTC()
	b.Net[0].ExpiresAt = a.Net[0].ExpiresAt.In(time.FixedZone("presentation", 3600))
	if r := rowResult(t, "destinations", a, b); r.Direction != Unchanged {
		t.Fatalf("same authority deadline in another zone: %+v", r)
	}
}

func TestReadRecordingChoiceChangesVisible(t *testing.T) {
	a, b := table(), table()
	a.ReasonReads, b.ReasonReads = agent.ReasonReadsAuto, agent.ReasonReadsOff
	if r := rowResult(t, "read recording", a, b); r.Direction != CannotClassify {
		t.Fatalf("changed choice hidden: %+v", r)
	}
}

func TestEveryUnclassifiedDifferenceIsVisible(t *testing.T) {
	for _, f := range families {
		if f.Classified {
			continue
		}
		for _, path := range f.Fields {
			t.Run(path, func(t *testing.T) {
				a, b := table(), table()
				v := reflect.ValueOf(b).Elem()
				for _, part := range strings.Split(path, ".") {
					if v.Kind() == reflect.Pointer {
						if v.IsNil() {
							v.Set(reflect.New(v.Type().Elem()))
						}
						v = v.Elem()
					}
					v = v.FieldByName(part)
				}
				changeValue(t, v)
				if r := rowResult(t, f.Family, a, b); r.Direction != CannotClassify {
					t.Fatalf("silent changed field %s: %+v", path, r)
				}
			})
		}
	}
}

func changeValue(t *testing.T, v reflect.Value) {
	t.Helper()
	if !v.CanSet() {
		// Test-only mutation of private compiler authority keeps the exhaustive
		// negative control effective when the matrix gains a private field.
		v = reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
	}
	switch v.Kind() {
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
	case reflect.String:
		v.SetString("changed")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int64:
		v.SetInt(1)
	case reflect.Uint, reflect.Uint32, reflect.Uint64:
		v.SetUint(1)
	case reflect.Map:
		v.Set(reflect.MakeMap(v.Type()))
		v.SetMapIndex(reflect.ValueOf("changed").Convert(v.Type().Key()), reflect.Zero(v.Type().Elem()))
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).CanSet() {
				changeValue(t, v.Field(i))
				return
			}
		}
		t.Fatalf("no settable field in %s", v.Type())
	default:
		t.Fatalf("unsupported mutation %s", v.Type())
	}
}

func TestValuesNeverAppearInComparison(t *testing.T) {
	a, b := table(), table()
	b.Set = map[string]string{"TOKEN": "private-never-render"}
	for _, r := range Compare(a, b) {
		if strings.Contains(strings.Join(r.NewlyAllowed, " "), "private-never-render") {
			t.Fatal("environment value escaped")
		}
	}
	if r := rowResult(t, "environment assignments", a, b); r.Direction != CannotClassify {
		t.Fatalf("hidden value change: %+v", r)
	}
}

func TestBaselineComparisonKeepsEffectiveAuthorityVisible(t *testing.T) {
	a, b := table(), table()
	a.EffectiveContract, b.EffectiveContract = a.Contract, b.Contract
	b.Contract.Command = []string{"new-command"}
	if r := rowResult(t, "machine baseline", a, b); r.Direction != Unchanged {
		t.Fatalf("source duplicate must use existing family classifiers: %+v", r)
	}
	if r := rowResult(t, "launch command", a, b); r.Direction != CannotClassify {
		t.Fatalf("source command change hidden: %+v", r)
	}
	effective := *b.Contract
	effective.Command = []string{"independent-effective-command"}
	b.EffectiveContract = &effective
	if r := rowResult(t, "machine baseline", a, b); r.Direction != CannotClassify {
		t.Fatalf("independent effective contract hidden: %+v", r)
	}
	b.EffectiveContract = b.Contract
	b.Baseline = &agent.BaselineTable{Applied: true}
	if r := rowResult(t, "machine baseline", a, b); r.Direction != CannotClassify {
		t.Fatalf("baseline snapshot change hidden: %+v", r)
	}
}
