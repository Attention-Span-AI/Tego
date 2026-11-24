// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger/runstart"
	"github.com/attention-span-ai/tego/internal/profilesrc"
	"github.com/attention-span-ai/tego/internal/registry"
	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/internal/testutil/contracttest"
	"github.com/attention-span-ai/tego/internal/testutil/jsonschema"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

var updateContracts = flag.Bool("update-contracts", false, "update contracts output fixtures")

const simpleContract = "version: 0\nname: fixture\ncommand: [fixture]\nenv:\n  pass: [PATH]\nnet:\n  allow: []\n"

func write(t testing.TB, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func fixture(t *testing.T) (*contracttest.Fixture, Options) {
	t.Helper()
	f := contracttest.Build(t, simpleContract, nil)
	m, ds, err := config.LoadSources(config.Sources{}, f.Home, os.Getuid(), config.TrustAbort)
	if err != nil {
		t.Fatalf("config %v: %v", err, ds)
	}
	o := Options{Machine: m, Places: registry.Places{Dir: f.Root, User: m.Registry.Value, UID: os.Getuid()}, PATH: filepath.Join(f.Root, "bin"), KeepTableFor: "fixture",
		Snapshot: &runstart.Snapshot{Root: m.LedgerRoot.Value}, Tiers: backend.Tiers(),
		CompileContext: CompileContext{MountInfo: new(string), Now: func() *time.Time { now := time.Unix(1700000000, 0).UTC(); return &now }()}}
	return f, o
}

func run(path, cwd, name, hash, tier, id string) *runstart.Run {
	return &runstart.Run{ID: id, Agent: name, UID: os.Getuid(), UIDKnown: true, Contract: path, Cwd: cwd, ContractHash: hash, Tier: tier, Start: time.Unix(1700000000, 0).UTC()}
}

func TestContractsStatesAndCanonicalComparison(t *testing.T) {
	f, o := fixture(t)
	base := filepath.Join(f.Root, "known")
	states := []struct{ name, body, hash, tier, want, same string }{
		{"same", simpleContract, "current", "landlock", "compiles", "yes"},
		{"changed", simpleContract, strings.Repeat("0", 64), "cgroup", "compiles", "no"},
		{"never", simpleContract, "", "", "compiles", ""},
		{"parse", "version: 0\nname: bad\nunknown: true\n", "", "landlock", "invalid", "unknown"},
		{"missing", "", "", "landlock", "missing", "unknown"},
		{"directory", simpleContract, "", "landlock", "unsafe", "unknown"},
		{"symlink", simpleContract, "", "landlock", "unsafe", "unknown"},
		{"observe", simpleContract, "current", "observe", "compiles", "not-enforced"},
		{"old", simpleContract, "broken-hash", "landlock", "compiles", "unknown"},
	}
	for i, tc := range states {
		path := filepath.Join(base, tc.name+".yaml")
		body := strings.Replace(tc.body, "name: fixture", "name: "+tc.name, 1)
		if tc.body != "" {
			write(t, path, body)
		}
		if tc.name == "directory" {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			// A directory is refused at every UID, including root. Permission
			// bits alone do not make a source unreadable for a privileged test.
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if tc.name == "symlink" {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(f.Path("contract.yaml"), path); err != nil {
				t.Fatal(err)
			}
		}
		hash := tc.hash
		if hash == "current" {
			one := Inspect(context.Background(), path, o)
			hash = one.Contracts[0].Hash
			if hash == "" {
				t.Fatalf("fixture failed: %+v", one)
			}
			write(t, path, "# a formatting change is not contract drift\n"+body)
		}
		if tc.name == "never" {
			write(t, filepath.Join(o.Places.User, "agents/never.yaml"), body)
			continue
		}
		o.Snapshot.Runs = append(o.Snapshot.Runs, run(path, f.Root, tc.name, hash, tc.tier, "r-fixture-"+string(rune('a'+i))))
	}
	c := Discover(context.Background(), o)
	for _, tc := range states {
		e, err := c.Select(tc.name)
		if err != nil {
			t.Fatalf("%s: %v; entries %+v", tc.name, err, c.Contracts)
		}
		if e.State != tc.want {
			t.Errorf("%s state %s, want %s: %+v", tc.name, e.State, tc.want, e.Diagnostics)
		}
		if tc.same == "" {
			if e.LastRun != nil {
				t.Errorf("never ran has last run")
			}
		} else if e.LastRun == nil || e.LastRun.SameContract != tc.same {
			t.Errorf("%s last %+v want %s", tc.name, e.LastRun, tc.same)
		}
		if tc.name == "parse" && (len(e.Diagnostics) == 0 || e.Diagnostics[0].Line != 3 || e.Diagnostics[0].File != e.Path) {
			t.Errorf("first error lost its position: %+v", e.Diagnostics)
		}
	}
	if c.ExitCode() != identity.ExitError {
		t.Fatalf("unsafe input exit %d", c.ExitCode())
	}
	var listing bytes.Buffer
	if err := PrintList(&listing, displayValue(t, c, f), true); err != nil {
		t.Fatal(err)
	}
	golden(t, "states", listing.String())
	jsonschema.Validate(t, "../../spec/contracts/v1/contracts.schema.json", c)
}

func TestContractsDiscoveryAmbiguityAndHistoricalPaths(t *testing.T) {
	f, o := fixture(t)
	write(t, filepath.Join(f.Root, "agent.yaml"), simpleContract)
	write(t, filepath.Join(o.Places.User, "agents/fixture.yaml"), simpleContract)
	other := filepath.Join(f.Root, "seen-project")
	write(t, filepath.Join(other, "agent.yaml"), strings.ReplaceAll(simpleContract, "fixture", "project"))
	write(t, filepath.Join(other, ".tego/agents/extra.yaml"), strings.ReplaceAll(simpleContract, "fixture", "extra"))
	write(t, filepath.Join(f.Root, "unseen/agent.yaml"), strings.ReplaceAll(simpleContract, "fixture", "hidden"))
	o.Snapshot.Runs = []*runstart.Run{run(f.Path("contract.yaml"), other, "fixture", "", "landlock", "r-a"), run("relative.yaml", "relative", "bad", "", "landlock", "r-b"), run(f.Root+"/link/../hostile.yaml", f.Root, "hostile", "", "landlock", "r-c")}
	c := Discover(context.Background(), o)
	if _, err := c.Select("fixture"); err == nil {
		t.Fatal("ambiguous name chose a file")
	}
	for _, name := range []string{"project", "extra"} {
		if _, err := c.Select(name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Select("hidden"); err == nil {
		t.Fatal("scanned an unseen folder")
	}
	for _, path := range []string{"relative.yaml", f.Root + "/link/../hostile.yaml"} {
		e, err := c.Select(path)
		if err != nil || e.State != "unsafe" {
			t.Fatalf("hostile path %q: %+v %v", path, e, err)
		}
	}
	if !c.Incomplete {
		t.Fatal("bad recorded cwd did not report incomplete")
	}
}

func TestContractsShowSourcesAndAddsNoRule(t *testing.T) {
	f, o := fixture(t)
	profile := filepath.Join(o.Machine.Profiles.Value, "personal.yaml")
	write(t, profile, "env:\n  deny: [SECRET]\n")
	text := "version: 0\nname: fixture\nextends: [personal, tego/no-secrets]\ncommand: [fixture]\nenv:\n  pass: [PATH]\nlimits:\n  pids: 10\n  memory: 2GiB\n"
	write(t, f.Path("contract.yaml"), text)
	o.Machine.Limits.Memory = config.Ceiling[config.ByteSize]{Value: 1 << 30, Bounded: true, Source: config.Provenance{File: "/etc/tego/config.yaml", Line: 8, Layer: config.LayerEtc}}
	c := Inspect(context.Background(), f.Path("contract.yaml"), o)
	e := c.Contracts[0]
	if e.State != "compiles" {
		t.Fatalf("check: %+v", e.Diagnostics)
	}
	show, err := c.Describe(e)
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]bool{}
	bothLimitSources := false
	for _, r := range show.Rules {
		if r.Key == "limits.memory" && len(r.Sources) == 2 {
			bothLimitSources = true
		}
		for _, s := range r.Sources {
			sources[s.Kind] = true
			if s.Kind == "profile" && (s.File != profile || s.Line != 2) {
				t.Errorf("profile source %+v", s)
			}
		}
	}
	if !bothLimitSources {
		t.Fatal("clamped limit lost its contract source or machine ceiling")
	}
	for _, kind := range []string{"contract", "profile", "preset", "machine-config ceiling"} {
		if !sources[kind] {
			t.Errorf("missing %s in %+v", kind, show.Rules)
		}
	}
	// Compare the canonical hash and printed compiler table to a direct compile
	// in the same offline context. The helper renders the original table.
	loaded, _, err := agent.Load(f.Path("contract.yaml"), profilesrc.Chain(o.Machine))
	if err != nil {
		t.Fatal(err)
	}
	before, err := loaded.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	// The caller facts the catalog compiled under (catalog.go: o.CompileContext.Caller = CallerContext(ctx)): the
	// runtime bases among them come from XDG_RUNTIME_DIR, so a process whose XDG_RUNTIME_DIR is not /run/user/<uid> (the
	// public cut test's scratch run folder) compiles three more built-in entries than a context without them.
	o.CompileContext.Caller = CallerContext(context.Background())
	opts := o.CompileContext.options()
	opts = append(opts, agent.WithContext(context.Background()), agent.WithCwd(f.Root), agent.WithHome(o.Machine.Home), agent.WithPATH(o.PATH), agent.WithTiers(o.Tiers...), agent.Offline(), agent.WithResolver(noDNS{}))
	rt, _, err := agent.Compile(loaded, o.Machine, opts...)
	if err != nil {
		t.Fatal(err)
	}
	if e.Hash != hex.EncodeToString(rt.Hash[:]) {
		t.Fatal("catalog changed the canonical contract hash")
	}
	if e.description == nil {
		t.Fatal("helper omitted compiled view")
	}
	after, err := loaded.Canonical()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("view changed contract bytes")
	}
	var table bytes.Buffer
	if err := agent.PrintRuleTable(&table, rt); err != nil {
		t.Fatal(err)
	}
	if table.String() != show.Table {
		t.Fatal("compiled table differs from compile's words")
	}
	jsonschema.Validate(t, "../../spec/contracts/v1/contracts.schema.json", show)
}

func TestContractsOfflineAndBounded(t *testing.T) {
	f, o := fixture(t)
	write(t, f.Path("contract.yaml"), strings.Replace(simpleContract, "allow: []", "allow: [tcp://never-query-this.invalid:443]", 1))
	c := Inspect(context.Background(), f.Path("contract.yaml"), o)
	if c.Contracts[0].State != "compiles" {
		t.Fatalf("offline compile failed: %+v", c.Contracts[0].Diagnostics)
	}
	found := false
	for _, d := range c.Contracts[0].Diagnostics {
		found = found || strings.Contains(d.Message, "DNS deferred by the contracts view")
	}
	if !found {
		t.Fatal("offline resolver was not used")
	}
	for _, kind := range []string{"oversize", "fifo", "hardlink", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			path := f.Path(kind + ".yaml")
			ctx := context.Background()
			switch kind {
			case "oversize":
				write(t, path, strings.Repeat("#", agent.MaxContractSize+1))
			case "fifo":
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(f.Path("contract.yaml"), path); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				write(t, path, simpleContract)
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			one := Inspect(ctx, path, o)
			if one.Contracts[0].State == "compiles" {
				t.Fatalf("%s silently compiled", kind)
			}
		})
	}
}

func TestContractsEmptyAndCutLedger(t *testing.T) {
	_, o := fixture(t)
	c := Discover(context.Background(), o)
	if len(c.Contracts) != 0 || c.ExitCode() != identity.ExitOK {
		t.Fatalf("empty %+v", c)
	}
	var b bytes.Buffer
	if err := PrintList(&b, c, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), Footer) {
		t.Fatal("empty list lost footer")
	}
	o.Snapshot.RunsCut = true
	c = Discover(context.Background(), o)
	if !c.Incomplete || c.ExitCode() != identity.ExitError {
		t.Fatal("bounded ledger silently complete")
	}
	jsonschema.Validate(t, "../../spec/contracts/v1/contracts.schema.json", c)
}

func TestContractsOutputGoldensAndSchema(t *testing.T) {
	f, o := fixture(t)
	write(t, filepath.Join(f.Root, "agent.yaml"), simpleContract)
	c := Discover(context.Background(), o)
	if c.ExitCode() != identity.ExitOK {
		t.Fatalf("fixture: %+v", c)
	}
	s, err := c.Describe(c.Contracts[0])
	if err != nil {
		t.Fatal(err)
	}
	displayC, displayS := displayValue(t, c, f), displayValue(t, s, f)
	for _, tc := range []struct {
		name   string
		render func(*bytes.Buffer) error
	}{
		{"list", func(b *bytes.Buffer) error { return PrintList(b, displayC, false) }},
		{"list-verbose", func(b *bytes.Buffer) error { return PrintList(b, displayC, true) }},
		{"show", func(b *bytes.Buffer) error { return PrintShow(b, displayS, false) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			if err := tc.render(&b); err != nil {
				t.Fatal(err)
			}
			got := b.String()
			path := filepath.Join("testdata", tc.name+".golden")
			if *updateContracts {
				write(t, path, got)
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Errorf("output mismatch\ngot:\n%s\nwant:\n%s", got, want)
			}
		})
	}
	jsonschema.Validate(t, "../../spec/contracts/v1/contracts.schema.json", c)
	jsonschema.Validate(t, "../../spec/contracts/v1/contracts.schema.json", s)
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var invalid map[string]any
	if err := json.Unmarshal(data, &invalid); err != nil {
		t.Fatal(err)
	}
	invalid["schema"] = "tego.contracts.v99"
	if jsonschema.Check("../../spec/contracts/v1/contracts.schema.json", invalid) == nil {
		t.Fatal("schema accepts unknown version")
	}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *updateContracts {
		write(t, path, got)
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("%s output differs\ngot:\n%s\nwant:\n%s", name, got, want)
	}
}

func TestContractsUnknownOwnerAndUnreadableProject(t *testing.T) {
	f, o := fixture(t)
	old := run(f.Path("contract.yaml"), f.Root, "fixture", "", "landlock", "r-old")
	old.UIDKnown = false
	o.Snapshot.Runs = []*runstart.Run{old}
	c := Discover(context.Background(), o)
	e, err := c.Select("fixture")
	if err != nil {
		t.Fatal(err)
	}
	if e.State != "incomplete" || !c.Incomplete || c.ExitCode() != identity.ExitError {
		t.Fatalf("unknown context hidden: %+v", c)
	}
	old.UIDKnown = true
	old.Cwd = filepath.Join(f.Root, "gone-project")
	c = Discover(context.Background(), o)
	e, err = c.Select("fixture")
	if err != nil {
		t.Fatal(err)
	}
	if e.State != "incomplete" {
		t.Fatalf("missing project silently checked: %+v", e)
	}
	old.Cwd = f.Root
	old.UID = os.Getuid() + 1
	c = Discover(context.Background(), o)
	if !c.Incomplete || len(c.Contracts) != 0 {
		t.Fatalf("other owner source opened: %+v", c)
	}
}

func TestContractsNeverExecutesAProgramOrReadsOwnState(t *testing.T) {
	f, o := fixture(t)
	marker := f.Path("executed")
	write(t, f.Path("bin/fixture"), "#!/bin/sh\n: > "+marker+"\n")
	if err := os.Chmod(f.Path("bin/fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	c := Inspect(context.Background(), f.Path("contract.yaml"), o)
	if c.Contracts[0].State != "compiles" {
		t.Fatalf("check: %+v", c)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("program executed: %v", err)
	}
	protected := filepath.Join(o.Machine.LedgerRoot.Value, "source.yaml")
	write(t, protected, simpleContract)
	c = Inspect(context.Background(), protected, o)
	if c.Contracts[0].State != "unsafe" {
		t.Fatalf("own state was read: %+v", c)
	}
}

// Replace fixture paths before tabwriter measures them, so random temporary
// directory lengths do not change the golden's column widths.
func displayValue[T any](t *testing.T, value T, f *contracttest.Fixture) T {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.ReplaceAll(raw, []byte(f.Root), []byte("<PROJECT>"))
	raw = bytes.ReplaceAll(raw, []byte(f.Home), []byte("<HOME>"))
	var copy T
	if err := json.Unmarshal(raw, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}

func TestContractsRegistryAliasesAreOneContract(t *testing.T) {
	f, o := fixture(t)
	target := f.Path(".tego/agents/fixture.yaml")
	write(t, target, simpleContract)
	if err := os.Symlink(".tego/agents/fixture.yaml", f.Path("agent.yaml")); err != nil {
		t.Fatal(err)
	}
	alias := f.Path("registry-alias")
	if err := os.Symlink(f.Path(".tego"), alias); err != nil {
		t.Fatal(err)
	}
	o.Places.User = alias
	o.Machine.Registry.Value = alias
	o.Snapshot.Runs = []*runstart.Run{run(filepath.Join(alias, "agents/fixture.yaml"), f.Root, "fixture", "", "landlock", "r-alias")}
	c := Discover(context.Background(), o)
	if len(c.Contracts) != 1 {
		t.Fatalf("same file acquired multiple catalog identities: %+v", c.Contracts)
	}
	e, err := c.Select("fixture")
	if err != nil {
		t.Fatal(err)
	}
	if e.Ambiguous || e.LastRun == nil || len(e.FoundIn) != 3 {
		t.Fatalf("alias lost run/source or became ambiguous: %+v", e)
	}
}

func TestContractsUnreadableLedgerRoot(t *testing.T) {
	_, o := fixture(t)
	o.Snapshot = nil
	write(t, o.Machine.LedgerRoot.Value, "not a ledger directory\n")
	c := Discover(context.Background(), o)
	if len(c.Roots) == 0 || c.Roots[0].State != "unreadable" || !c.Incomplete || c.ExitCode() != identity.ExitError {
		t.Fatalf("ledger root failure hidden: %+v", c)
	}
}

func TestContractsDisconnectedSourceCannotTell(t *testing.T) {
	for _, failure := range []error{syscall.EIO, syscall.ENOTCONN} {
		t.Run(failure.Error(), func(t *testing.T) {
			f, o := fixture(t)
			e := Entry{Path: f.Path("contract.yaml"), Cwd: f.Root}
			c := Catalog{machine: o.Machine}
			c.checkSource(context.Background(), &e, o, func(context.Context, string, rulefile.Guard) ([]byte, error) {
				return nil, fmt.Errorf("read disconnected source: %w", failure)
			})
			if !c.Incomplete || e.State != "incomplete" || len(e.Diagnostics) != 1 || !strings.Contains(e.Diagnostics[0].Message, UnavailableLocation) {
				t.Fatalf("dead source became an ordinary finding: incomplete=%v entry=%+v", c.Incomplete, e)
			}
			restored := packError(fmt.Errorf("read: %w", failure)).error()
			if !errors.Is(restored, failure) {
				t.Fatalf("transport dropped %v: %v", failure, restored)
			}
		})
	}
}

func TestContractsDisconnectedCwdCannotTell(t *testing.T) {
	f, o := fixture(t)
	original := statCwd
	defer func() { statCwd = original }()
	for _, failure := range []error{syscall.EIO, syscall.ENOTCONN} {
		statCwd = func(string) (os.FileInfo, error) { return nil, failure }
		e := Entry{Path: f.Path("contract.yaml"), Cwd: f.Root}
		c := Catalog{machine: o.Machine}
		c.checkSource(context.Background(), &e, o, readSource)
		if !c.Incomplete || e.State != "incomplete" || len(e.Diagnostics) == 0 || !strings.Contains(e.Diagnostics[len(e.Diagnostics)-1].Message, UnavailableLocation) {
			t.Fatalf("dead cwd became an ordinary finding: incomplete=%v entry=%+v", c.Incomplete, e)
		}
	}
}
