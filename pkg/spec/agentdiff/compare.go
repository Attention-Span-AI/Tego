// SPDX-License-Identifier: Apache-2.0

package agentdiff

import (
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// Direction is the ordering of a family's compiled authority.
type Direction string

const (
	Unchanged      Direction = "unchanged"
	Narrowed       Direction = "narrowed"
	Widened        Direction = "widened"
	CannotClassify Direction = "cannot classify"
)

// Result describes one family. NewlyAllowed names grants or increased bounds,
// never environment values. Widened includes changes that also remove grants.
type Result struct {
	Family       string
	Direction    Direction
	NewlyAllowed []string
}

// Row assigns compiler fields to exactly one family. Fields use RuleTable's
// field names, including private fields, with Contract fields as Contract.<field>.
// Classified means the family has an ordering implementation; it may still
// return CannotClassify for an incomparable or unsupported change.
type Row struct {
	Family     string
	Fields     []string
	Classified bool
}

type family struct {
	Row
	compare func(*agent.RuleTable, *agent.RuleTable) Result
}

var families = []family{
	{Row{"filesystem", []string{"FS", "Contract.FS"}, true}, filesystem},
	{Row{"filesystem approvals", []string{"FSAsk"}, true}, fsApprovals},
	{Row{"filesystem protection", []string{"AskDenyWrite", "DenyWrite", "DenyWriteLinked", "NameDeny", "NameExempt", "NameLeftOut", "Reads", "OwnState", "OwnReadable", "DenyReadPatterns", "AbsentDenyRead", "AskReadRelaxes"}, true}, fsProtection},
	{Row{"programs", []string{"Exec", "Contract.Exec"}, true}, programs},
	{Row{"program arguments", []string{"ExecCommands"}, false}, nil},
	{Row{"destinations", []string{"Net", "Contract.Net"}, true}, destinations},
	{Row{"destination approvals", []string{"NetAsk"}, true}, netApprovals},
	{Row{"environment", []string{"Env", "Deny"}, true}, environment},
	{Row{"environment assignments", []string{"Set"}, false}, nil},
	{Row{"run limits", []string{"Limits"}, true}, limits},
	{Row{"network limits", []string{"NetLimits"}, true}, netLimits},
	{Row{"approval configuration", []string{"AskConfig"}, true}, askConfig},
	{Row{"credentials", []string{"Contract.Credentials"}, true}, credentials},
	{Row{"read recording", []string{"ReasonReads"}, true}, readRecording},
	{Row{"listeners", []string{"Listen"}, false}, nil},
	{Row{"ingress", []string{"Ingress"}, false}, nil},
	{Row{"DNS", []string{"DNS", "DNSQueries", "DeniedResolved"}, false}, nil},
	{Row{"proxy", []string{"Proxy"}, false}, nil},
	{Row{"HTTP", []string{"HTTP"}, false}, nil},
	{Row{"gate", []string{"Gate", "Workdir"}, false}, nil},
	{Row{"live controls", []string{"Live", "Contract.Live"}, false}, nil},
	{Row{"assurance", []string{"NetAssurance", "FSAssurance", "ExecAssurance"}, false}, nil},
	{Row{"recording", []string{"Record"}, false}, nil},
	{Row{"protection tier", []string{"Tier", "Reach"}, false}, nil},
	{Row{"capture", []string{"Capture"}, false}, nil},
	{Row{"harness", []string{"Harness", "HarnessHook"}, false}, nil},
	{Row{"launch grants", []string{"RunCommandGrant"}, false}, nil},
	{Row{"built-in refusals", []string{"Builtins"}, false}, nil},
	{Row{"compile context", []string{"Home", "ContractPath", "PATH"}, false}, nil},
	{Row{"business rules", []string{"businessRules"}, false}, nil},
	{Row{"machine baseline", []string{"EffectiveContract", "Baseline", "replayed", "baselineReplayFacts", "Contract.materialized", "Contract.baselineCounts"}, false}, machineBaseline},
	{Row{"MCP", []string{"Contract.MCP"}, false}, nil},
	{Row{"models", []string{"Contract.Models"}, false}, nil},
	{Row{"process privileges", []string{"Contract.IOUring", "Contract.Keyring", "Contract.IPC", "Contract.Setuid", "Contract.HostSockets", "Contract.KeepDescendants"}, true}, privileges},
	{Row{"launch command", []string{"Contract.Command"}, false}, nil},
	{Row{"reserved declarations", []string{"Contract.Prompt", "Contract.Skills", "Contract.Visibility", "Contract.Docker", "Contract.Containers"}, false}, nil},
	// These declarations are represented by the compiled fields above. Their
	// spelling, source positions and profile names confer no additional authority.
	{Row{"compiler metadata", []string{"Hash", "EffectiveHash", "Profiles", "Contract.Learn", "Contract.Version", "Contract.Name", "Contract.Revision", "Contract.Extends", "Contract.Env", "Contract.Limits", "Contract.Record", "Contract.Tier", "Contract.Capture", "Contract.Harness", "Contract.Reason", "Contract.Gate", "Contract.Ask", "Contract.file", "Contract.origins", "Contract.loaded", "Contract.profiles"}, true}, metadata},
}

// Rows returns an independent copy of the exhaustive family matrix.
func Rows() []Row {
	out := make([]Row, len(families))
	for i, f := range families {
		out[i] = f.Row
		out[i].Fields = slices.Clone(f.Fields)
	}
	return out
}

// Compare orders each family independently. It performs no I/O or evaluation.
// A nil table is unclassifiable. All rows, including unchanged rows, are returned
// in matrix order. Consumers must require review of every CannotClassify result.
func Compare(a, b *agent.RuleTable) []Result {
	out := make([]Result, 0, len(families))
	for _, f := range families {
		r := Result{Family: f.Family, Direction: Unchanged}
		switch {
		case a == nil || b == nil:
			r.Direction = CannotClassify
		case f.compare != nil:
			r = f.compare(a, b)
			r.Family = f.Family
		default:
			for _, field := range f.Fields {
				if !compiledEqual(fieldValue(a, field), fieldValue(b, field), map[equalPointerPair]bool{}) {
					r.Direction = CannotClassify
					break
				}
			}
		}
		out = append(out, r)
	}
	return out
}

// The explicit matrix, rather than all fields found by reflection, defines what
// is compared. Reflection is confined to equal comparisons of unclassified rows;
// TestFamilyCoverage rejects any compiler field absent from that matrix.
func fieldValue(t *agent.RuleTable, path string) reflect.Value {
	v := reflect.ValueOf(t).Elem()
	for _, name := range strings.Split(path, ".") {
		if v.Kind() == reflect.Pointer {
			if v.IsNil() {
				v = reflect.Zero(v.Type().Elem())
			} else {
				v = v.Elem()
			}
		}
		v = v.FieldByName(name)
	}
	return v
}

func metadata(_, _ *agent.RuleTable) Result { return Result{Direction: Unchanged} }

// Empty-baseline compilation retains the source as its effective contract. Its
// changes belong to the existing source/compiled families. A separately
// materialized effective contract and every baseline/replay fact are frozen
// context: differences require review until composition can be proved.
func machineBaseline(a, b *agent.RuleTable) Result {
	sourceOnly := func(t *agent.RuleTable) bool {
		return t.EffectiveContract == nil || compiledEqual(reflect.ValueOf(t.EffectiveContract), reflect.ValueOf(t.Contract), map[equalPointerPair]bool{})
	}
	if !(sourceOnly(a) && sourceOnly(b)) && !compiledEqual(reflect.ValueOf(a.EffectiveContract), reflect.ValueOf(b.EffectiveContract), map[equalPointerPair]bool{}) {
		return unknown()
	}
	for _, field := range []string{"Baseline", "replayed", "baselineReplayFacts", "Contract.materialized", "Contract.baselineCounts"} {
		if !compiledEqual(fieldValue(a, field), fieldValue(b, field), map[equalPointerPair]bool{}) {
			return unknown()
		}
	}
	return Result{Direction: Unchanged}
}

func order(added, removed []string) Result {
	if len(added) > 0 {
		slices.Sort(added)
		return Result{Direction: Widened, NewlyAllowed: slices.Compact(added)}
	}
	if len(removed) > 0 {
		return Result{Direction: Narrowed}
	}
	return Result{Direction: Unchanged}
}

func unknown() Result { return Result{Direction: CannotClassify} }

func sets(a, b []string, prefix string) Result {
	var added, removed []string
	for _, v := range b {
		if !slices.Contains(a, v) {
			added = append(added, prefix+v)
		}
	}
	for _, v := range a {
		if !slices.Contains(b, v) {
			removed = append(removed, prefix+v)
		}
	}
	return order(added, removed)
}

func environment(a, b *agent.RuleTable) Result {
	// Pass-list nil means the universe, less deny. Assignments have their own row.
	var added, removed []string
	if a.Env != nil && b.Env == nil {
		added = append(added, "Pass all environment variables except refusals")
	}
	if a.Env == nil && b.Env != nil {
		removed = append(removed, "environment pass list")
	}
	for _, v := range b.Env {
		if !slices.Contains(b.Deny, v) && (slices.Contains(a.Deny, v) || a.Env != nil && !slices.Contains(a.Env, v)) {
			added = append(added, "Pass environment variable "+v)
		}
	}
	for _, v := range a.Deny {
		if !slices.Contains(b.Deny, v) && (b.Env == nil || slices.Contains(b.Env, v)) {
			added = append(added, "Pass environment variable "+v)
		}
	}
	for _, v := range a.Env {
		if !slices.Contains(a.Deny, v) && (slices.Contains(b.Deny, v) || b.Env != nil && !slices.Contains(b.Env, v)) {
			removed = append(removed, v)
		}
	}
	for _, v := range b.Deny {
		if !slices.Contains(a.Deny, v) && (a.Env == nil || slices.Contains(a.Env, v)) {
			removed = append(removed, v)
		}
	}
	return order(added, removed)
}

func readRecording(a, b *agent.RuleTable) Result {
	// This switch changes visibility of refusals, not the allowed operations.
	// A changed recording choice still gets an explicit family review.
	if a.ReasonReads == b.ReasonReads {
		return Result{Direction: Unchanged}
	}
	if b.ReasonReads == agent.ReasonReadsOn {
		return Result{Direction: Narrowed}
	}
	if a.ReasonReads == agent.ReasonReadsOn {
		return Result{Direction: Widened, NewlyAllowed: []string{"Run without recording every refused read at Basic protection"}}
	}
	return unknown()
}

func credentials(a, b *agent.RuleTable) Result {
	entries := func(t *agent.RuleTable) []string {
		var out []string
		if t.Contract == nil {
			return out
		}
		for _, c := range t.Contract.Credentials {
			for _, raw := range c.Allow {
				authority, ok := agent.ParseCredentialAuthority(raw)
				if !ok {
					authority = raw
				}
				entry := fmt.Sprintf("Use credential %s through %s at %s", c.Name, c.Env, authority)
				if c.BaseURLEnv != "" {
					entry += " (base URL variable " + c.BaseURLEnv + ")"
				}
				out = append(out, entry)
			}
		}
		return out
	}
	return sets(entries(a), entries(b), "")
}

func privileges(a, b *agent.RuleTable) Result {
	flags := func(t *agent.RuleTable) map[string]bool {
		c := t.Contract
		if c == nil {
			c = &agent.Contract{}
		}
		return map[string]bool{"Use io_uring": c.IOUring, "Use kernel keyring": c.Keyring, "Use System V IPC": c.IPC, "Use setuid programs": c.Setuid, "Use host sockets": c.HostSockets, "Keep descendants after the main program ends": c.KeepDescendants}
	}
	x, y := flags(a), flags(b)
	var added, removed []string
	for key, v := range y {
		if v && !x[key] {
			added = append(added, key)
		}
		if !v && x[key] {
			removed = append(removed, key)
		}
	}
	return order(added, removed)
}
