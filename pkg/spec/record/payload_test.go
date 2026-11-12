// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// jsonNames returns the JSON key of every field of a payload struct, in declaration order.
func jsonNames(v any) []string {
	rt := reflect.TypeOf(v)
	names := make([]string, 0, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		names = append(names, strings.Split(tag, ",")[0])
	}
	return names
}

// TestPayloadJSONNamesFrozen pins the exact key names of docs/P0-DESIGN.md §3.2 and spec/record/v1/README.md.
// Changing a name here is a schema change (docs/VERSIONING.md §2): only additions are allowed within v1.
func TestPayloadJSONNamesFrozen(t *testing.T) {
	tests := []struct {
		payload any
		keys    string
	}{
		{RunStartPayload{}, "launcher_pid launcher_start_ns tego_version commit bpf_hash tier capture net_assurance net_guarantees kernel contract_hash parsers stop_grace command command_blob cwd limits capabilities stdio run_command_grant record_minor decision_plane best_effort ask_read_relaxes runtime_grants contract_source harness profiles host_sockets launcher_uid launcher_user sudo_uid sudo_user host parent_run labels role contract_revision fs_reads deployment secrets vault shares reads_notified live_mode live_fence deny_read_frozen"},
		{DeploymentChange{}, "from_revision class"},
		{SecretUse{}, "name version deliver env exposure"},
		{VaultUse{}, "peer memory"},
		{LineRedactions{}, "redactions"},
		{Redaction{}, "secret version count"},
		{ShareUse{}, "name path mode"},
		{HarnessStart{}, "name provisioned why files reason_file state_dir hook"},
		{HarnessHook{}, "argv granted"},
		{AskReadRelax{}, "rule builtin how"},
		{Limits{}, "tokens cost_usd wall stall_after repeats ledger_bytes"},
		{ExecPayload{}, "path argv script stage exec_id parent_exec_id mechanism decision_plane plane_reason syscall_ret attempt_path argv_from errno by command_rule command_list command_match command_via closure_of argv_facts argv_read pin_unavailable argv_decided signal kill_failed detected_bypass"},
		{FSPayload{}, "op path path2 flags count created errno by verdict_from mechanism decision_plane plane_reason alternate_for"},
		{NetPayload{}, "op method path http_authority proto dst host boundary propagated mechanism decision_plane plane_reason syscall_ret syscall_errno verdict_from what credential route"},
		{MCPPayload{}, "name command transport tool"},
		{SSLRequestPayload{}, "endpoint method path host request_id blob size trace_id span_id parent_span_id retry_of headers body_sha256 frame messages truncated wire_size route side tool_results"},
		{Usage{}, "input output cache_read cache_write output_bound cache_write_1h server_tool modified"},
		{SSLResponsePayload{}, "request_seq status model response_id stop_reason usage latency_ms request_id content_encoding parser_version blob headers truncated wire_size"},
		{DecisionPayload{}, "step tool_use_id tool name input_hash text unparsed why"},
		{GapPayload{}, "what why binary count decision_plane live_block live_control mcp_tool model_route"},
		{MCPToolChange{}, "server tool decision by serial at"},
		{CredentialUse{}, "name version"},
		{LiveControlChange{}, "op by serial at"},
		{LimitPayload{}, "which value ceiling"},
		{RefusedPayload{}, "op target reason rule mechanism decision_plane command_rule command_match"},
		{Supervisor{}, "notifications held_ms anomalies orphaned starved order_lost exec_rules exec_missing"},
		{RunEndPayload{}, "reason exit_code signal escalated detail supervisor head resources network stopped_by"},
		{backend.NetworkCounters{}, "available bytes_in bytes_out datagrams_in datagrams_out connections_active connections_pending refusals"},
		{Resources{}, "memory_peak pids_peak cpu_usage_usec cpu_user_usec cpu_system_usec cpu_nr_throttled cpu_throttled_usec memory_events"},
		{MemoryEvents{}, "high max oom oom_kill"},
		{AskPayload{}, "ask_id hold"},
		{AnswerPayload{}, "ask_id by after_s"},
		{AnswerAlternate{}, "alternate alternate_dev alternate_ino"},
		{BoundaryPayload{}, "context_bytes dockerfile_sha256 tags network_mode"},
		{Attribution{}, "thread step tool_use_id confidence method"},
	}
	for _, tc := range tests {
		got := strings.Join(jsonNames(tc.payload), " ")
		if got != tc.keys {
			t.Errorf("%T keys\n got %s\nwant %s", tc.payload, got, tc.keys)
		}
		for _, k := range strings.Fields(tc.keys) {
			if IsReservedField(k) {
				t.Errorf("%T: key %q collides with a reserved common field", tc.payload, k)
			}
		}
	}
}

func TestClosedSets(t *testing.T) {
	if len(Kinds) != 15 || len(P0Kinds) != 12 {
		t.Fatalf("kinds %d, p0 kinds %d", len(Kinds), len(P0Kinds))
	}
	for _, k := range P0Kinds {
		if !k.Valid() {
			t.Errorf("%s not valid", k)
		}
		if k == KindAsk || k == KindAnswer || k == KindBoundary {
			t.Errorf("%s is not a P0 kind", k)
		}
	}
	if len(Reasons) != 29 {
		t.Fatalf("reasons: %d, want the 29 of spec/reason/REASON-CHANNEL.md", len(Reasons))
	}
	sorted := append([]Reason(nil), Reasons...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] {
			t.Errorf("duplicate reason %s", sorted[i])
		}
	}
	for _, r := range []Reason{ReasonLimitTokens, ReasonLimitRepeats} {
		if !r.IsLimit() || !r.Valid() {
			t.Errorf("%s should be a valid limit reason", r)
		}
	}
	if ReasonOOM.IsLimit() || Reason("nope").Valid() || Verdict("x").Valid() || Authority("x").Valid() || Source("x").Valid() {
		t.Error("membership helpers accept unknown values")
	}
	for _, k := range []Kind{KindExec, KindFS, KindNet, KindMCP} {
		if !k.IsAction() {
			t.Errorf("%s is an action kind", k)
		}
	}
	if KindRefused.IsAction() || KindRunStart.IsAction() {
		t.Error("non-action kinds reported as actions")
	}
	if !IsAgentID("a-1") || IsAgentID("") || IsAgentID(strings.Repeat("a", 41)) || IsAgentID("A") {
		t.Error("IsAgentID")
	}
	if !Unattributed().Valid() || !AttributedByTime("t", 1).Valid() || (*Attribution)(nil).Valid() {
		t.Error("attribution helpers")
	}
	if len(RunEndReasons) != 9 || !IsRunEndReason(RunEndOrphaned) || IsRunEndReason("oom-killed") {
		t.Error("run_end reasons")
	}
	if !IsSharedField("rule") || !IsSharedField("reason") || IsReservedField("rule") || !IsReservedField("id") || IsReservedField("op") {
		t.Error("shared/reserved field helpers")
	}
}

// ADR 0057 D5: the record gained held reads and alternates (an ask's op read, an answer's alternate, alternate_dev
// and alternate_ino, an fs line's alternate_for), so the writer's revision says so: a reader of a ledger at 9 or later
// knows an answer without alternate gave none, and one below 9 may come from the POC that wrote alternate alone.
func TestRecordMinorCoversHeldReadsAndAlternates(t *testing.T) {
	if MinorHeldObject != 10 || Minor < MinorHeldObject || MinorHeldObject <= MinorAskRead {
		t.Fatalf("Minor %d, MinorHeldObject %d: held_object gate facts are 10, after held reads at 9", Minor, MinorHeldObject)
	}
	if MinorAskRead != 9 || Minor < MinorAskRead || MinorAskRead <= MinorExecMissing || MinorExecMissing <= MinorExecCommands {
		t.Fatalf("Minor %d, MinorAskRead %d, MinorExecMissing %d: held reads and alternates are 9, after exec_missing at 8, after 7", Minor, MinorAskRead, MinorExecMissing)
	}
}

// agent-contract.md R10a and supervisor.md R23a: runtime_grants and order_lost came after held_object, so a reader of
// a ledger at 11 or later knows an absent runtime_grants means the run made no grant, and one below 11 cannot tell.
// Their lane chose 8; exec_missing (8), held reads (9) and held_object (10) took it first when the branches were merged.
func TestRecordMinorCoversRuntimeGrantsAndOrderLost(t *testing.T) {
	if MinorRuntimeGrants != 11 || Minor < MinorRuntimeGrants || MinorRuntimeGrants <= MinorHeldObject {
		t.Fatalf("Minor %d, MinorRuntimeGrants %d, MinorHeldObject %d: runtime_grants and order_lost are 11, after held_object at 10", Minor, MinorRuntimeGrants, MinorHeldObject)
	}
}

// agent-contract.md R26: contract_source came after the exec pins, so a reader of a ledger at 13 or later knows an
// absent contract_source means the run's contract was one tego generated (a watch or an adoption with no boundary),
// and one below 13 cannot tell.
func TestRecordMinorCoversTheContractSource(t *testing.T) {
	if MinorContractSource != 13 || Minor < MinorContractSource || MinorContractSource <= MinorExecPins {
		t.Fatalf("Minor %d, MinorContractSource %d: contract_source is 13, after the exec pins at 12", Minor, MinorContractSource)
	}
	b, err := json.Marshal(ContractSource{Path: "/p/agent.yaml"})
	if err != nil || string(b) != `{"path":"/p/agent.yaml"}` {
		t.Fatalf("a contract given by path = %s (%v), want its path alone", b, err)
	}
	b, err = json.Marshal(ContractSource{Path: "/p/agent.yaml", Name: "retriever", Registry: "project"})
	if err != nil || string(b) != `{"path":"/p/agent.yaml","name":"retriever","registry":"project"}` {
		t.Fatalf("a contract resolved by name = %s (%v)", b, err)
	}
}

// ADR 0066 D6: run_start's profiles came after contract_source, at 15 (14 is the V1 numbering's for another key), so a
// reader of a ledger at 15 or later knows an absent profiles means the run's contract extended nothing.
func TestRecordMinorCoversTheProfiles(t *testing.T) {
	if MinorProfiles != 15 || Minor < MinorProfiles || MinorProfiles <= MinorContractSource {
		t.Fatalf("Minor %d, MinorProfiles %d: profiles is 15, after contract_source at 13", Minor, MinorProfiles)
	}
	b, err := json.Marshal(ProfileRef{Name: "tego/python", Source: ProfileSourceBuiltin, SHA256: strings.Repeat("ab", 32)})
	if err != nil || string(b) != `{"name":"tego/python","source":"builtin","sha256":"`+strings.Repeat("ab", 32)+`"}` {
		t.Fatalf("a profile = %s (%v)", b, err)
	}
	// ProfileRef's names are frozen here rather than in TestPayloadJSONNamesFrozen, whose reserved-field check is for a
	// line's own payload keys (E25): source sits inside each entry of run_start.profiles, never beside the line's
	// common source, so it collides with nothing on the wire.
	if got := strings.Join(jsonNames(ProfileRef{}), " "); got != "name source sha256" {
		t.Fatalf("ProfileRef keys %s, want name source sha256", got)
	}
	if b, _ := json.Marshal(RunStartPayload{}); strings.Contains(string(b), "profiles") {
		t.Fatalf("a run whose contract extends nothing writes profiles: %s", b)
	}
}

// ADR 0073: run_start's run identity is MinorRunIdentity, so a reader of a ledger at that revision or later knows an
// absent launcher_uid is a writer fault and an absent sudo_uid, host, parent_run, labels, role or contract_revision
// means the run had none. launcher_uid and sudo_uid are pointers so a uid of 0 is written. The revision numbers have no
// gap (TestRecordMinorsHaveNoGap).
func TestRecordMinorCoversTheRunIdentity(t *testing.T) {
	if Minor < MinorRunIdentity || MinorRunIdentity <= MinorProfiles {
		t.Fatalf("Minor %d, MinorRunIdentity %d: the run identity is written, after profiles at %d", Minor,
			MinorRunIdentity, MinorProfiles)
	}
	zero := uint32(0)
	b, err := json.Marshal(RunStartPayload{LauncherUID: &zero, SudoUID: &zero})
	if err != nil || !strings.Contains(string(b), `"launcher_uid":0`) || !strings.Contains(string(b), `"sudo_uid":0`) {
		t.Fatalf("uid 0 = %s (%v), want launcher_uid and sudo_uid written", b, err)
	}
	b, err = json.Marshal(RunStartPayload{})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"launcher_uid", "launcher_user", "sudo_uid", "sudo_user", "host", "parent_run", "labels", "role", "contract_revision"} {
		if strings.Contains(string(b), `"`+k+`"`) {
			t.Errorf("an empty run_start writes %s: %s", k, b)
		}
	}
}

// TestRecordMinorsHaveNoGap: the Minor* revision constants in record.go are exactly 1 to the highest, each once, and
// Minor is the constant at the highest. A ledger's record_minor tells a reader
// which optional fields the writer knew, every lower revision's included, so a number no feature holds would make a
// reader take a missing field of a later package for "the run had none" in a ledger whose writer never knew the field.
func TestRecordMinorsHaveNoGap(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "record.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	byValue := map[int]string{}
	minorIs, highest := "", 0
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, spec := range g.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, "Minor") || i >= len(vs.Values) {
					continue
				}
				if name.Name == "Minor" {
					id, ok := vs.Values[i].(*ast.Ident)
					if !ok {
						t.Fatalf("Minor is %T, want the name of a Minor* constant", vs.Values[i])
					}
					minorIs = id.Name
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.INT {
					t.Fatalf("%s is not an integer literal", name.Name)
				}
				n, err := strconv.Atoi(lit.Value)
				if err != nil {
					t.Fatal(err)
				}
				if other, dup := byValue[n]; dup {
					t.Fatalf("%s and %s are both revision %d", other, name.Name, n)
				}
				byValue[n] = name.Name
				highest = max(highest, n)
			}
		}
	}
	// The reserved revisions' constants (declaredAheadMinors) are the only ones allowed above Minor, and once Minor
	// reaches one of them every revision up to it must hold a constant, as for any other.
	written := 0
	for n, name := range byValue {
		if want, ok := declaredAheadMinors[name]; ok && n == want && n > Minor {
			continue
		}
		written = max(written, n)
	}
	for n := 1; n <= written; n++ {
		if byValue[n] == "" {
			t.Errorf("no Minor* constant is revision %d: the numbers must have no gap (highest written %d)", n, written)
		}
	}
	if minorIs != byValue[written] || Minor != written {
		t.Fatalf("Minor = %s (%d), want the highest constant not declared ahead, %s (%d)", minorIs, Minor, byValue[written], written)
	}
	if highest > written && highest != 35 {
		t.Fatalf("the highest constant is %d, above every reserved revision", highest)
	}
}

// ADR 0047: held fs mutations (hold mutation, target2, the human mutation line) came after model routes, so a reader of
// a ledger at 28 or later knows a mutation in an fs.ask scope could have been asked, and one below 28 refused it
// unasked.
func TestRecordMinorCoversFSMutationAsks(t *testing.T) {
	if MinorFSMutationAsk != 28 || Minor < MinorFSMutationAsk || MinorFSMutationAsk <= MinorModelRoutes {
		t.Fatalf("Minor %d, MinorFSMutationAsk %d, MinorModelRoutes %d: fs mutation asks are 28, after model routes at 27", Minor, MinorFSMutationAsk, MinorModelRoutes)
	}
}

// capture-derive R40, R42: attribution by the reply's tool_use id (method tool_id, attribution.tool_use_id), by tid,
// and ssl_request's side and tool_results came after the fs mutation asks, so a reader of a ledger below 29 knows its
// actions were attributed by time alone.
func TestRecordMinorCoversAttribution(t *testing.T) {
	if MinorAttribution != 29 || Minor < MinorAttribution || MinorAttribution <= MinorFSMutationAsk {
		t.Fatalf("Minor %d, MinorAttribution %d, MinorFSMutationAsk %d: attribution by tool_use id is 29, after the fs mutation asks at 28", Minor, MinorAttribution, MinorFSMutationAsk)
	}
}
