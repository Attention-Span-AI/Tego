// SPDX-License-Identifier: Apache-2.0

package linewords

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// labels is the label of each payload key, by its dotted path (resources.memory_peak). A nested key with no entry
// of its own is looked up by its last part (Label), so "memory_peak" labels it under any parent.
var labels = map[string]string{
	// The line's decision (the common fields after the envelope).
	"kind": "Kind of line", "source": "Recorded by", "rule": "Rule", "verdict": "Verdict", "authority": "Decided by",
	"reason": "Reason", "attribution": "Model step", "attribution.confidence": "Step match",
	"attribution.method": "Matched by", "attribution.step": "Model step", "attribution.thread": "Model thread",

	// Actions: files, programs, connections.
	"op": "Operation", "path": "Path", "path2": "Second path", "flags": "Open flags", "count": "Count",
	"created": "Created the file", "errno": "Error the agent got", "syscall_errno": "Error the kernel returned",
	"syscall_ret": "Kernel return value", "operation_completed": "Operation completed", "fd_delivered": "File handle handed to the agent",
	"verdict_from": "Verdict came from", "by": "By", "argv": "Command line", "argv_blob": "Command line (stored apart)",
	"argv_truncated": "Command line cut", "argv_facts": "How the command line was read", "argv_from": "Command line taken from",
	"argv_read": "Command line arguments read", "argv_decided": "Command line decided on", "exec_id": "Process id (this run)",
	"parent_exec_id": "Parent process id", "attempt_path": "Path the agent asked for", "path_search": "A PATH lookup",
	"fileless": "Ran from memory, not a file", "command_rule": "Command rule", "command_list": "Command list",
	"command_match": "Command match", "command_via": "Command matched by", "closure_of": "Allowed as part of",
	"signal": "Signal", "dst": "Destination", "host": "Host name", "proto": "Protocol", "method": "HTTP method",
	"http_authority": "HTTP host", "peer": "Peer", "detected_bypass": "Bypass detected", "mechanism": "Refused by",
	"decision_plane": "Kernel decision mode", "plane_reason": "Kernel reason", "pin_refused": "Pin refused",
	"pin_unavailable": "Pin unavailable", "target": "Target", "dropped": "Lines dropped", "best_effort": "Best effort",
	"result_unknown": "Result unknown", "relay_dst": "Relayed to", "upstream_connected": "Upstream connected",
	"alternate_for": "Given in place of", "dns_name": "DNS name", "dns_type": "DNS record type",
	"dns_phase": "DNS phase", "dns_error": "DNS error", "dns_cached": "DNS answer cached", "rcode": "DNS answer code",

	// Gates.
	"score": "Gate score", "gate_rule": "Gate rule", "gate_outcome": "Gate outcome", "gate_facts": "Gate facts",
	"completion_unsupported": "Completion not supported",

	// Asks and answers.
	"ask_id": "Question id", "ask_rule": "Rule that asked", "hold": "What was held", "approved": "Approved",
	"after_s": "Answered after", "answer_reason": "Answer reason", "alternate": "File given instead",
	"alternate_dev": "Given file's device", "alternate_ino": "Given file's inode",

	// Gaps, limits, live changes.
	"what": "What is missing", "why": "Why", "binary": "Program", "which": "Limit", "value": "Value",
	"ceiling": "Ceiling", "live_block": "Live block", "live_block.op": "Change", "live_block.kind": "Block kind",
	"live_block.value": "Blocked", "live_block.rule": "Rule", "live_block.by": "By", "live_block.serial": "Change number",
	"live_block.at": "Made at", "live_control": "Pause or resume", "live_control.op": "Change",
	"live_control.by": "By", "live_control.serial": "Change number", "live_control.at": "Made at",
	"credential": "Credential", "credential.name": "Credential", "credential.version": "Credential version",
	"mcp_tool": "MCP tool switch", "mcp_tool.server": "MCP server", "mcp_tool.tool": "MCP tool",
	"mcp_tool.decision": "Decision", "mcp_tool.by": "By", "mcp_tool.serial": "Change number", "mcp_tool.at": "Made at",
	"route": "Model route", "route.name": "Route", "route.authority": "Sent to",
	"model_route": "Model route change", "model_route.model": "Model endpoint", "model_route.route": "Route",
	"model_route.authority": "Sent to", "model_route.by": "By", "model_route.serial": "Change number",
	"model_route.at": "Made at",

	// run_start.
	"tier": "Enforcement tier", "command": "Command", "command_blob": "Command (stored apart)", "cwd": "Working folder",
	"contract_source": "Rules file", "contract_source.path": "Rules file", "contract_source.name": "Agent name",
	"contract_hash": "Contract hash", "contract_revision": "Contract revision", "launcher_pid": "Launcher process",
	"launcher_start_ns": "Launcher start time", "launcher_uid": "Started by user id", "launcher_user": "Started by",
	"sudo_uid": "Through sudo, user id", "sudo_user": "Through sudo, user", "kernel": "Kernel",
	"tego_version": "Tego version", "commit": "Build commit",
	"bpf_hash": "Kernel program hash", "capabilities": "What this protection level can do", "capture": "Model traffic capture",
	"record_minor": "Record revision", "parsers": "Parsers", "limits": "Limits", "stop_grace": "Grace before kill",
	"net_assurance": "Network assurance", "net_guarantees": "Network guarantees", "fs_reads": "How reads are held",
	"fs_reads.reads": "Reads", "fs_reads.why": "Why", "fs_reads.nested": "Secret files inside writable folders",
	"reads_notified": "Reads seen by Tego", "reads_notified.notified": "Every read seen",
	"reads_notified.why": "Why", "harness": "Agent harness", "harness.name": "Harness",
	"harness.provisioned": "Set up by Tego", "harness.why": "Why", "harness.reason_file": "Refusal note file",
	"harness.files": "Files Tego wrote", "harness.state_dir": "Hook state folder", "harness.hook": "Hook",
	"harness.hook.argv": "Hook command", "harness.hook.granted": "Hook allowed", "stdio": "Standard streams",
	"stdio.stdin": "Input", "stdio.stdout": "Output", "stdio.stderr": "Errors", "deployment": "Deployment",
	"deployment.id": "Deployment id", "deployment.name": "Deployed agent", "deployment.revision": "Revision",
	"deployment.revision_hash": "Revision hash", "deployment.instance": "Instance", "deployment.trigger": "Started because",
	"deployment.previous_run": "Previous run", "deployment.change": "Change", "deployment.change.class": "Kind of change",
	"deployment.change.from_revision": "From revision", "runtime_grants": "Grants Tego made for this run",
	"run_command_grant": "Grant for the run's own command", "ask_read_relaxes": "Built-in secrets an ask relaxes",
	"exec_rules": "Command rules", "profiles": "Profiles", "redactions": "Secrets hidden from the record",
	"secrets": "Secrets handed to the agent", "vault": "Secret vault", "vault.memory": "Vault memory",
	"vault.peer": "Vault peer", "shares": "Shared folders", "labels": "Labels", "tags": "Tags", "role": "Role",
	"parent_run": "Parent run", "trace_id": "Trace id", "span_id": "Span id", "parent_span_id": "Parent span id",
	"propagated": "Trace headers passed on", "network_mode": "Network mode", "dockerfile_sha256": "Dockerfile hash",
	"host_sockets": "Host sockets", "env": "Environment", "network": "Network",

	// run_end.
	"exit_code": "Exit code", "stopped_by": "Stopped by", "resources": "Resources used",
	"memory_peak": "Peak memory", "pids_peak": "Most processes at once", "cpu_usage_usec": "CPU time",
	"cpu_user_usec": "CPU time (user)", "cpu_system_usec": "CPU time (system)", "cpu_nr_throttled": "Times slowed by the CPU limit",
	"cpu_throttled_usec": "Time slowed by the CPU limit", "memory_events": "Memory events", "high": "Over the high mark",
	"max": "At the memory cap", "oom": "Out of memory", "oom_kill": "Killed for memory", "supervisor": "Supervisor",
	"notifications": "Calls checked", "held_ms": "Time calls were held", "anomalies": "Anomalies",
	"exec_missing": "Programs that did not exist", "order_lost": "Order lost", "starved": "Starved",
	"ledger_bytes": "Record size", "killed": "Killed", "kill_failed": "Kill failed", "orphaned": "Left running",
	"escalated": "Escalated",

	// Model traffic.
	"endpoint": "Endpoint", "model": "Model", "status": "HTTP status", "latency_ms": "Took", "request_id": "Request id",
	"response_id": "Response id", "request_seq": "Request line", "stop_reason": "Why the model stopped",
	"content_encoding": "Compression", "parser_version": "Parser", "blob": "Body (stored apart)", "headers": "Headers",
	"truncated": "Cut", "wire_size": "Size on the wire", "size": "Size", "usage": "Tokens", "input": "Input tokens",
	"output": "Output tokens", "cache_read": "Cache read tokens", "cache_write": "Cache write tokens",
	"cache_write_1h": "Cache write tokens (1 h)", "server_tool": "Server tools", "modified": "Billed with a modifier",
	"context_bytes": "Context size", "body_sha256": "Body hash", "frame": "Body frame", "messages": "Messages",
	"cost_usd": "Cost (USD)", "tokens": "Tokens", "wall": "Wall time", "stall_after": "Stall after",
	"repeats": "Repeats",

	// Model steps and tools.
	"step": "Model step", "tool_use_id": "Tool call id", "tool": "Tool", "name": "Name", "input_hash": "Input hash",
	"text": "Text only", "unparsed": "Not parsed", "transport": "Transport",
	"side": "Side traffic (no model step)", "tool_results": "Tool results it reports",
}

// mapKeys are the keys whose nested keys are names, not fields (a capability, a header, a label): a nested key under
// one is labelled "<parent label>: <name>".
var mapKeys = map[string]bool{
	"capabilities": true, "net_guarantees": true, "headers": true, "labels": true, "parsers": true,
	"server_tool": true, "limits": true, "env": true, "gate_facts": true,
}

// Label is key's label: key is a payload key as a line writes it, or a nested key as a dotted path
// (resources.memory_peak). ok is false for a key this glossary does not know; label is then key itself.
func Label(key string) (label string, ok bool) {
	if l, ok := labels[key]; ok {
		return l, true
	}
	for i := strings.LastIndexByte(key, '.'); i > 0; i = strings.LastIndexByte(key[:i], '.') {
		if mapKeys[key[:i]] {
			parent, _ := Label(key[:i])
			return parent + ": " + key[i+1:], true
		}
	}
	if i := strings.LastIndexByte(key, '.'); i >= 0 {
		if l, ok := labels[key[i+1:]]; ok {
			return l, true
		}
	}
	return key, false
}

// Value is the plain words for key's value raw (one JSON value as the line holds it). ok is false when the glossary
// has nothing to add to the value as written: words is then raw read as text (a string unquoted, a list of strings
// joined), so a caller can always show words.
func Value(key string, raw []byte) (words string, ok bool) {
	leaf := key
	if i := strings.LastIndexByte(key, '.'); i >= 0 {
		leaf = key[i+1:]
	}
	var s string
	isStr := json.Unmarshal(raw, &s) == nil
	if isStr {
		if s == "" {
			return "empty", true
		}
		if w, ok := stringWords(key, leaf, s); ok {
			return w, true
		}
		return s, false
	}
	switch string(raw) {
	case "true":
		return "yes", true
	case "false":
		return "no", true
	case "null":
		return "none", true
	}
	var n json.Number
	if d := json.NewDecoder(strings.NewReader(string(raw))); d.Decode(&n) == nil {
		if w, ok := numberWords(key, leaf, n); ok {
			return w, true
		}
		return n.String(), false
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		if leaf == "argv" || leaf == "command" {
			return strings.Join(list, " "), false
		}
		if len(list) == 0 {
			return "none", true
		}
		return strings.Join(list, ", "), false
	}
	return string(raw), false
}

// stringWords is Value for a string value s.
func stringWords(key, leaf, s string) (string, bool) {
	switch key {
	case "reason", "answer_reason":
		return Reason(s)
	case "source":
		return Source(s)
	case "verdict":
		return Verdict(s)
	case "authority":
		return Authority(s)
	case "kind":
		return Kind(s)
	case "hold":
		return Hold(s)
	case "mechanism":
		return Mechanism(s)
	case "decision_plane":
		return DecisionPlane(s)
	case "plane_reason":
		return PlaneReason(s)
	case "what":
		return GapWhat(s)
	case "why":
		return GapWhy(s)
	case "reads_notified.why":
		return ReadsNotifiedWhy(s)
	case "fs_reads.why":
		return FSReadsWhy(s)
	case "fs_reads.reads":
		return lookup(map[string]string{"held": "held: Tego decides each read before it happens", "direct": "direct: the kernel decides reads on its own"}, s)
	case "tier":
		return Tier(s)
	case "capture":
		return lookup(map[string]string{"off": "off: model traffic is not recorded", "forwarder": "through Tego's forwarder",
			"ssl": "read from the TLS library", "hook": "from the harness's hook"}, s)
	case "attribution.confidence":
		return lookup(map[string]string{"exact": "exact", "likely": "likely", "unattributed": "not matched to a model step"}, s)
	case "attribution.method":
		return lookup(map[string]string{"tool_id": "the tool call id", "tid": "the thread", "time": "the time", "none": "nothing"}, s)
	case "verdict_from":
		return lookup(map[string]string{"plane": "the kernel decision plane", "lsm-chain": "another kernel security module", "unknown": "not known"}, s)
	case "argv_facts":
		return lookup(map[string]string{"copied_syscall": "copied from the call as it was made", "kernel_pinned": "pinned by the kernel", "unproven": "not proven"}, s)
	case "command_via":
		return lookup(map[string]string{"name": "the program's name", "path": "the program's path"}, s)
	case "command_list":
		return lookup(map[string]string{"allow": "the allowed commands", "deny": "the refused commands", "ask": "the commands that ask"}, s)
	case "command_match":
		return lookup(map[string]string{"definite": "a definite match", "ambiguous": "an ambiguous match"}, s)
	case "net_assurance":
		return lookup(map[string]string{"best-effort": "best effort: a program built to get past Tego could", "enforced": "enforced by the kernel"}, s)
	case "live_block.op", "live_control.op":
		return lookup(map[string]string{"add": "added", "remove": "removed", "pause": "paused", "resume": "resumed"}, s)
	case "deployment.trigger":
		return lookup(map[string]string{"update": "the deployment was updated", "schedule": "its schedule", "manual": "a person started it"}, s)
	case "stdio.stdin", "stdio.stdout", "stdio.stderr":
		return lookup(map[string]string{"tty": "a terminal", "null": "nothing (/dev/null)", "file": "a file", "pipe": "a pipe",
			"socket": "a socket", "unknown": "not known"}, s)
	}
	switch leaf {
	case "op":
		return Op(s)
	case "by", "stopped_by":
		return Who(s, nil), strings.Contains(s, "uid:") || strings.HasPrefix(s, "service:") || strings.HasPrefix(s, "standing:")
	}
	return "", false
}

// numberWords is Value for a number n.
func numberWords(key, leaf string, n json.Number) (string, bool) {
	i, iErr := n.Int64()
	f, fErr := n.Float64()
	switch {
	case leaf == "after_s" && fErr == nil:
		return Duration(time.Duration(f * float64(time.Second))), true
	case leaf == "flags" && iErr == nil && key == "flags":
		return OpenFlags(i), true
	case (leaf == "errno" || leaf == "syscall_errno") && iErr == nil:
		return Errno(i)
	case leaf == "syscall_ret" && iErr == nil:
		if i < 0 {
			if w, ok := Errno(-i); ok {
				return "failed: " + w, true
			}
			return "failed", true
		}
		return strconv.FormatInt(i, 10) + " (succeeded)", true
	case strings.HasSuffix(leaf, "_usec") && iErr == nil:
		return Duration(time.Duration(i) * time.Microsecond), true
	case strings.HasSuffix(leaf, "_ms") && iErr == nil:
		return Duration(time.Duration(i) * time.Millisecond), true
	case (leaf == "memory_peak" || leaf == "ledger_bytes" || leaf == "context_bytes" || leaf == "size" || leaf == "wire_size") && iErr == nil:
		return Bytes(i), true
	case leaf == "signal" && iErr == nil:
		return Signal(i)
	}
	return "", false
}

func lookup(m map[string]string, s string) (string, bool) {
	w, ok := m[s]
	if !ok {
		return s, false
	}
	return w, true
}

var reasons = map[string]string{
	"write-outside-contract":  "a write outside the folders the agent may change",
	"delete-outside-contract": "a delete outside the folders the agent may change",
	"rename-outside-contract": "a rename outside the folders the agent may change",
	"mkdir-outside-contract":  "a new folder outside the folders the agent may change",
	"read-denied":             "a read the rules refuse",
	"path-unresolved":         "a path Tego could not resolve, so it refused",
	"exec-not-allowed":        "a program the rules do not allow",
	"fs-gate":                 "a file gate refused it",
	"exec-gate":               "a program gate refused it",
	"net-not-allowed":         "a destination the rules do not allow",
	"net-gate":                "a network gate refused it",
	"net-http":                "an HTTP request the rules do not allow",
	"ask-denied":              "a person said no",
	"ask-timeout":             "nobody answered in time",
	"ask-unavailable":         "the question could not be asked",
	"ask-unreadable":          "the answer could not be read",
	"landlock-topology":       "a file layout the kernel's rules cannot hold, refused to be safe",
	"limit-tokens":            "the run used its token budget",
	"limit-cost":              "the run used its cost budget",
	"limit-wall":              "the run reached its time limit",
	"limit-stall":             "the agent stalled past its limit",
	"limit-repeats":           "the agent repeated the same thing too often",
	"oom":                     "the run ran out of memory",
	"pids":                    "the run reached its process limit",
	"credential-not-allowed":  "a key Tego would not send there",
	"credential-revoked":      "a revoked key",
	"credential-unavailable":  "a key the vault does not hold",
	"mcp-tool-denied":         "an MCP tool the rules do not allow",
	"model-route-changed":     "a model request whose route a person changed while it was held",
	// run_end reasons.
	"exit":    "the agent exited",
	"signal":  "the agent was ended by a signal",
	"stopped": "a person or service stopped it",
}

// Reason is a reason code (a refusal's, an answer's, a run_end's) in words.
func Reason(code string) (string, bool) { return lookup(reasons, code) }

var sources = map[string]string{
	"kernel":     "the kernel",
	"landlock":   "the kernel's Landlock rules",
	"seccomp":    "Tego's system-call supervisor",
	"fanotify":   "the kernel's file watcher (fanotify)",
	"ssl":        "the TLS library",
	"forwarder":  "Tego's model traffic forwarder",
	"hook":       "the agent harness's hook",
	"python":     "the Python runtime",
	"node":       "the Node.js runtime",
	"supervisor": "Tego's supervisor",
	"proxy":      "Tego's network proxy",
}

// Source is a line's source (which part of Tego wrote it) in words.
func Source(s string) (string, bool) { return lookup(sources, s) }

// Verdict is a verdict in words.
func Verdict(v string) (string, bool) {
	return lookup(map[string]string{"allow": "allowed", "ask": "held for a person", "refused": "refused", "observed": "recorded only, not decided"}, v)
}

// Authority is who decided a verdict, in words.
func Authority(a string) (string, bool) {
	return lookup(map[string]string{"rule": "a rule", "gate": "a gate", "human": "a person", "llm": "a model"}, a)
}

// Kind is a line's kind in words.
func Kind(k string) (string, bool) {
	return lookup(map[string]string{
		"run_start": "the run started", "run_end": "the run ended", "exec": "a program started", "fs": "a file action",
		"net": "a network action", "mcp": "a tool server call", "ssl_request": "a request to the model",
		"ssl_response": "the model's answer", "decision": "a model step", "ask": "a question to a person",
		"answer": "a person's answer", "refused": "a refusal", "gap": "a note about what the record lacks",
		"boundary": "a boundary", "limit": "a run limit",
	}, k)
}

// Hold is what an ask held, in words.
func Hold(h string) (string, bool) {
	return lookup(map[string]string{
		"open": "a file open", "exec": "a program start", "connect": "a connection", "first_write": "the first data sent on a connection",
		"request": "an HTTP request", "net": "a connection", "send": "data sent", "mutation": "a file change",
	}, h)
}

// Op is an operation in words.
func Op(op string) (string, bool) {
	return lookup(map[string]string{
		"open": "open", "read": "read", "write": "write", "unlink": "delete", "rmdir": "delete a folder", "rename": "rename",
		"mkdir": "create a folder", "link": "hard link", "symlink": "symbolic link", "chmod": "change permissions",
		"mknod": "create a device file", "truncate": "cut a file", "connect": "connect", "send": "send", "bind": "listen on",
		"listen": "listen", "accept": "accept a connection", "exec": "run a program", "request": "HTTP request",
		"socket": "open a socket", "sendto": "send", "sendmsg": "send",
	}, op)
}

// Mechanism is the kernel mechanism a refusal names (mechanism) in words.
func Mechanism(m string) (string, bool) {
	return lookup(map[string]string{
		"plane":    "the kernel decision plane",
		"cgroup":   "a kernel network filter on the run's process group",
		"landlock": "the kernel's Landlock rules",
	}, m)
}

// DecisionPlane is the kernel decision plane's mode in words.
func DecisionPlane(p string) (string, bool) {
	return lookup(map[string]string{
		"lsm": "a kernel security module (BPF LSM)", "fmod_ret": "a kernel return override (fmod_ret)",
		"fanotify": "the kernel's file watcher (fanotify), no decision plane",
	}, p)
}

var planeReasons = map[string]string{
	"refer":               "a rename or link across folders the rules keep apart",
	"deny-write-ancestor": "a change to a folder above a protected one",
	"identity-mismatch":   "the file changed identity while it was checked",
	"pin-missing":         "the program has no pinned fingerprint",
	"pin-mismatch":        "the program does not match its pinned fingerprint",
	"pin-unverifiable":    "the program's fingerprint could not be checked",
	"argv-changed":        "the command line changed after it was checked",
	"argv-unreadable":     "the command line could not be read",
	"exec-traced":         "the program was being traced",
}

// PlaneReason is the kernel decision plane's own reason in words.
func PlaneReason(r string) (string, bool) { return lookup(planeReasons, r) }

// GapWhat is a gap's what in words.
func GapWhat(w string) (string, bool) {
	return lookup(map[string]string{
		"capture": "model traffic not captured", "record": "something not recorded", "enforce": "a change to what is enforced",
		"limits": "a limit not held as asked",
	}, w)
}

var gapWhys = map[string]string{
	"no-price-table":          "no price table for this model, so cost is not counted",
	"no-models":               "no model capture for this agent",
	"argv-truncated":          "a command line too long to record whole",
	"path-truncated":          "a path too long to record whole",
	"ringbuf-full":            "some kernel events were dropped (the buffer was full)",
	"memory-swap-uncapped":    "the memory cap does not cover swap on this machine",
	"plane-identity-mismatch": "the kernel plane refused files that changed identity while checked",
	"plane-path-unresolved":   "the kernel plane refused paths it could not resolve",
	"plane-walk-bound":        "the kernel plane refused paths too deep to walk",
	"plane-no-rows":           "the kernel plane refused actions it had no rules for",
	"plane-counters-unread":   "the kernel plane's counters could not be read at the end",
	"live-block-added":        "a live block was added",
	"live-block-removed":      "a live block was removed",
	"live-block-unreadable":   "the live blocks could not be read; the last ones read stay in force",
	"live-block-lost":         "some live changes were lost from the record",
	"run-paused":              "the run was paused",
	"mcp-tool-changed":        "an MCP tool's rule was changed live",
	"run-resumed":             "the run was resumed",
	"pause-failed":            "a pause could not be put in force; the run kept running",
	"resume-failed":           "a resume could not be put in force; the run stays paused",
	"live-block-expired":      "a live block's time ran out; it no longer refuses",
	"live-unblock-expired":    "a live block's time off ran out; it refuses again",
	"live-rule-lifted":        "a rule in the fence was allowed for now",
	"live-rule-restored":      "a rule in the fence refuses again",
	"live-lift-expired":       "an allowed rule's time ran out; it refuses again",
	"live-lift-refused":       "a request to allow a rule was refused; nothing was loosened",
	"model-route-changed":     "a model endpoint's requests were sent to another approved backend",
	"launcher-lost":           "the run's supervisor was gone before the run ended, so the record's last lines may be missing",
	"torn-tail":               "the supervisor died in the middle of a line, so that line is lost",
}

// GapWhy is a gap's why in words.
func GapWhy(w string) (string, bool) { return lookup(gapWhys, w) }

var readsNotifiedWhys = map[string]string{
	"record-full":   "the contract records everything",
	"gate":          "a read gate scores every read",
	"ask-read":      "an ask on reads holds the reads it decides",
	"held":          "the run holds its reads",
	"reason":        "the contract asks for refused reads to be recorded",
	"reason-off":    "refused reads are left to the kernel and not recorded",
	"kernel":        "the kernel records refused reads itself",
	"records-only":  "the run enforces nothing; it only records",
	"no-supervisor": "no supervisor answered the run's checks",
}

// ReadsNotifiedWhy is run_start's reads_notified.why in words.
func ReadsNotifiedWhy(w string) (string, bool) { return lookup(readsNotifiedWhys, w) }

var fsReadsWhys = map[string]string{
	"contract":        "the contract asks for held reads",
	"nested":          "a secret file sits inside a folder the agent may change",
	"contract-direct": "the contract asks for direct reads",
	"none-nested":     "no secret file sits inside a folder the agent may change",
	"kernel":          "the kernel refuses such reads itself",
	"records-only":    "the run enforces nothing; it only records",
}

// FSReadsWhy is run_start's fs_reads.why in words.
func FSReadsWhy(w string) (string, bool) { return lookup(fsReadsWhys, w) }

// Tier is an enforcement tier in words.
func Tier(t string) (string, bool) {
	return lookup(map[string]string{
		"landlock": "Basic (tier 1): Landlock and a system-call supervisor, no root", "cgroup": "Strong (tier 2): kernel filters with root",
		"bpflsm": "Strongest (tier 3): a kernel security module", "observe": "watch only: nothing enforced", "watch": "watch only: nothing enforced",
	}, t)
}

// errnos are the Linux error numbers a ledger line names, with their names and words.
var errnos = map[int64][2]string{
	1: {"EPERM", "operation not permitted"}, 2: {"ENOENT", "no such file or folder"}, 3: {"ESRCH", "no such process"},
	4: {"EINTR", "interrupted"}, 5: {"EIO", "input/output error"}, 6: {"ENXIO", "no such device"},
	7: {"E2BIG", "argument list too long"}, 8: {"ENOEXEC", "not a program it can run"}, 9: {"EBADF", "bad file handle"},
	11: {"EAGAIN", "try again"}, 12: {"ENOMEM", "out of memory"}, 13: {"EACCES", "permission denied"},
	14: {"EFAULT", "bad address"}, 16: {"EBUSY", "busy"}, 17: {"EEXIST", "already exists"},
	18: {"EXDEV", "across file systems"}, 20: {"ENOTDIR", "not a folder"}, 21: {"EISDIR", "is a folder"},
	22: {"EINVAL", "invalid argument"}, 24: {"EMFILE", "too many open files"}, 26: {"ETXTBSY", "program file busy"},
	28: {"ENOSPC", "no space left"}, 30: {"EROFS", "read-only file system"}, 32: {"EPIPE", "broken pipe"},
	36: {"ENAMETOOLONG", "name too long"}, 38: {"ENOSYS", "not supported by the kernel"}, 39: {"ENOTEMPTY", "folder not empty"},
	40: {"ELOOP", "too many symbolic links"}, 88: {"ENOTSOCK", "not a socket"}, 93: {"EPROTONOSUPPORT", "protocol not supported"},
	95: {"EOPNOTSUPP", "operation not supported"}, 97: {"EAFNOSUPPORT", "address family not supported"},
	98: {"EADDRINUSE", "address in use"}, 99: {"EADDRNOTAVAIL", "address not available"}, 101: {"ENETUNREACH", "network unreachable"},
	104: {"ECONNRESET", "connection reset"}, 110: {"ETIMEDOUT", "timed out"}, 111: {"ECONNREFUSED", "connection refused"},
	113: {"EHOSTUNREACH", "host unreachable"},
}

// Errno is a Linux error number as "EACCES (permission denied)"; ok is false for a number the table lacks.
func Errno(n int64) (string, bool) {
	e, ok := errnos[n]
	if !ok {
		return strconv.FormatInt(n, 10), false
	}
	return e[0] + " (" + e[1] + ")", true
}

// ErrnoName is the name alone ("EACCES"), "" for a number the table lacks.
func ErrnoName(n int64) string { return errnos[n][0] }

// Signal is a signal number as "SIGKILL (9)".
func Signal(n int64) (string, bool) {
	names := map[int64]string{1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 6: "SIGABRT", 9: "SIGKILL", 11: "SIGSEGV", 13: "SIGPIPE", 15: "SIGTERM"}
	s, ok := names[n]
	if !ok {
		return strconv.FormatInt(n, 10), false
	}
	return fmt.Sprintf("%s (%d)", s, n), true
}

// OpenFlags is open(2) flags in words: what the open was for and the flags that change what it does.
func OpenFlags(f int64) string {
	const (
		wronly, rdwr                         = 0o1, 0o2
		creat, excl, trunc, appnd            = 0o100, 0o200, 0o1000, 0o2000
		directory, nofollow, cloexec, tmpfil = 0o200000, 0o400000, 0o2000000, 0o20000000
		path                                 = 0o10000000
	)
	var parts []string
	switch {
	case f&path != 0:
		parts = append(parts, "a handle only (O_PATH)")
	case f&3 == wronly:
		parts = append(parts, "write")
	case f&3 == rdwr:
		parts = append(parts, "read and write")
	default:
		parts = append(parts, "read")
	}
	for _, x := range []struct {
		bit  int64
		word string
	}{{creat, "create"}, {excl, "only if new"}, {trunc, "empty it first"}, {appnd, "append"}, {directory, "a folder"},
		{nofollow, "no symbolic link"}, {tmpfil &^ directory, "an unnamed temporary file"}} {
		if f&x.bit == x.bit && x.bit != 0 {
			parts = append(parts, x.word)
		}
	}
	_ = cloexec // closing on exec changes nothing a person reads
	return strings.Join(parts, ", ") + " (" + strconv.FormatInt(f, 10) + ")"
}

// Bytes is a byte count as "6.3 MiB".
func Bytes(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " bytes"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// Duration is d as a person reads it: "850 ms", "41.7 s", "2 m 5 s", "1 h 3 m".
func Duration(d time.Duration) string {
	switch {
	case d == 0:
		return "0 s"
	case d < 0:
		return "-" + Duration(-d)
	case d < time.Millisecond:
		return strconv.FormatInt(d.Microseconds(), 10) + " µs"
	case d < time.Second:
		return strconv.FormatInt(d.Milliseconds(), 10) + " ms"
	case d < time.Minute:
		return strconv.FormatFloat(d.Seconds(), 'f', 1, 64) + " s"
	case d < time.Hour:
		return fmt.Sprintf("%d m %d s", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%d h %d m", int(d.Hours()), int(d.Minutes())%60)
}

// WithdrawnBy is the principal of the answer the broker writes when it takes a pending ask back because a live block
// landed while the person was deciding (an ask-unavailable answer by "cancelled", SEMANTICS §6). No person answered
// it, so it never reads "denied by cancelled".
const WithdrawnBy = "cancelled"

// Withdrawn is how a withdrawn ask (WithdrawnBy) reads wherever an answer is shown.
const Withdrawn = "Withdrawn: a live block now refuses this"

// Who is a principal as a ledger line names it ("uid:1000 pid:4035742 dashboard", "standing:…", "service:deploy")
// in words: "alice, from the dashboard". name looks a uid up ("" when unknown, or a nil name): an unknown uid reads
// "user 1000". A principal that names no uid is returned as written.
func Who(by string, name func(uid string) string) string {
	if by == "" {
		return ""
	}
	if strings.HasPrefix(by, "standing:") {
		return "an earlier answer for the rest of this run"
	}
	if svc, ok := strings.CutPrefix(by, "service:"); ok {
		return "the service " + svc
	}
	who, rest := "", []string{}
	for _, w := range strings.Fields(by) {
		switch {
		case strings.HasPrefix(w, "uid:"):
			uid := strings.TrimPrefix(w, "uid:")
			if _, err := strconv.Atoi(uid); err == nil {
				if name != nil {
					who = name(uid)
				}
				if who == "" {
					who = "user " + uid
				}
			}
		case strings.HasPrefix(w, "pid:"), w == "always":
		default:
			rest = append(rest, w)
		}
	}
	if who == "" {
		return by
	}
	switch r := strings.Join(rest, " "); r {
	case "":
		return who
	case "dashboard":
		return who + ", from the dashboard"
	case "cli":
		return who + ", from the command line"
	default:
		return who + " (" + r + ")"
	}
}
