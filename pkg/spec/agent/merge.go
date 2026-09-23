// SPDX-License-Identifier: Apache-2.0

package agent

import "reflect"

// merge lays contract c on top of profile p (R5, SEMANTICS §1): one loop over contractMergeRows, where every key
// of Contract and of its sections has its row and merge class (mergeclass.go, ADR 0065). Origins are carried
// across so every merged entry still points at the file and line it was written in.
func merge(p, c *Contract) *Contract { return mergeWith(newMerger(p.origins, c.origins), p, c) }

// mergeScalars is merge for a file's whole view (ADR 0066 D3): its scalar keys only, every list left out, so a
// view that counts a shared ancestor once per path to it stays the size of its keys. written is filled with every
// contract-wins and env.set key c wrote, which settles a conflict between the parents p combines.
func mergeScalars(p, c *Contract, written map[string]bool) *Contract {
	m := newMerger(p.origins, c.origins)
	m.scalars, m.written = true, written
	return mergeWith(m, p, c)
}

func mergeWith(m *merger, p, c *Contract) *Contract {
	r := &Contract{file: c.file, origins: m.out}
	contractTable.merge(m, reflect.ValueOf(p).Elem(), reflect.ValueOf(c).Elem(), reflect.ValueOf(r).Elem())
	return r
}

// assuranceOrder is fs.assurance's and exec.assurance's: kernel is the stricter (ADR 0041 D1 (a), ADR 0048 (3)
// P2), so a contract cannot lower a profile's kernel requirement; Load warns at a best-effort a profile's kernel
// outvoted (fsAssuranceOutvoted, execAssuranceOutvoted).
var assuranceOrder = []string{string(FSAssuranceKernel), string(FSAssuranceBestEffort)}

// contractMergeRows is the merge table: one row per key, a section's rows after it. A key a package adds to the
// contract adds its row here, with the class ADR 0065 fixes for it; TestEveryContractKeyHasAMergeClass fails for a
// key with none.
var contractMergeRows = []mergeRow{
	// version and name are the top file's own and never inherited: validateMerged asks the merged origins
	// whether version was written, and a profile's version: 0 answered for a contract that wrote none.
	keyRow("version", classOwn),
	keyRow("name", classOwn),
	// revision names the version of the top-level file a run compiled; a profile's would name another file's
	// (agent-contract.md R28).
	keyRow("revision", classRefusedInProfile),
	keyRow("extends", classOwn),
	keyRow("command", classContractWins),

	keyRow("fs", classSection),
	keyRow("fs.write", classConcat),
	keyRow("fs.ask", classConcat),
	// deny_read: a contract's deny_read: [] cannot disable a profile's entries, and a profile's nil (the
	// built-in list) is kept when the contract says nothing. The merged list is empty, the one shape that
	// disables the built-in list (R6), only when some file wrote `[]` and no file declares an entry; Load's
	// denyReadSwitch warns a file whose `[]` the union outvoted.
	keyRow("fs.deny_read", classUnion),
	// ask_read never removes a deny: an entry at or beneath a declared deny_read, whichever file declared either,
	// is a contradiction at Compile, and one that would lift a built-in entry is honoured only when the
	// top-level contract declares it (compile_askread.go).
	keyRow("fs.ask_read", classConcat),
	keyRow("fs.watch", classConcat),
	// deny_write: what a run may not modify beneath its write entries (ADR 0071); a file's `[]` contributes nothing,
	// and no file removes another's entry or the built-in set (R20).
	keyRow("fs.deny_write", classUnion),
	stricterRow("fs.assurance", assuranceOrder),
	// fs.reads (ADR 0069): held, then auto, then direct, which counts only from the top-level contract, so a
	// profile cannot leave a deny_read inside a write entry unenforced (a profile's direct is ignored with a warning).
	stricterRow("fs.reads", readsOrder, string(ReadsDirect)),

	keyRow("net", classSection),
	keyRow("net.assurance", classContractWins),
	keyRow("net.allow", classConcat),
	keyRow("net.ask", classConcat),
	keyRow("net.http", classConcat),
	keyRow("net.listen", classConcat),
	keyRow("net.ingress", classConcat),
	keyRow("net.limits", classSection),
	keyRow("net.limits.connections", classContractWins),
	keyRow("net.limits.pending_connects", classContractWins),
	keyRow("net.limits.bytes", classContractWins),
	keyRow("net.limits.datagrams_per_second", classContractWins),
	keyRow("net.dns", classSection),
	keyRow("net.dns.mode", classContractWins),
	keyRow("net.dns.allow", classConcat),
	keyRow("net.dns.types", classConcat),
	keyRow("net.dns.max_stale", classContractWins),
	keyRow("net.dns.max_parallel", classContractWins),
	keyRow("net.dns.cache", classContractWins),
	keyRow("net.proxy", classSection),
	keyRow("net.proxy.http2", classContractWins),
	keyRow("net.proxy.websocket", classConcat),
	keyRow("net.proxy.connect", classConcat),
	keyRow("net.proxy.max_streams", classContractWins),
	keyRow("net.proxy.max_tunnel_bytes", classContractWins),
	keyRow("net.proxy.max_frame_bytes", classContractWins),
	keyRow("net.proxy.tunnel_idle", classContractWins),
	keyRow("net.proxy.tunnel_wall", classContractWins),

	// exec: deny and ask concatenate as allow does; a present empty list stays non-nil, since presence is the
	// mode (ADR 0048 (1)).
	keyRow("exec", classSection),
	keyRow("exec.allow", classConcat),
	keyRow("exec.deny", classConcat),
	keyRow("exec.ask", classConcat),
	keyRow("exec.privileged", classConcat),
	keyRow("exec.anonymous", classContractWins),
	stricterRow("exec.assurance", assuranceOrder),

	keyRow("env", classSection),
	keyRow("env.pass", classConcat),
	keyRow("env.deny", classConcat),
	keyRow("env.mask", classConcat),
	keyRow("env.set", classKeyMerge),

	keyRow("mcp", classConcat),
	keyRow("models", classConcat),
	keyRow("credentials", classConcat),

	keyRow("limits", classSection),
	keyRow("limits.cpu", classContractWins),
	keyRow("limits.cpu_weight", classContractWins),
	keyRow("limits.memory", classContractWins),
	keyRow("limits.memory_high", classContractWins),
	keyRow("limits.pids", classContractWins),
	keyRow("limits.tokens", classContractWins),
	keyRow("limits.cost_usd", classContractWins),
	keyRow("limits.wall", classContractWins),
	keyRow("limits.stall_after", classContractWins),
	keyRow("limits.repeats", classContractWins),

	keyRow("record", classContractWins),
	keyRow("tier", classContractWins),
	keyRow("capture", classContractWins),
	keyRow("io_uring", classContractWins),
	keyRow("keyring", classContractWins),
	keyRow("ipc", classContractWins),
	keyRow("setuid", classContractWins),
	keyRow("harness", classContractWins),
	keyRow("reason", classSection),
	keyRow("reason.reads", classContractWins),
	// host_sockets: true opens every host daemon socket to a run with no net: section (ADR 0070): false is the
	// stricter value and true loosens, so a profile cannot open them for the contract that extends it.
	stricterRow("host_sockets", []string{"false", "true"}, "true"),
	// keep_descendants: true lets processes the agent left behind keep the run going after its main process exits:
	// false ends them stop_grace after it, so a profile cannot keep them for the contract that extends it.
	stricterRow("keep_descendants", []string{"false", "true"}, "true"),

	// gate and ask are retained as YAML nodes: a mapping the contract writes, even an empty one, replaces the
	// inherited mapping as a whole; absent, it inherits the profile's (R5). Docker keeps its empty-is-absent
	// compatibility (schema-only).
	{path: "gate", class: classContractWins, rule: mergeRule{empty: emptyResetsInContract}},
	keyRow("prompt", classContractWins),
	keyRow("skills", classConcat),
	keyRow("visibility", classConcat),
	{path: "docker", class: classContractWins, rule: mergeRule{empty: emptyIsAbsent}},
	keyRow("containers", classContractWins),
	{path: "ask", class: classContractWins, rule: mergeRule{empty: emptyResetsInContract}},
	// live: is how the top-level contract's runs may change while they run (ADR 0125): a profile's would let a file
	// the contract only extends make its runs loosenable.
	{path: "live", class: classRefusedInProfile, rule: mergeRule{code: CodeLiveInProfile}},
}

var contractTable = mustMergeTable(reflect.TypeFor[Contract](), contractMergeRows)
