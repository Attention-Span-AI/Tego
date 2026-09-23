// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// origins maps a dotted field path ("fs.write.2", "limits.memory",
// "env.set.HOME", "mcp.0.command.1") to the position of its value node.
type origins map[string]Pos

// originIndex groups an origins map's keys by every dotted prefix they
// sit under ("fs.write.2.path" is filed under itself, "fs.write.2",
// "fs.write" and "fs"), so copyPrefix finds a subtree without scanning
// the whole map. Building it costs O(keys x depth); a merge that copied
// each of n list entries by scanning the map was O(n^2) (E24).
type originIndex struct {
	o     origins
	under map[string][]string
}

func indexOrigins(o origins) *originIndex {
	x := &originIndex{o: o, under: make(map[string][]string, len(o))}
	for k := range o {
		for p := k; ; {
			x.under[p] = append(x.under[p], k)
			i := strings.LastIndexByte(p, '.')
			if i < 0 {
				break
			}
			p = p[:i]
		}
	}
	return x
}

// copyPrefix copies src[srcKey] and every key beneath it into dst under dstKey.
func (o origins) copyPrefix(dstKey string, src *originIndex, srcKey string) {
	for _, k := range src.under[srcKey] {
		o[dstKey+k[len(srcKey):]] = src.o[k]
	}
}

// fieldKind is the shape a schema node expects.
type fieldKind int

const (
	kindScalar fieldKind = iota
	kindSeq
	kindMap      // fixed field set
	kindMapFree  // free keys (env.set)
	kindAny      // schema-only subtree, accepted verbatim
	kindOneOrSeq // one value, or a list of 1 to maxItems of them (extends)
)

// checkFn validates one scalar; a non-empty msg is a schema error.
type checkFn func(value string) (msg, fix string)

// field is one node of the v0 schema tree.
type field struct {
	kind     fieldKind
	fields   map[string]*field // kindMap
	elem     *field            // kindSeq, kindMapFree, kindOneOrSeq
	maxItems int               // kindOneOrSeq: the most entries its list form may hold
	check    checkFn           // kindScalar
	keyCheck checkFn           // kindMapFree
	required []string          // kindMap: keys that must be present
	// nullMeans and nullFix, when set, make a null value (the key present with nothing after it, or
	// with only comments under it) a schema error saying what it would have read as, rather than absent
	// (nullRefused).
	nullMeans, nullFix string
	// nullDeferred, when set, records a null value's position (walker.nulls) for a check after the merge, which
	// alone can say what the key's absence means.
	nullDeferred bool
	// numeric marks a scalar the typed decode reads into a Go number, so a quoted value is refused with a
	// fix line (number) rather than left to yaml.v3's "cannot unmarshal !!str".
	numeric bool
	// textual marks a scalar agent.schema.json types as a string, so a plain value YAML resolves to a number or a
	// boolean is refused with a fix line (text), as a JSON Schema validator refuses it.
	textual bool
}

func scalar(check checkFn) *field { return &field{kind: kindScalar, check: check} }
func seq(elem *field) *field      { return &field{kind: kindSeq, elem: elem} }

// oneOrList is a key written as one value or as a list of 1 to maxItems values, each held to elem.
func oneOrList(elem *field, maxItems int) *field {
	return &field{kind: kindOneOrSeq, elem: elem, maxItems: maxItems}
}
func mapping(f map[string]*field) *field {
	return &field{kind: kindMap, fields: f}
}

// number marks a scalar field as one written as a YAML number: `tokens: "5"` is a string, which the typed
// decode refused as "cannot unmarshal !!str `5` into int64", naming neither the key nor the fix.
func number(f *field) *field {
	f.numeric = true
	return f
}

// text marks a scalar field as one written as a YAML string: `revision: 1.50` is the float 1.5 to YAML and to
// a JSON Schema validator of agent.schema.json, whose {"type": "string"} refuses it, while the walk alone would take
// its text "1.50". So Go refuses it too, with the fix to quote it, and the two agree on every spelling.
func text(f *field) *field {
	f.textual = true
	return f
}

// requiring marks keys a mapping must carry (checked per file, so the
// top-level required fields, which a profile may omit, are validated after
// the merge instead).
func requiring(m *field, keys ...string) *field {
	m.required = keys
	return m
}

// nullRefused makes a null value for this key a schema error: means is what the absent key it parsed as
// reads as, fix what to write instead. `net:` or `exec:` with nothing under it (every entry commented out)
// parsed as absent, which SEMANTICS §1 reads as unrestricted, while it looks like a section that allows
// nothing, and compile's table printed it like deny-all (R1).
func nullRefused(f *field, means, fix string) *field {
	f.nullMeans, f.nullFix = means, fix
	return f
}

// nullDeferred reads a null value for this key as absent, and records where it was (walker.nulls) for a check
// after the merge.
func nullDeferred(f *field) *field {
	f.nullDeferred = true
	return f
}

// nullLimit refuses a null value for one limits key: absent is unbounded.
func nullLimit(f *field) *field {
	return nullRefused(f, "unbounded", "give the limit a value, or remove the key")
}

func freeMap(keyCheck checkFn, elem *field) *field {
	return &field{kind: kindMapFree, keyCheck: keyCheck, elem: elem}
}

// Validation regexes (R3, R12, E26).
var (
	nameRE = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)
	// revisionRE is the contract key revision (agent-contract.md R28).
	revisionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	envNameRE  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	intRE      = regexp.MustCompile(`^-?[0-9]+$`)
	// profileRE is a profile name: '/'-separated segments of lowercase letters, digits, '.', '_' and '-', the
	// first opening with a letter or digit, no segment empty, '.' or holding "..". Each profile file then has one
	// spelling (ADR 0066 D1): `base/./py` read profiles/base/py.yaml as `base/py` does, and merge-once and the
	// cycle check compare names. A name under tego/ may end in a revision pin, '@' and a revision number from 1
	// without a leading zero (tego/no-secrets@1, ADR 0068); no other name takes one, since only a built-in profile
	// has revisions. spec/agent/v0/agent.schema.json's profileName is this pattern (TestProfileNameHasOneSpelling).
	profileRE = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9_-]|\.[a-z0-9_-])*\.?(?:/(?:[a-z0-9_-]|\.[a-z0-9_-])+\.?)*|tego(?:/(?:[a-z0-9_-]|\.[a-z0-9_-])+\.?)+@[1-9][0-9]{0,8})$`)
)

// contractSchema is the v0 schema tree. Every key here mirrors a field of
// Contract; the not-yet-supported subset is accepted by shape and rejected
// by value after the merge (R2).
var contractSchema = mapping(map[string]*field{
	"version": number(scalar(checkVersion)),
	"name":    text(scalar(regexCheck(nameRE, "name must match ^[a-z0-9-]{1,40}$"))),
	// The author's name for this version of the contract (agent-contract.md R28).
	"revision": nullRefused(text(scalar(regexCheck(revisionRE, "revision must match ^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$"))),
		"no revision is recorded", "write the revision, or remove the key"),
	// `extends:` with no value parsed as absent, no profile, while it reads like a profile left out (R1).
	// One profile name or a list of 1 to MaxExtendsList (ADR 0066).
	"extends": nullRefused(oneOrList(scalar(checkProfileName), MaxExtendsList), "no profile is merged", "name the profile, or remove the key"),
	"command": seq(scalar(nonEmpty("command entry"))),
	"fs": nullRefused(mapping(map[string]*field{
		"write": seq(scalar(checkPath)),
		"ask":   seq(scalar(checkAskPath)),
		"deny_read": nullRefused(seq(scalar(checkPath)), "the built-in credential deny list only",
			"write `deny_read: []` to turn the built-in list off, list the paths to deny, or remove the key"),
		"ask_read":   seq(scalar(checkAskReadPath)),
		"watch":      seq(scalar(checkPath)),
		"deny_write": seq(scalar(checkDenyWritePath)),
		"assurance":  scalar(enumCheck("assurance", "best-effort", "kernel")),
		"reads":      scalar(enumCheck("reads", "auto", "held", "direct")),
	}), "no writable path", "write `fs: {}` for no writable path, or remove the key"),
	"net": nullRefused(mapping(map[string]*field{
		"assurance": scalar(enumCheck("assurance", "best-effort", "kernel")),
		"allow":     seq(scalar(checkEndpoint)),
		"ask":       seq(scalar(checkAskEndpoint)),
		"listen":    nullRefused(seq(scalar(nonEmpty("listen endpoint"))), "listener control is absent", "write `listen: []` to refuse binds, or list bind endpoints"),
		"ingress": nullRefused(seq(requiring(mapping(map[string]*field{
			"from": scalar(nonEmpty("source prefix")),
			"to":   scalar(nonEmpty("listener endpoint")),
		}), "from", "to")), "ingress control is absent", "write `ingress: []` to allow replies only, or list source/listener rules"),
		"limits": nullRefused(mapping(map[string]*field{
			"connections":          nullLimit(number(scalar(intRange("connections", 0, 1<<62)))),
			"pending_connects":     nullLimit(number(scalar(intRange("pending_connects", 0, 1<<62)))),
			"bytes":                nullLimit(scalar(checkNetworkByteSize)),
			"datagrams_per_second": nullLimit(number(scalar(intRange("datagrams_per_second", 0, 1<<62)))),
		}), "network limits are absent", "write the intended budgets or remove the key"),
		"dns": nullRefused(mapping(map[string]*field{
			"mode":         scalar(enumCheck("dns mode", "system", "broker", "off")),
			"allow":        nullRefused(seq(scalar(nonEmpty("DNS name"))), "DNS names are unrestricted", "write `allow: []` to refuse all names, or list allowed names"),
			"types":        nullRefused(seq(scalar(nonEmpty("DNS type"))), "default DNS types are used", "write `types: []` to refuse all types, or list allowed types"),
			"max_stale":    nullLimit(scalar(checkNonnegativeDuration)),
			"max_parallel": number(scalar(intRange("max_parallel", 1, 16))),
			"cache":        nullLimit(number(scalar(intRange("cache", 0, 512)))),
		}), "DNS policy is absent", "write the intended mode or remove the key"),
		"proxy": nullRefused(mapping(map[string]*field{
			"http2": scalar(enumCheck("http2", "true", "false")),
			"websocket": seq(requiring(mapping(map[string]*field{
				"host": scalar(nonEmpty("host")), "allow": seq(scalar(nonEmpty("path"))), "methods": seq(scalar(nonEmpty("method"))),
			}), "host")),
			"connect":          seq(scalar(nonEmpty("CONNECT authority"))),
			"max_streams":      number(scalar(intRange("max_streams", 1, 128))),
			"max_tunnel_bytes": nullLimit(scalar(checkByteSize)),
			"max_frame_bytes":  nullLimit(scalar(checkByteSize)),
			"tunnel_idle":      nullLimit(scalar(checkDuration)),
			"tunnel_wall":      nullLimit(scalar(checkDuration)),
		}), "additional proxy protocols are disabled", "write the intended optional protocols or remove the key"),
		// host is required, as agent.schema.json and proxy.websocket say (amended 2026-10-05, review spec-5:
		// a host-less entry was refused only later, by CompileHTTPPolicy, with a message naming the host's form).
		"http": seq(requiring(mapping(map[string]*field{
			"host":    scalar(nonEmpty("host")),
			"allow":   seq(scalar(nonEmpty("path"))),
			"methods": seq(scalar(nonEmpty("method"))),
		}), "host")),
	}), "the network is unrestricted", "write `net: {}` to refuse all, or remove the key"),
	"exec": nullRefused(mapping(map[string]*field{
		// allow, deny and ask: a key with nothing under it parsed as absent, which flips the mode (ADR 0048 (1): the
		// mode is the keys present). A null allow is refused only where it does flip it: when the merged section is
		// a deny-list, where every image may run, though an allow key, even allow: [], restricts images
		// (loader.nullExecAllow). Alone it reads as absent, a restricted section, as every contract written
		// before ADR 0048 read it.
		"allow": nullDeferred(seq(scalar(checkExecEntry))),
		"deny": nullRefused(seq(scalar(checkExecEntry)), "no deny key: with no allow key either, exec: restricts every image",
			"write `deny: []` for a deny-list with no entry yet, list the commands to deny, or remove the key"),
		"ask": nullRefused(seq(scalar(checkExecEntry)), "no ask key: with no allow or deny key either, exec: restricts every image",
			"write `ask: []`, list the commands, or remove the key"),
		"privileged": seq(scalar(nonEmpty("privileged pattern"))),
		"anonymous":  scalar(enumCheck("anonymous", "true", "false")),
		"assurance":  scalar(enumCheck("assurance", "best-effort", "kernel")),
	}), "exec is unrestricted", "write `exec: {}` to refuse all, or remove the key"),
	"env": mapping(map[string]*field{
		"pass": nullRefused(seq(scalar(checkEnvName)), "the whole environment is passed", "write `pass: []` to pass nothing, or remove the key"),
		"deny": nullRefused(seq(scalar(checkEnvName)), "nothing is denied", "write `deny: []` to deny nothing, or remove the key"),
		"mask": seq(scalar(checkEnvName)),
		"set":  freeMap(checkEnvName, scalar(checkEnvValue)),
	}),
	"mcp": seq(requiring(mapping(map[string]*field{
		"name":    text(scalar(regexCheck(nameRE, "mcp name must match ^[a-z0-9-]{1,40}$"))),
		"command": seq(scalar(nonEmpty("mcp command entry"))),
		// Read by validateMCP (ParseMCPURL), which also asks for exactly one of command and url (R16a).
		"url": scalar(nonEmpty("mcp url")),
		// Per-tool rules behind Tego's MCP relay (R16b, ADR 0126); validateMCPTools reads the names. A key with no value
		// parsed as absent: tools: left the server off the relay, and allow: allowed every tool, the opposite of allow: [].
		"tools": nullRefused(mapping(map[string]*field{
			"allow": nullRefused(seq(scalar(nonEmpty("mcp tool name"))), "every tool is allowed", "write `allow: []` to allow none, list the tools, or remove the key"),
			"deny":  nullRefused(seq(scalar(nonEmpty("mcp tool name"))), "no tool is denied", "write `deny: []` to deny none, list the tools, or remove the key"),
			"ask":   nullRefused(seq(scalar(nonEmpty("mcp tool name"))), "no tool is asked about", "write `ask: []` to ask about none, list the tools, or remove the key"),
		}), "the server is not behind the relay", "write `tools: {}` to put it behind the relay, or remove the key"),
	}), "name")),
	// The credentials: section (R30); validateCredentials reads the cross-field rules.
	"credentials": seq(requiring(mapping(map[string]*field{
		"name":         scalar(nonEmpty("credential name")),
		"env":          scalar(checkEnvName),
		"allow":        seq(scalar(nonEmpty("credential allow entry"))),
		"base_url_env": scalar(checkEnvName),
	}), "name", "env", "allow")),
	"models": seq(requiring(mapping(map[string]*field{
		"provider": scalar(nonEmpty("provider")),
		"host":     scalar(checkHost),
		"port":     number(scalar(intRange("port", 1, 65535))),
		// Declared backends a run's model requests may be rerouted to, live (R32, ADR 0127); validateModelRoutes
		// reads the cross-field rules.
		"routes": seq(requiring(mapping(map[string]*field{
			"name": scalar(nonEmpty("route name")),
			"host": scalar(checkHost),
			"port": number(scalar(intRange("port", 1, 65535))),
			"tls":  scalar(enumCheck("tls", "true", "false")),
		}), "name", "host", "port")),
	}), "provider", "host", "port")),
	// A null limit (`memory:` with nothing after it) parsed as absent, which is unbounded, while it reads
	// like a limit whose value was left out: each is refused (R1). So is a null limits: section itself
	// (`limits: ~`, or every key under it commented out), which parsed as absent, every limit unbounded.
	"limits": nullRefused(mapping(map[string]*field{
		"cpu":         nullLimit(scalar(checkCPU)),
		"cpu_weight":  nullLimit(number(scalar(intRange("cpu_weight", 1, 10000)))),
		"memory":      nullLimit(scalar(checkByteSize)),
		"memory_high": nullLimit(scalar(checkByteSize)),
		"pids":        nullLimit(number(scalar(intRange("pids", 1, config.PidsMax)))),
		"tokens":      nullLimit(number(scalar(intRange("tokens", 1, 1<<62)))),
		"cost_usd":    nullLimit(number(scalar(checkCost))),
		"wall":        nullLimit(scalar(checkDuration)),
		"stall_after": nullLimit(scalar(checkDuration)),
		"repeats":     nullLimit(number(scalar(intRange("repeats", 1, 1<<31-1)))),
	}), "every limit is unbounded", "write `limits: {}` for no limit, give the limits values, or remove the key"),
	"record":           scalar(enumCheck("record", "full", "summary", "off")),
	"tier":             scalar(enumCheck("tier", "auto", "landlock", "cgroup", "bpflsm")),
	"capture":          scalar(enumCheck("capture", "auto", "uprobe", "forwarder", "off")),
	"io_uring":         scalar(enumCheck("io_uring", "true", "false")),
	"keyring":          scalar(enumCheck("keyring", "true", "false")),
	"ipc":              scalar(enumCheck("ipc", "true", "false")),
	"setuid":           scalar(enumCheck("setuid", "true", "false")),
	"host_sockets":     scalar(enumCheck("host_sockets", "true", "false")),
	"keep_descendants": scalar(enumCheck("keep_descendants", "true", "false")),
	"harness":          scalar(enumCheck("harness", "auto", "claude-code", "codex", "generic", "none")),
	// The reason channel's own keys (ADR 0077).
	"reason": nullRefused(mapping(map[string]*field{
		"reads": scalar(enumCheck("reason reads", "auto", "on", "off")),
	}), "the reason channel's defaults", "write `reason: {}` for the defaults, or remove the key"),
	"ask": nullRefused(mapping(map[string]*field{
		"hold":        nullRefused(scalar(enumCheck("ask hold", "connect", "first_write", "request")), "default connect hold", "write the intended hold or remove the key"),
		"timeout":     nullRefused(scalar(checkAskTimeout), "default timeout", "write a positive duration or remove the key"),
		"max_pending": nullRefused(number(scalar(intRange("max_pending", 1, 64))), "default 64 pending requests", "write an integer 1..64 or remove the key"),
		"on_timeout":  nullRefused(scalar(enumCheck("ask on_timeout", "refuse", "refuse_always")), "default refuse", "write refuse or refuse_always, or remove the key"),
	}), "default approval configuration", "write ask: {} for defaults, or remove the key"),

	"gate": nullRefused(mapping(map[string]*field{
		"rules": nullRefused(seq(freeMap(checkGatePredicate, number(scalar(intRange("gate score", 0, 100))))), "no scored predicates", "write rules: [] or remove the key"),
		"thresholds": nullRefused(mapping(map[string]*field{
			// 1 <= allow < ask <= 100 (gate.New; ADR 0007): each key's own range here, the
			// pair's order at compile.
			"allow": nullRefused(number(scalar(intRange("gate allow threshold", 1, 99))), "default 50", "write an integer or remove the key"),
			"ask":   nullRefused(number(scalar(intRange("gate ask threshold", 2, 100))), "default 80", "write an integer or remove the key"),
		}), "default thresholds 50/80", "write thresholds: {} or remove the key"),
		"completion": nullRefused(scalar(enumCheck("gate completion", "copied", "held")), "default copied", "write copied or held, or remove the key"),
	}), "no gate", "write gate: {} or remove the key"),

	// Schema-only in P0 (R2).
	"prompt":     scalar(nil),
	"skills":     seq(scalar(nonEmpty("skill name"))),
	"visibility": seq(scalar(nonEmpty("visibility entry"))),
	"docker":     {kind: kindAny},
	"containers": scalar(enumCheck("containers", "none", "rootless")),
	// live: (ADR 0125). Compile checks the mode and each entry ([live-mode], [live-fence-entry]), so the message can
	// say what the fence takes.
	"live": nullRefused(mapping(map[string]*field{
		"mode": scalar(nonEmpty("live.mode")),
		"fence": nullRefused(mapping(map[string]*field{
			"read": seq(scalar(checkPath)),
			"net":  seq(scalar(nonEmpty("live.fence.net entry"))),
			"exec": seq(scalar(checkPath)),
		}), "no fence", "write `fence: {}` for an empty fence, or remove the key"),
	}), "live.mode: locked", "write `live: {mode: locked}`, or remove the key"),
})

func checkVersion(v string) (string, string) {
	if !intRE.MatchString(v) {
		return fmt.Sprintf("version must be an integer, got %q", v), "write version: 0"
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil && n == 0 && v != "0" {
		// `version: 00` and `version: -0` are version 0 written another way; saying version 00 is not
		// supported pointed at the version rather than at its spelling.
		return fmt.Sprintf("version is written %q; the version is spelled 0", v), "write version: 0"
	}
	if v != "0" {
		return fmt.Sprintf("version %s is not supported by this binary (v0 only)", v), "write version: 0"
	}
	return "", ""
}

func regexCheck(re *regexp.Regexp, msg string) checkFn {
	return func(v string) (string, string) {
		if !re.MatchString(v) {
			return fmt.Sprintf("%s, got %q", msg, v), ""
		}
		return "", ""
	}
}

func nonEmpty(what string) checkFn {
	return func(v string) (string, string) {
		if strings.TrimSpace(v) == "" {
			return what + " is empty", ""
		}
		if strings.ContainsRune(v, 0) {
			return what + " contains NUL", ""
		}
		return "", ""
	}
}

func checkProfileName(v string) (string, string) {
	if !profileRE.MatchString(v) {
		return fmt.Sprintf("extends %q is not a profile name (letters, digits, '.', '_', '-' and '/' segments; never an empty, '.' or '..' segment, never absolute; a revision pin @<n> on a tego/ name only)", v),
			"name a profile under the profiles directory, such as base/python-dev"
	}
	return "", ""
}

func checkPath(v string) (string, string) {
	if msg, fix := nonEmpty("path")(v); msg != "" {
		return msg, fix
	}
	if strings.ContainsRune(v, '\n') {
		return "path contains a newline", ""
	}
	// Only "~" and "~/" name the home directory (Compile's abs); "~root/x" was taken as a relative directory
	// literally named "~root" beneath the working directory, which is not what a shell makes of it.
	if strings.HasPrefix(v, "~") && v != "~" && !strings.HasPrefix(v, "~/") {
		user, _, _ := strings.Cut(v, "/")
		return fmt.Sprintf("path %q: %s is a ~user form, and only ~/ (your home directory) is expanded", v, user),
			"write ~/... for your home directory, the absolute path for another user's, or ./" + v + " for a directory named " + user
	}
	return "", ""
}

// checkExecEntry is an exec entry's shape: a one-word entry is a path or a name, checked as checkPath checks one; an
// entry with unquoted spaces is a command pattern, whose grammar validateExec checks with its row (ADR 0048 (1)).
func checkExecEntry(v string) (string, string) {
	if strings.TrimSpace(v) == "" {
		return checkPath(v)
	}
	if strings.ContainsAny(v, "\n\r") {
		return "exec entry contains a newline", "write each command as its own entry"
	}
	if !execmatch.IsPattern(v) {
		return checkPath(execmatch.Word(v))
	}
	return "", ""
}

func checkEndpoint(v string) (string, string) {
	if _, err := ParseEndpoint(v); err != nil {
		return err.Error(), "write host:port, tcp://host:port, udp://host:port, cidr:port, unix:/path or unix:@name"
	}
	return "", ""
}

func checkHost(v string) (string, string) {
	if e, err := ParseEndpoint(v + ":1"); err != nil || e.Kind != EndpointHost || e.Proto != ProtoInet {
		return fmt.Sprintf("host %q is not a host name or address", v), ""
	}
	return "", ""
}

func checkEnvName(v string) (string, string) {
	if !envNameRE.MatchString(v) {
		return fmt.Sprintf("environment variable name %q must match ^[A-Za-z_][A-Za-z0-9_]*$", v), ""
	}
	return "", ""
}

func checkEnvValue(v string) (string, string) {
	if strings.ContainsAny(v, "\x00\n") {
		return "environment value contains NUL or newline", ""
	}
	return "", ""
}

func intRange(what string, lo, hi int64) checkFn {
	return func(v string) (string, string) {
		if !intRE.MatchString(v) {
			return fmt.Sprintf("%s must be an integer, got %q", what, v), ""
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Sprintf("%s %s overflows int64", what, v), ""
		}
		if n < lo || n > hi {
			return fmt.Sprintf("%s must be between %d and %d, got %d", what, lo, hi, n), ""
		}
		return "", ""
	}
}

func checkCPU(v string) (string, string) {
	if _, err := ParseCPUCores(v); err != nil {
		return err.Error(), "write a cores count such as \"2.0\""
	}
	return "", ""
}

func checkByteSize(v string) (string, string) {
	b, err := ParseByteSize(v)
	if err != nil {
		if strings.HasPrefix(err.Error(), ErrDecimalUnit.Error()) {
			return err.Error(), "only IEC units are accepted: KiB, MiB, GiB, TiB"
		}
		return err.Error(), ""
	}
	if b <= 0 {
		return "size must be greater than zero", ""
	}
	return "", ""
}

func checkNetworkByteSize(v string) (string, string) {
	if _, err := ParseByteSize(v); err != nil {
		return err.Error(), "write a nonnegative IEC byte count"
	}
	return "", ""
}

func checkNonnegativeDuration(v string) (string, string) {
	if _, err := ParseDuration(v); err != nil {
		return err.Error(), "write a nonnegative duration"
	}
	return "", ""
}

func checkDuration(v string) (string, string) {
	d, err := ParseDuration(v)
	if err != nil {
		return err.Error(), ""
	}
	if d <= 0 {
		return "duration must be greater than zero", ""
	}
	return "", ""
}

func checkCost(v string) (string, string) {
	// One decimal grammar is shared with machine limits; ParseFloat also accepts
	// hex floats and underscores, which the configuration surface does not.
	if !config.IsDecimal(v) {
		return fmt.Sprintf("cost_usd must be a decimal number, got %q", v), "write a dollar amount such as 5 or 0.50"
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fmt.Sprintf("cost_usd %s is out of range", v), "write a dollar amount such as 5 or 0.50"
	}
	if f < 0 || strings.HasPrefix(v, "-") { // "-0" is a negative spelling of 0
		return "cost_usd must not be negative", ""
	}
	// A nonzero amount too small for a float64 reads as 0, a budget that trips on the first cent: 1e-400 is
	// not 0, and is refused rather than read as it.
	if config.Underflows(v, f) {
		return fmt.Sprintf("cost_usd %s is too small to represent and would read as 0", v), "write 0 for no spend, or a dollar amount such as 0.01"
	}
	return "", ""
}

func enumCheck(what string, allowed ...string) checkFn {
	return func(v string) (string, string) {
		for _, a := range allowed {
			if v == a {
				return "", ""
			}
		}
		return fmt.Sprintf("%s must be one of %s, got %q", what, strings.Join(allowed, "|"), v), ""
	}
}

// walker validates one YAML document against the schema tree, records the
// position of every value and reports every shape error with line and column.
type walker struct {
	file    string
	ds      *diags
	origins origins
	// nulls is where each nullDeferred key had a null value, by path.
	nulls map[string]Pos
}

const maxAliasDepth = 32

// walk validates n against f at path. Null values are treated as absent, except for a key whose
// null value is refused (nullRefused).
func (w *walker) walk(n *yaml.Node, f *field, path string) {
	n = w.deref(n, path)
	if n != nil && isNull(n) && f.nullFix != "" {
		as := "an empty section"
		switch f.kind {
		case kindSeq:
			as = "an empty list"
		case kindScalar, kindOneOrSeq:
			as = "a value"
		}
		w.ds.errorf(Pos{File: w.file, Line: n.Line, Col: n.Column}, CodeSchema,
			"%s: has no value and reads as if absent (%s), not as %s", path, f.nullMeans, as).fix("%s", f.nullFix)
		return
	}
	if n != nil && isNull(n) && f.nullDeferred {
		if w.nulls == nil {
			w.nulls = map[string]Pos{}
		}
		w.nulls[path] = Pos{File: w.file, Line: n.Line, Col: n.Column}
		return
	}
	if n == nil || isNull(n) {
		return
	}
	pos := Pos{File: w.file, Line: n.Line, Col: n.Column}
	w.origins[path] = pos
	// An explicit tag changes what the typed decode makes of the text this walk checks: `!!binary` is
	// base64-decoded after the walk accepted the encoded text, so a name, a tier or an env value could be any
	// bytes. A contract needs no tag, so none is accepted.
	if n.Style&yaml.TaggedStyle != 0 {
		w.ds.errorf(pos, CodeSchema, "%s: explicit YAML tag %s is not accepted in a contract", path, n.Tag).
			fix("remove the tag; quote the value if it should be a string")
		return
	}
	switch f.kind {
	case kindAny:
	case kindScalar:
		if n.Kind != yaml.ScalarNode {
			w.ds.errorf(pos, CodeSchema, "%s must be a single value, got %s", path, describe(n))
			return
		}
		if f.numeric && n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) != 0 {
			fix := "write the number without quotes"
			if f.check == nil || func() bool { msg, _ := f.check(n.Value); return msg == "" }() {
				fix = fmt.Sprintf("write %s: %s, without quotes", lastSegment(path), n.Value)
			}
			w.ds.errorf(pos, CodeSchema, "%s must be a number, got the quoted string %q", path, n.Value).fix("%s", fix)
			return
		}
		var msg, fix string
		if f.check != nil {
			msg, fix = f.check(n.Value)
		}
		if msg != "" {
			w.ds.errorf(pos, CodeSchema, "%s: %s", path, msg).fix("%s", fix)
		} else if f.textual && n.ShortTag() != "!!str" {
			w.ds.errorf(pos, CodeSchema, "%s must be a string, got %s", path, describe(n)).
				fix("quote it: %s: %q", lastSegment(path), n.Value)
		}
	case kindSeq:
		if n.Kind != yaml.SequenceNode {
			w.ds.errorf(pos, CodeSchema, "%s must be a list, got %s", path, describe(n)).fix("write %s: [...]", lastSegment(path))
			return
		}
		for i, c := range n.Content {
			elem := path + "." + strconv.Itoa(i)
			// A null element (a bare "-" or an unquoted "~") is dropped by the typed decode, so a list that
			// reads as holding an entry would compile without it: `deny_read: [~]` became `deny_read: []`,
			// which turns the built-in credential denies off, and `command: [~, x]` ran x. It is an error.
			if d := w.deref(c, elem); d != nil && isNull(d) {
				w.ds.errorf(Pos{File: w.file, Line: c.Line, Col: c.Column}, CodeSchema,
					"%s: empty entry", elem).fix(`write "~" in quotes for the home directory, or remove the entry`)
				continue
			}
			w.walk(c, f.elem, elem)
		}
	case kindMap, kindMapFree:
		if n.Kind != yaml.MappingNode {
			w.ds.errorf(pos, CodeSchema, "%s must be a mapping, got %s", path, describe(n))
			return
		}
		w.walkMapping(n, f, path)
	case kindOneOrSeq:
		w.walkOneOrSeq(n, f, path, pos)
	}
}

// walkOneOrSeq holds a one-or-list key: a single value is walked as its element, a list as a list of 1 to
// f.maxItems of them.
func (w *walker) walkOneOrSeq(n *yaml.Node, f *field, path string, pos Pos) {
	switch {
	case n.Kind == yaml.ScalarNode:
		w.walk(n, f.elem, path)
		return
	case n.Kind != yaml.SequenceNode:
		w.ds.errorf(pos, CodeSchema, "%s must be one value or a list of 1 to %d, got %s", path, f.maxItems, describe(n))
		return
	case len(n.Content) == 0:
		w.ds.errorf(pos, CodeSchema, "%s: [] names nothing, and reads as if absent", path).
			fix("name at least one, or remove the key")
		return
	case len(n.Content) > f.maxItems:
		w.ds.errorf(pos, CodeSchema, "%s lists %d entries; at most %d are accepted", path, len(n.Content), f.maxItems).
			fix("list at most %d, or combine some into one", f.maxItems)
		return
	}
	w.walk(n, seq(f.elem), path)
}

func (w *walker) walkMapping(n *yaml.Node, f *field, path string) {
	seen := map[string]Pos{}
	defer func() {
		// A key with a null value is absent (walk records no origin for it).
		for _, req := range f.required {
			if _, ok := w.origins[childPath(path, req)]; !ok {
				w.ds.errorf(Pos{File: w.file, Line: n.Line, Col: n.Column}, CodeSchema, "%s: %s is required", path, req)
			}
		}
	}()
	for i := 0; i+1 < len(n.Content); i += 2 {
		kn, vn := n.Content[i], n.Content[i+1]
		kpos := Pos{File: w.file, Line: kn.Line, Col: kn.Column}
		if kn.Kind != yaml.ScalarNode {
			w.ds.errorf(kpos, CodeSchema, "%s: mapping key must be a plain scalar", path)
			continue
		}
		key := kn.Value
		if prev, dup := seen[key]; dup {
			w.ds.errorf(kpos, CodeSchema, "key %q already defined at line %d", key, prev.Line).fix("keep one %s:", key)
			continue
		}
		seen[key] = kpos
		child := childPath(path, key)
		switch f.kind {
		case kindMapFree:
			if msg, fix := f.keyCheck(key); msg != "" {
				w.ds.errorf(kpos, CodeSchema, "%s: %s", path, msg).fix("%s", fix)
				continue
			}
			// A null value under a free map is not absent: the typed decode keeps the key with its zero value,
			// so `set: {PATH: }` (a value left out or commented out) set PATH to "" with no diagnostic and no
			// origin for a later one to point at. It is an error, as a null list entry is.
			if d := w.deref(vn, child); d != nil && isNull(d) {
				w.ds.errorf(Pos{File: w.file, Line: vn.Line, Col: vn.Column}, CodeSchema,
					"%s: has no value, which reads as the empty string", child).
					fix(`write "" for an empty value, or remove the key`)
				continue
			}
			w.walk(vn, f.elem, child)
		default:
			sub, ok := f.fields[key]
			if !ok {
				where := "the top level"
				if path != "" {
					where = path
				}
				w.ds.errorf(kpos, CodeSchema, "unknown field %q in %s", key, where).fix("%s", suggest(key, f.fields))
				continue
			}
			w.walk(vn, sub, child)
		}
	}
}

func childPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// deref follows alias nodes, bounded so an alias loop cannot recurse forever.
func (w *walker) deref(n *yaml.Node, path string) *yaml.Node {
	for depth := 0; n != nil && n.Kind == yaml.AliasNode; depth++ {
		if depth >= maxAliasDepth || n.Alias == nil {
			w.ds.errorf(Pos{File: w.file, Line: n.Line, Col: n.Column}, CodeSchema, "%s: alias chain too deep", path)
			return nil
		}
		n = n.Alias
	}
	return n
}

func isNull(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null"
}

// describe names a node's shape for a message: `string "x"`, `list`, `mapping`.
func describe(n *yaml.Node) string {
	switch n.Kind {
	case yaml.ScalarNode:
		v := n.Value
		if len(v) > 40 {
			v = v[:37] + "..."
		}
		return fmt.Sprintf("%s %q", tagName(n.ShortTag()), v)
	case yaml.SequenceNode:
		return "a list"
	case yaml.MappingNode:
		return "a mapping"
	}
	return "an unsupported node"
}

// tagName spells a YAML core tag for a message.
func tagName(tag string) string {
	switch tag {
	case "!!str":
		return "string"
	case "!!int":
		return "integer"
	case "!!float":
		return "number"
	case "!!bool":
		return "boolean"
	case "!!null":
		return "null"
	}
	return strings.TrimPrefix(tag, "!!")
}

func lastSegment(path string) string {
	if i := strings.LastIndexByte(path, '.'); i >= 0 {
		return path[i+1:]
	}
	return path
}

// suggest names the closest known field (edit distance <= 3), else lists them.
func suggest(key string, fields map[string]*field) string {
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	sort.Strings(names)
	best, bestDist := "", 4
	for _, k := range names {
		if d := editDistance(key, k); d < bestDist {
			best, bestDist = k, d
		}
	}
	if best != "" {
		return fmt.Sprintf("did you mean %q?", best)
	}
	return "known fields: " + strings.Join(names, ", ")
}

// editDistance is the Levenshtein distance, small inputs only.
func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}
