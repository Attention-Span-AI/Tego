// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/capture"
	"github.com/attention-span-ai/tego/internal/runtime/capture/forwarder"
	"github.com/attention-span-ai/tego/internal/runtime/capture/uprobe"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// selectCapture is `run`'s half of docs/p0/capture-derive.md §4: it supplies the mechanisms this binary
// carries and lets capture.Select decide which of them the compiled contract and the selected tier want.
// It never fails the run — an unavailable mechanism is a gap on the ledger, not an error (§4) — so it
// returns the sources to start and the gaps the choice already implies, both of which go into
// runtime.Deps.
//
// It runs here, before runtime.Run, because the forwarder binds its listeners at construction: the base
// URLs have to exist before the agent execs, and the ports have to be admitted by the enforcement tier
// the run prepares (§3, R38).
func selectCapture(rt *agent.RuleTable, m *config.Machine, b enforce.Backend) ([]source.Source, []source.Gap) {
	return capture.Select(rt, b.Tier(), b.Capabilities(), capture.Deps{
		Uprobe:    uprobeFactory(rt, m),
		Forwarder: forwarderFactory(rt, m),
	})
}

// warnForwarderEnv prints env-runtime-reserved on stderr for each variable the contract passes or sets that
// this run's forwarder overrides, where Compile did not warn. compiled is the capture Compile resolved, read
// before the run's tier could lower it (agent.RuleTable.AtTier).
//
// A contract that pins capture: uprobe keeps its ANTHROPIC_BASE_URL at Compile when Compile resolved capture to
// uprobe (agent.RuleTable.PinsUprobe), which is right wherever the run captures with uprobes: no forwarder runs
// there. Compile resolves an unpinned tier to the machine's ceiling without probing it, though, and the run's
// tier can then be one that runs no uprobes (landlock, which is every unprivileged run), or the run can be
// --observe, or its tier's capability set can lack model capture. There a pinned uprobe tops out at the
// forwarder (agent.AtTier, capture.Select), and identity.Env.Apply writes the forwarder's base URL over the
// contract's value (RUN-IDENTITY R7), so the agent's model traffic goes through the forwarder to models[]
// instead of to the endpoint the variable named, a gateway for one. It used to happen with nothing said
// (agent-contract R12). The reason given is the one that lowered capture here, since each has its own fix.
//
// Nothing is said when Compile resolved anything but uprobe: it lowered a pinned uprobe to the forwarder itself
// (a contract that pins tier: landlock, or a machine capture or tier ceiling) and has printed
// env-runtime-reserved for these names already, and under every unpinned mode it said that the forwarder owns
// them wherever it can run. Saying it again here gave a second line for env.set, and for a machine capture
// ceiling a reason and a fix naming the tier, which changed nothing.
func warnForwarderEnv(w io.Writer, rt *agent.RuleTable, compiled agent.CaptureMode, tier backend.Tier, sources []source.Source) {
	if rt == nil || !rt.PinsUprobe() || compiled != agent.CaptureUprobe {
		return
	}
	owned := map[string]bool{}
	for _, s := range sources {
		if ls, ok := s.(source.LoopbackSource); ok {
			for name := range ls.Vars() {
				owned[name] = true
			}
		}
	}
	if len(owned) == 0 {
		return
	}
	why := fmt.Sprintf("capture: uprobe does not run at tier %s", tier)
	fix := "run at tier cgroup or above to keep %[1]s, or set capture: forwarder and remove it"
	switch {
	case tier == backend.TierObserve:
		why = "capture: uprobe does not run under --observe, which records through tier 1"
		fix = "drop --observe and run at tier cgroup or above to keep %[1]s, or set capture: forwarder and remove it"
	case backend.TierCgroup.AtOrBelow(tier):
		why = fmt.Sprintf("capture: uprobe cannot run at tier %s on this machine, whose tier reports no model capture", tier)
		fix = "run where `tego doctor` reports capture.model_traffic at tier cgroup to keep %[1]s, or set " +
			"capture: forwarder and remove it"
	}
	var ds []agent.Diagnostic
	warn := func(verb, name string) {
		ds = append(ds, agent.Diagnostic{
			File: rt.ContractPath, Severity: agent.SeverityWarning, Code: agent.CodeEnvRuntimeReserved,
			Message: fmt.Sprintf("env.%s %s is set by the capture forwarder on this run and the contract's value is "+
				"overridden: %s, so the forwarder captures instead", verb, name, why),
			Fix: fmt.Sprintf(fix, name),
		})
	}
	for _, name := range rt.Env {
		if owned[name] {
			warn("pass", name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(rt.Set)) {
		if owned[name] {
			warn("set", name)
		}
	}
	_ = agent.WriteDiagnostics(w, ds)
}

// uprobeFactory builds the run's OpenSSL capture source, or nil when this binary carries no compiled capture
// object — every build without `-tags tegobpf` — and then Select records gap what=capture
// why=mechanism-unavailable binary=uprobe: this build cannot run uprobes, and the ledger says so instead of
// staying silent (§4, R37, I4). Select asks for it only at tier cgroup or above.
//
// The source is built in Kernel mode and opens nothing here. Nothing of the build is pinned until the tier-2
// backend has prepared the run, so the run itself hands the source the build its handle pinned and the
// kernel record's exec, open and exit stream (source.KernelFollower), and the source's Start loads the
// capture object under those pins. A source that cannot load then is one mechanism-unavailable gap, never a
// failed run.
func uprobeFactory(rt *agent.RuleTable, m *config.Machine) capture.Factory {
	if !bpf.Available() {
		return nil
	}
	var (
		models  []agent.ModelEndpoint
		servers []agent.MCPServer
	)
	if rt.Contract != nil {
		models, servers = rt.Contract.Models, rt.Contract.MCP
	}
	return func() (capture.Source, error) {
		return uprobe.New(uprobe.Options{
			// models[] name the endpoint an ssl_request is attributed to; record decides bodies.
			Rules:  rt,
			Kernel: true,
			// The same dispatch the forwarder runs (R25), so an exchange derives alike whichever mechanism
			// captured it: the ssl_response carries the model, the usage `limits` counts and the
			// parser_version, and its decisions follow it. The uprobes see every TLS peer of the run, so they
			// alone also read the declared HTTP MCP servers' exchanges for their tool calls (capture-derive.md R41).
			Deriver: derive.NewDispatcher(linkedParsers(models), derive.WithMCP(servers), derive.WithLogger(ownLogger(m))),
			// Bodies go to the run's own content-addressed store (record-ledger R11), which exists
			// only once the run directory does.
			OpenBlobs: uprobeBlobs,
			Logger:    ownLogger(m),
		})
	}
}

// uprobeBlobs is the body store a uprobe source writes through: its own handle on the run's blob directory,
// beside the ledger writer's. The writer's Close syncs only the store it wrote through itself before it syncs
// events.jsonl (record-ledger R6), so this one must be a store the source's Stop can sync, which runs before
// run_end is written; ledger's blob store is (it has Sync), and uprobe.Stop syncs whatever store has one.
func uprobeBlobs(run source.RunRef) uprobe.BlobStore {
	if run.BlobBytes == nil {
		return ledger.NewBlobRepository(run.Dir)
	}
	return ledger.NewCountedBlobRepository(run.Dir, run.BlobBytes)
}

// forwarderFactory builds the run's loopback forwarder over the contract's declared models[], or nil when
// the contract declared none — there is then nothing for a listener to be bound to. Select checks models[]
// itself before it looks at the factory and records gap why=no-models binary=forwarder (R37), rather than
// starting a source that could never see a request.
//
// The compiled table keeps the merged contract for exactly this kind of consumer (agent.RuleTable.Contract):
// models[] is a declaration about the world, not a rule, so Compile does not lower it.
func forwarderFactory(rt *agent.RuleTable, m *config.Machine) capture.Factory {
	models := rt.Contract.Models
	if len(models) == 0 {
		return nil
	}
	var creds forwarder.KeyLayer
	if credentialLayer != nil {
		creds = credentialLayer(rt, m)
	}
	return func() (capture.Source, error) {
		return forwarder.NewManager(models, forwarder.Options{
			Credentials:    creds,
			HTTPPolicy:     rt.HTTP,
			Proxy:          rt.Proxy,
			DeniedResolved: rt.DeniedResolved,
			// forwarder.listen is the machine's, not the contract's (spec/config/v0). The
			// default is 127.0.0.1:0, which is what R19 asks for and what a listener would
			// have chosen anyway. An operator who pins a port and declares more than one
			// model gets the pinned port for the first entry and an ephemeral port on the
			// same host for each later one (NewManager, capture-derive R19), with a warning.
			Listen: m.Forwarder.Listen.Value,
			// Dispatch is by the declared provider and the upstream host, never by sniffing
			// the body. The declared hosts join the parser's own so a models[] entry pointing at
			// some other Anthropic-compatible host still reaches it.
			Deriver: derive.NewDispatcher(linkedParsers(models), derive.WithLogger(ownLogger(m))),
			// record: full is the only mode that keeps bodies; summary and off keep the sizes and
			// the derived facts alone (SEMANTICS §7).
			Bodies: rt.Record == agent.RecordFull,
			// The Clock is left at its default deliberately: it is the same system clock the runner
			// falls back to, so one run's events carry one monotonic origin. The logger is tego's
			// own log, the one the runner itself is given (Deps.Logger), never the agent's stderr,
			// which `run` hands to the child untouched.
			Logger: ownLogger(m),
		})
	}
}

// credentialLayer is nil: Compile has refused a contract with credentials: before any forwarder is built (agent's
// credentialsAndRelayTier).
var credentialLayer func(rt *agent.RuleTable, m *config.Machine) forwarder.KeyLayer

// hostsFor is the declared hosts of one provider, so a parser can claim them by host as well as by name.
func hostsFor(models []agent.ModelEndpoint, provider string) []string {
	var out []string
	for _, m := range models {
		if strings.EqualFold(strings.TrimSpace(m.Provider), provider) && m.Host != "" {
			out = append(out, m.Host)
		}
	}
	return out
}

// linkedParsers is the one list of response-body parsers this build carries: what the forwarder's and the
// uprobe source's dispatchers run, and what `tego version` and run_start.parsers report (R30, VERSIONING.md §2).
// Both readings come from here, so the binary can never claim a parser it does not link or hide one
// it does. hosts are the contract's declared endpoints for a parser that claims hosts (R25).
func linkedParsers(models []agent.ModelEndpoint) []derive.Parser {
	return []derive.Parser{anthropic.New(hostsFor(models, anthropic.Provider)...)}
}

// parserNames is linkedParsers' providers, the form `version` prints and run_start records
// (spec/record/v1: parsers is keyed by provider name).
func parserNames() []string {
	ps := linkedParsers(nil)
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Provider())
	}
	return out
}
