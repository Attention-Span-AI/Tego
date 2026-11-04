// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/internal/runtime/dnsbroker"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const (
	dnsBrokerDirEnv = "TEGO_DNS_BROKER_DIR"
	dnsBrokerPIDEnv = "TEGO_DNS_BROKER_PID"
)

// setupDNSBroker binds before Prepare so every backend receives the same exact
// owned Unix endpoint. The table is cloned; neither the contract nor a caller's
// compiled grants gain access to the private ledger directory.
func (r *runner) setupDNSBroker() error {
	if r.rt.DNS.Mode != "broker" {
		return nil
	}
	if r.rt.DNSQueries == nil || r.rt.DNS.Cache == nil {
		return fmt.Errorf("%w: broker DNS requires compiled query settings", dnsbroker.ErrUnavailable)
	}
	uid := os.Geteuid()
	if uid == 0 {
		var err error
		uid, _, err = dropTarget()
		if err != nil {
			return err
		}
	}
	m := r.deps.Config
	if m == nil {
		return fmt.Errorf("%w: DNS broker requires machine resolver configuration", ErrDeps)
	}
	upstreams := dns.MachineResolvers(m.Resolver.Value.Auto, m.Resolver.Value.Servers)
	dir, err := newDNSDirectory()
	if err != nil {
		return fmt.Errorf("runtime: DNS socket directory: %w", err)
	}
	b, err := dnsbroker.New(dir.path, dnsbroker.Options{RelayPID: os.Getpid(),
		UID: uint32(uid), Policy: r.rt.DNSQueries, Upstreams: upstreams,
		MaxParallel: r.rt.DNS.MaxParallel, Cache: *r.rt.DNS.Cache,
		Authorize: r.dnsPeerAuthorize, Emit: r.emitDNS,
	})
	if err != nil {
		_ = dir.Close()
		return fmt.Errorf("runtime: DNS broker: %w", err)
	}
	if err = dir.captureSocket(); err != nil {
		_ = b.Close()
		_ = dir.Close()
		return fmt.Errorf("runtime: hold DNS socket identity: %w", err)
	}
	r.dnsBroker, r.dnsDirectory = b, dir
	out := *r.rt
	out.Net = append(slices.Clone(r.rt.Net), agent.NetRule{
		Raw: "unix:" + b.Endpoint(), Proto: agent.ProtoUnix,
		UnixPath: b.Endpoint(), Static: true, Verdict: agent.VerdictAllow,
		Runtime: agent.DNSBrokerGrant,
	})
	r.rt = &out
	return nil
}

func (r *runner) dnsPeerAuthorize(peer dnsbroker.Peer) error {
	// Binding the endpoint during prepare does not authorize a stage or an
	// outside process to write before run_start has landed.
	select {
	case <-r.started:
	default:
		return dnsbroker.ErrUnauthorized
	}
	_, run := splitCgroupPath(r.cg.Path)
	task, err := unifiedAskCgroup(peer.PID)
	if err != nil {
		return err
	}
	if !inAskCgroup(run, task) {
		return dnsbroker.ErrUnauthorized
	}
	return nil
}

func (r *runner) startDNSBroker(ctx context.Context) error {
	if r.dnsBroker == nil {
		return nil
	}
	if !r.dnsBroker.Available() {
		return dnsbroker.ErrUnavailable
	}
	r.group.Go("dns-broker", func() error { return r.dnsBroker.Run(ctx) })
	r.dnsBrokerStarted = true
	return nil
}

// dnsBrokerReady is evidence about this run's cooperating transport, not a
// promise that glibc or arbitrary applications consult an environment override.
func (r *runner) dnsBrokerReady() bool {
	return r != nil && r.dnsBroker != nil && r.dnsBrokerStarted && r.dnsBroker.Available()
}

func (r *runner) stopDNSBroker() {
	if r.reapHandoff != nil { // a run unwound before startReaper: its reaper gets no target
		_ = r.reapHandoff.Close()
		r.reapHandoff = nil
	}
	if r.dnsBroker != nil {
		if err := r.dnsBroker.Close(); err != nil {
			r.log.Error("run: DNS broker cleanup", "err", err)
			r.noteDetail(err.Error())
		}
	}
	if r.dnsDirectory != nil {
		if err := r.dnsDirectory.Close(); err != nil {
			r.log.Error("run: DNS socket directory cleanup", "err", err)
			r.noteDetail(err.Error())
		}
	}
}

// dnsBrokerEnv runs after env.pass/deny/set. A contract or inherited environment
// cannot point a cooperating client at another run; disabled brokers remove the
// reserved variables entirely. This is an explicit client protocol, not libc DNS.
func (r *runner) dnsBrokerEnv(env []string) []string {
	out := make([]string, 0, len(env)+2)
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		if name != dnsBrokerDirEnv && name != dnsBrokerPIDEnv {
			out = append(out, entry)
		}
	}
	if r.dnsBroker != nil {
		out = append(out, dnsBrokerDirEnv+"="+filepath.Dir(r.dnsBroker.Endpoint()), dnsBrokerPIDEnv+"="+strconv.Itoa(os.Getpid()))
	}
	return out
}

type dnsPayload struct {
	record.NetPayload
	DNSName   string `json:"dns_name"`
	DNSType   uint16 `json:"dns_type"`
	DNSPhase  string `json:"dns_phase"`
	DNSCached bool   `json:"dns_cached,omitempty"`
	DNSError  string `json:"dns_error,omitempty"`
}

func (r *runner) emitDNS(e dnsbroker.Event) error {
	if r.writer == nil || r.dnsBroker == nil {
		return dnsbroker.ErrUnavailable
	}
	// record: off keeps policy refusals. Allowed decision/completion metadata
	// remains optional telemetry; it does not create an unrecorded policy grant.
	if r.rt.Record == agent.RecordOff && e.Allowed {
		return nil
	}
	ev := &record.Event{
		V: record.Version, TS: r.deps.Clock.Now(), MonoNS: r.deps.Clock.MonoNS(),
		PID: e.Peer.PID, Cgroup: r.cg.ID,
		Kind: record.KindNet, Source: record.SourceSupervisor, Rule: e.Rule, Verdict: record.VerdictAllow,
		Authority: record.AuthorityRule, Attr: record.Unattributed(),
	}
	if !e.Allowed {
		ev.Verdict, ev.Reason = record.VerdictRefused, record.ReasonNetNotAllowed
	}
	op := "dns_query"
	if e.Phase == dnsbroker.PhaseCompletion {
		op = "dns_response"
	}
	if err := ev.SetPayload(dnsPayload{
		NetPayload: record.NetPayload{Op: op, Proto: agent.ProtoUnix, Dst: "unix:" + r.dnsBroker.Endpoint(), Mechanism: "dns-broker"},
		DNSName:    e.Name, DNSType: e.Type, DNSPhase: e.Phase, DNSCached: e.Cached, DNSError: e.Error,
	}); err != nil {
		return err
	}
	// Serialize the decision before upstream dispatch. A failed completion
	// write ends the run and withholds the response, but cannot retract a query.
	events := []*record.Event{ev}
	if !e.Allowed {
		mirror := *ev
		mirror.Kind, mirror.Verdict, mirror.Authority, mirror.Attr = record.KindRefused, "", "", nil
		mirror.Payload = refusedPayload(ev)
		events = append(events, &mirror)
	}
	prepare := r.writer.RedactStage(r.writer.SplitBlobsStage(func(*record.Event) error { return nil }))
	for _, event := range events {
		if err := prepare(event); err != nil {
			r.ledgerFailed(err)
			return err
		}
	}
	if err := r.writer.AppendBatch(events...); err != nil {
		r.ledgerFailed(err)
		return err
	}
	if r.budget != nil {
		r.budget.Touch(r.deps.Clock.MonoNS())
	}
	return nil
}
