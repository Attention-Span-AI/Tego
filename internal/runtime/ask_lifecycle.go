// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/askclient"
	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/internal/platform/peer"
	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// askSource configures cooperating request-aware sources before they start.
// A source must bind the immutable table and authenticate the actual request
// peer; an opaque TLS transport cannot implement this interface honestly.
type askSource interface {
	ConfigureAsk(*agent.RuleTable, func(context.Context, ask.Request) (ask.Decision, error)) error
}

func validateAskRequest(rt *agent.RuleTable, deps Deps) error {
	declared := rt.Contract != nil && (rt.Contract.FS != nil && (len(rt.Contract.FS.Ask) > 0 || len(rt.Contract.FS.AskRead) > 0) || rt.Contract.Net != nil && len(rt.Contract.Net.Ask) > 0) || rt.HasAskRead()
	if rt.AskConfig == nil {
		if declared {
			return fmt.Errorf("%w: ask scopes lack compiled configuration", ask.ErrUnavailable)
		}
		return nil
	}
	cfg := rt.AskConfig
	// Only tier 1's supervisor holds a read (POC 2026-10-06): a table that would land elsewhere, compile refuses
	// already; one that reached here anyway (an --observe run, a hand-built table, a backend chosen after the
	// compile) does not run with its asks turned into plain refusals, nor into reads nothing holds. Asked first, so
	// the refusal names what refused it.
	if rt.HasAskRead() && deps.Enforce.Tier() != backend.TierLandlock {
		return fmt.Errorf("%w: fs.ask_read holds reads at tier landlock only, and this run is at tier %s", ask.ErrUnavailable, deps.Enforce.Tier())
	}
	if deps.Enforce.Tier() == backend.TierObserve || rt.Contract.IOUring || rt.Contract.Setuid {
		return fmt.Errorf("%w: ask requires enforcement with io_uring and setuid disabled", ask.ErrUnavailable)
	}
	if cfg.MaxPending < 1 || cfg.MaxPending > ask.DefaultMaxPending || time.Duration(cfg.Timeout) <= 0 || time.Duration(cfg.Timeout) > time.Hour {
		return fmt.Errorf("%w: invalid ask bounds", ask.ErrUnavailable)
	}
	if len(rt.FSAsk) > 256 || len(rt.NetAsk) > 256 {
		return fmt.Errorf("%w: too many ask scopes", ask.ErrUnavailable)
	}
	for _, rule := range rt.FSAsk {
		if len(rule.Governed()) > 4096 || len(rule.Governed()) == 0 {
			return fmt.Errorf("%w: invalid fs ask scope", ask.ErrUnavailable)
		}
	}
	for _, rule := range rt.NetAsk {
		switch {
		case rule.Proto == agent.ProtoUnix && rule.UnixPath != "":
			// Held at the connect and relayed as the task once approved (supervisor R11): no other hold carries one.
			if cfg.Hold != agent.AskHoldConnect {
				return fmt.Errorf("%w: unix ask destinations are held at the connect, not by ask.hold %s", ask.ErrUnavailable, cfg.Hold)
			}
		case rule.Port <= 0 || rule.Proto != agent.ProtoTCP && rule.Proto != agent.ProtoUDP && rule.Proto != agent.ProtoInet:
			return fmt.Errorf("%w: only TCP, UDP or unix ask destinations with a port are supported", ask.ErrUnavailable)
		case rule.Proto != agent.ProtoTCP && cfg.Hold != agent.AskHoldConnect:
			// A udp:// or bare host:port entry names UDP, whose datagram or connect is held at the syscall and relayed
			// once approved (supervisor R13d): no other hold carries one.
			return fmt.Errorf("%w: UDP ask destinations are held at the datagram or connect, not by ask.hold %s", ask.ErrUnavailable, cfg.Hold)
		}
	}
	switch cfg.Hold {
	case agent.AskHoldConnect, agent.AskHoldFirstWrite:
	case agent.AskHoldRequest:
		if len(rt.NetAsk) > 0 && (rt.Capture != agent.CaptureForwarder || rt.HTTP == nil || rt.Contract == nil || len(rt.Contract.Models) == 0) {
			return fmt.Errorf("%w: request holds require authenticated forwarder HTTP policy", ask.ErrUnavailable)
		}
	default:
		return fmt.Errorf("%w: unsupported ask hold", ask.ErrUnavailable)
	}
	return nil
}

// unifiedAskCgroup is pid's unified cgroup, read from /proc by the one strict reader (runscope.Unified); its caller
// takes any error as unauthorized.
func unifiedAskCgroup(pid int) (string, error) {
	if pid <= 0 {
		return "", ask.ErrUnauthorized
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return "", err
	}
	return runscope.Unified(b)
}

func inAskCgroup(run, task string) bool {
	return run != "" && run != "/" && (task == run || strings.HasPrefix(task, strings.TrimSuffix(run, "/")+"/"))
}

// askPeerAuthorize is whom ask.sock serves (ADR 0008, amended 2026-10-25; ADR 0100 (7)): the person, never an
// agent. The broker has taken the uid first (the invoking user's or root's), and the socket read p's cgroup and
// cgroup namespace by peer.Identify, at the connect and again at the packet. Unauthorized, with every ask left
// pending: a peer in this run's cgroup or below it, and every peer peer.Refuse refuses, which is one inside any
// run's or adoption's scope or a look-alike of one ([run-member]), one in another or an unreadable cgroup namespace
// or above this one's root, and every peer while this process is outside the initial cgroup namespace
// ([peer-cgroupns]), where a run's scope above that root could not show.
func (r *runner) askPeerAuthorize(p ask.Peer) error {
	_, run := splitCgroupPath(r.cg.Path)
	if run == "" || run == "/" || inAskCgroup(run, p.Cgroup) {
		return ask.ErrUnauthorized
	}
	owner := int(r.askOwner)
	if p.UID == 0 {
		owner = 0 // root is served beside the run's owner (ask.Broker's uid rule)
	}
	return peer.Refuse(peer.Peer{UID: int(p.UID), PID: p.PID, Cgroup: p.Cgroup, CgroupNS: p.CgroupNS}, owner)
}

func (r *runner) askRequest(ctx context.Context, req ask.Request) (ask.Decision, error) {
	if r.askBroker == nil {
		return ask.Decision{Reason: ask.ReasonUnavailable}, ask.ErrUnavailable
	}
	_, run := splitCgroupPath(r.cg.Path)
	ids := []int{req.PID, req.TID}
	if req.Hold == "first_write" {
		// A relay asks at the first delivery, after the connect returned, and
		// authenticated its peer by the held socket: the connecting thread
		// need not outlive its connect, so only its process is re-checked.
		ids = ids[:1]
	}
	for _, pid := range ids {
		cg, err := unifiedAskCgroup(pid)
		if err != nil || !inAskCgroup(run, cg) {
			return ask.Decision{Reason: ask.ReasonUnavailable}, ask.ErrUnauthorized
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if r.askCtx != nil {
		stop := context.AfterFunc(r.askCtx, cancel)
		defer stop()
	}
	return r.askBroker.Request(ctx, req)
}

func (r *runner) emitAsk(e ask.Event) error {
	if r.writer == nil {
		return ask.ErrUnavailable
	}
	ev := &record.Event{V: record.Version, TS: r.deps.Clock.Now(), MonoNS: r.deps.Clock.MonoNS(), PID: e.Request.PID, TID: e.Request.TID, Cgroup: r.cg.ID, Source: record.SourceSupervisor}
	if e.Kind == "ask" {
		ev.Kind = record.KindAsk
		if err := ev.SetPayload(struct {
			record.AskPayload
			Op       string `json:"op"`
			Target   string `json:"target"`
			Target2  string `json:"target2,omitempty"` // a held mutation's second name (ADR 0047, record_minor 28)
			AskRule  string `json:"ask_rule"`
			Score    *int   `json:"score,omitempty"`
			GateRule string `json:"gate_rule,omitempty"`
		}{record.AskPayload{AskID: e.Request.AskID, Hold: e.Request.Hold}, e.Request.Op, askclient.LedgerTarget(e.Request.Op, e.Request.Target), e.Request.Target2, e.Request.Rule, e.Request.Score, e.Request.GateRule}); err != nil {
			return err
		}
	} else {
		ev.Kind = record.KindAnswer
		if err := ev.SetPayload(struct {
			record.AnswerPayload
			Approved     bool   `json:"approved"`
			Op           string `json:"op"`
			Target       string `json:"target"`
			Target2      string `json:"target2,omitempty"`
			AskRule      string `json:"ask_rule"`
			Score        *int   `json:"score,omitempty"`
			GateRule     string `json:"gate_rule,omitempty"`
			AnswerReason string `json:"answer_reason,omitempty"`
			// The file a person named in place of the target and its identity (ADR 0057 D1, record_minor 9):
			// approved false, no answer_reason, and the delivered open's fs line names the file with alternate_for.
			record.AnswerAlternate
		}{record.AnswerPayload{AskID: e.Request.AskID, By: e.Decision.By, AfterS: e.Decision.AfterS}, e.Decision.Approved, e.Request.Op, askclient.LedgerTarget(e.Request.Op, e.Request.Target), e.Request.Target2, e.Request.Rule, e.Request.Score, e.Request.GateRule, e.Decision.Reason,
			record.AnswerAlternate{Alternate: e.Decision.Alternate, AlternateDev: e.Decision.AlternateDev, AlternateIno: e.Decision.AlternateIno}}); err != nil {
			return err
		}
	}
	// This synchronous ledger path is deliberate: a dropped queue line must
	// never turn into an unrecorded human grant. The writer serializes it with
	// ordinary events and applies the normal hash chain and write failures.
	if err := r.writer.RedactStage(r.writer.Append)(ev); err != nil {
		r.ledgerFailed(err)
		return err
	}
	if e.Kind == "answer" && e.Request.Hold == "first_write" && !e.Decision.Approved {
		// The original connect already completed into the private relay. Its
		// denied first delivery has no pending notification to emit a refusal.
		if err := r.appendFirstWrite(r.firstWriteRefusal(e.Request, e.Decision.Reason)); err != nil {
			return err
		}
	}
	if r.budget != nil {
		r.budget.Touch(r.deps.Clock.MonoNS())
	}
	return nil
}

// firstWriteRefusal is the refused line of a first delivery the relay reset:
// its connect was allowed into the relay, so no notification refuses it.
func (r *runner) firstWriteRefusal(req ask.Request, reason string) (*record.Event, error) {
	ev := &record.Event{V: record.Version, TS: r.deps.Clock.Now(), MonoNS: r.deps.Clock.MonoNS(), PID: req.PID, TID: req.TID, Cgroup: r.cg.ID, Source: record.SourceSupervisor, Kind: record.KindRefused, Rule: req.Rule, Reason: record.Reason(reason)}
	if ev.Reason == "" {
		ev.Reason = record.ReasonAskUnavailable
	}
	return firstWritePayload(ev, req)
}

// firstWriteBlocked is the refused line of a first delivery a live block refused (ask.Delivery.Blocked): under the
// block's rule, refused net-not-allowed, as the supervisor refuses a connect the block names (liveNet), never the ask's.
func (r *runner) firstWriteBlocked(req ask.Request, rule string) (*record.Event, error) {
	ev := &record.Event{V: record.Version, TS: r.deps.Clock.Now(), MonoNS: r.deps.Clock.MonoNS(), PID: req.PID, TID: req.TID, Cgroup: r.cg.ID, Source: record.SourceSupervisor, Kind: record.KindRefused, Rule: rule, Reason: record.ReasonNetNotAllowed}
	return firstWritePayload(ev, req)
}

// firstWritePayload sets a first-write refused line's payload: the target in its ledger form, askclient.LedgerTarget's
// alone (askclient TestLedgerTargetSingleSource counts the call sites), so a reset and a blocked first delivery name the
// target alike.
func firstWritePayload(ev *record.Event, req ask.Request) (*record.Event, error) {
	return ev, ev.SetPayload(record.RefusedPayload{Op: "first_write", Target: askclient.LedgerTarget(req.Op, req.Target), Rule: ev.Rule, Reason: ev.Reason})
}

// appendFirstWrite writes a first-write line on emitAsk's synchronous path.
func (r *runner) appendFirstWrite(ev *record.Event, err error) error {
	if err != nil {
		return err
	}
	if err = r.writer.RedactStage(r.writer.Append)(ev); err != nil {
		r.ledgerFailed(err)
		return err
	}
	return nil
}

// emitFirstWrite records a relay's end once it read the agent's first bytes.
// The supervisor wrote only the connect into the relay (`allow`, hold
// first_write, upstream_connected false). A request that failed before an
// answer line was accepted (broker capacity, a process no longer in the run,
// cancellation) is refused here, as a recorded denial is by emitAsk's mirror
// (SEMANTICS §6). An approval records its outcome as an approved open does:
// a human-authority net line with upstream_connected and delivered. A
// delivery a live block refused (d.Blocked) is refused under the block's rule
// when nobody was asked, the request failed unrecorded, or an approval came
// back after the block landed; a request the block withdrew was answered
// ask-unavailable by cancelled, whose line emitAsk's mirror already refused.
func (r *runner) emitFirstWrite(d ask.Delivery) {
	if r.writer == nil {
		return
	}
	var err error
	switch {
	case d.Blocked != "" && (d.Err != nil || d.Decision.Approved || d.Decision.AskID == ""):
		err = r.appendFirstWrite(r.firstWriteBlocked(d.Request, d.Blocked))
	case d.Err != nil:
		reason := d.Decision.Reason
		if errors.Is(d.Err, context.DeadlineExceeded) {
			reason = ask.ReasonTimeout
		}
		err = r.appendFirstWrite(r.firstWriteRefusal(d.Request, reason))
	case d.Decision.Approved:
		if d.Delivered && r.rt.Record == agent.RecordOff {
			return
		}
		ev := &record.Event{V: record.Version, TS: r.deps.Clock.Now(), MonoNS: r.deps.Clock.MonoNS(), PID: d.Request.PID, TID: d.Request.TID, Cgroup: r.cg.ID, Source: record.SourceSupervisor, Kind: record.KindNet, Rule: d.Request.Rule, Verdict: record.VerdictAllow, Authority: record.AuthorityHuman, Attr: record.Unattributed()}
		err = r.appendFirstWrite(ev, ev.SetPayload(struct {
			record.NetPayload
			Hold              string `json:"hold"`
			UpstreamConnected bool   `json:"upstream_connected"`
			Delivered         bool   `json:"delivered"`
		}{record.NetPayload{Op: "first_write", Proto: "tcp", Dst: d.Request.Target}, "first_write", d.Connected, d.Delivered}))
	default:
		return
	}
	if err != nil {
		r.log.Error("run: record first-write delivery", "err", err)
	}
	if r.budget != nil {
		r.budget.Touch(r.deps.Clock.MonoNS())
	}
}

func (r *runner) startAsk(ctx context.Context) error {
	if r.rt.AskConfig == nil {
		return nil
	}
	if recordsOnly(r.handle) || r.notifyFD == nil {
		return fmt.Errorf("%w: ask requires an enforcing notification listener", ask.ErrUnavailable)
	}
	uid, _ := config.InvokingUID()
	r.askOwner = uint32(uid) // before ask.New, whose socket serves from the start (askPeerAuthorize reads it)
	cfg := r.rt.AskConfig
	opts := ask.Options{UID: uint32(uid), Timeout: time.Duration(cfg.Timeout), MaxPending: cfg.MaxPending, Authorize: r.askPeerAuthorize, Emit: r.emitAsk, TimeoutStands: cfg.OnTimeout == agent.AskOnTimeoutRefuseAlways}
	if tell := r.deps.AskPending; tell != nil {
		id := r.id
		opts.Pending = func(req ask.Request) { tell(AskPending{Run: id, AskID: req.AskID, Op: req.Op}) }
	}
	b, err := ask.New(r.dir, opts)
	if err != nil {
		return err
	}
	r.askBroker = b
	r.askCtx = ctx
	r.configureMCPAsk()
	if cfg.Hold == agent.AskHoldFirstWrite {
		pool, err := ask.NewRelayPool(cfg.MaxPending, time.Duration(cfg.Timeout), r.askRequest, r.emitFirstWrite)
		if err != nil {
			return err
		}
		r.askRelays = pool
	}
	if cfg.Hold == agent.AskHoldRequest && len(r.rt.NetAsk) > 0 {
		configured := 0
		for _, s := range r.deps.Capture {
			if source, ok := s.(askSource); ok {
				if err := source.ConfigureAsk(r.rt, r.askRequest); err != nil {
					return err
				}
				configured++
			}
		}
		if configured == 0 {
			return fmt.Errorf("%w: request holds require a cooperating authenticated forwarder", ask.ErrUnavailable)
		}
	}
	return nil
}

func (r *runner) stopAsk() {
	if r.askRelays != nil {
		if err := r.askRelays.Close(); err != nil {
			r.log.Error("run: ask relay cleanup", "err", err)
			r.noteDetail(err.Error())
		}
	}
	if r.askBroker != nil {
		if err := r.askBroker.Close(); err != nil {
			r.log.Error("run: ask broker cleanup", "err", err)
			r.noteDetail(err.Error())
		}
	}
}

// Return the option's interface type so an absent optional set remains a nil
// interface, rather than a non-nil interface containing a nil *dns.Set.
func (r *runner) startAskDNS(ctx context.Context, opts dns.Options, tick time.Duration) supervisor.Resolver {
	if len(r.rt.NetAsk) == 0 {
		return nil
	}
	set := dns.NewSet(r.rt.NetAsk, nil, opts)
	r.group.Go("ask-dns", func() error {
		ticker := time.NewTicker(tick)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				if err := set.Refresh(ctx); err != nil && !errors.Is(err, context.Canceled) {
					return err
				}
			}
		}
	})
	return set
}
