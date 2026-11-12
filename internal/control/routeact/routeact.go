// SPDX-License-Identifier: Apache-2.0

package routeact

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/modelroutes"
	"github.com/attention-span-ai/tego/internal/runlock"
	"github.com/attention-span-ai/tego/pkg/policy/modelroute"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Errors a page turns into words.
var (
	ErrBadRun     = errors.New("routeact: no such run")
	ErrNotRunning = errors.New("routeact: the run is not running, so a route change would apply to nothing")
	ErrNoEndpoint = errors.New("routeact: the run declares no such model endpoint")
	ErrNoRoute    = errors.New("routeact: the endpoint declares no such route")
	ErrGoverned   = errors.New("routeact: a run's model route is never changed from inside a run")
	ErrAck        = errors.New("routeact: this change needs the preview's acknowledgement, and the one sent is missing or out of date")
	// ErrLocked is a route other than direct asked of a Locked run, which would leave it looser than its contract
	// (runact.CheckLoosening, ADR 0127 §6): it changes from the run's next run only.
	ErrLocked = runact.ErrLocked
	// ErrStarting is such a route asked while the run's run_start cannot be read yet: its mode is not known, so it is
	// refused as not known yet, never as Locked (runact.ErrStarting).
	ErrStarting = runact.ErrStarting
	// ErrStartUnreadable is such a route asked of a run whose first record line is not a run_start this tego can
	// read: refused as not known, never as Locked (runact.ErrStartUnreadable).
	ErrStartUnreadable = runact.ErrStartUnreadable
)

// maxContract bounds the contract copy read.
const maxContract = 1 << 20

// ackDomain separates this acknowledgement from every other HMAC the key could make.
const ackDomain = "tego-route-ack-v1"

// Option is one route an endpoint may take.
type Option struct {
	Name      string
	Authority string
	TLS       bool
	// Current is whether the forwarder sends the endpoint's next request by it.
	Current bool
	// Requests is how many of the run's requests to the endpoint went by it (its ssl_request lines).
	Requests int
}

// Model is one models[] endpoint as the page shows it.
type Model struct {
	Endpoint string // the declared host:port
	Provider string
	// Route is the route in force and SendsTo its backend; By and At who put it in force and when ("" when direct
	// from the start).
	Route, SendsTo string
	By             string
	At             time.Time
	// Options are direct and the declared routes, in contract order; one option is an endpoint without routes.
	Options []Option
	// Changes are the route changes the forwarder recorded for this endpoint, oldest first.
	Changes []record.ModelRouteChange
}

// Routed reports whether the endpoint declares any route.
func (m Model) Routed() bool { return len(m.Options) > 1 }

// State is the page's view of a run's model endpoints.
type State struct {
	Run     string
	Running bool
	Models  []Model
}

// Plan is one previewed change.
type Plan struct {
	Run, Endpoint string
	From, To      Option
	// Widens is whether the change sends the endpoint's requests to a route other than direct; only then is Ack needed.
	Widens bool
	Ack    string
	// Changed is set by Set: whether the overlay changed.
	Changed bool
}

// Service is the model routes service over one ledger root.
type Service struct {
	Root string
	// Now stamps a change; nil is time.Now.
	Now func() time.Time
	// governed reports whether the caller is inside a run; nil is runact.SelfGoverned. Tests replace it.
	governed func() (bool, error)
	// beforeLock runs in Set between the preview's read and the writers' lock; nil in production. Tests use it to move
	// the overlay there.
	beforeLock func()
}

// New is the service over the ledger root.
func New(root string) *Service { return &Service{Root: root} }

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) runDir(run string) (string, error) {
	if !ledger.IsRunID(run) {
		return "", fmt.Errorf("%q: %w", run, ErrBadRun)
	}
	dir := filepath.Join(s.Root, run)
	if _, err := os.Stat(dir); err != nil {
		return "", fmt.Errorf("%s: %w", run, ErrBadRun)
	}
	return dir, nil
}

// models reads the run's contract copy's models[] entries, ports defaulted to 443. The copy is the compiled,
// self-contained contract, so its models list is the run's.
func models(dir string) ([]agent.ModelEndpoint, error) {
	f, err := os.OpenFile(filepath.Join(dir, "contract.yaml"), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxContract+1))
	if err != nil || len(b) > maxContract {
		return nil, fmt.Errorf("routeact: contract copy unreadable or too large")
	}
	var doc struct {
		Models []agent.ModelEndpoint `yaml:"models"`
	}
	if err := config.GuardYAML(func() error { return yaml.Unmarshal(b, &doc) }); err != nil {
		return nil, fmt.Errorf("routeact: contract copy: %w", err)
	}
	for i := range doc.Models {
		if doc.Models[i].Port == 0 {
			doc.Models[i].Port = 443
		}
	}
	return doc.Models, nil
}

// facts is what the run's ledger says per endpoint: the requests by each route, and the route changes.
type facts struct {
	requests map[[2]string]int // (endpoint, route) -> requests
	changes  map[string][]record.ModelRouteChange
}

func readFacts(dir string, ms []agent.ModelEndpoint) facts {
	f := facts{requests: map[[2]string]int{}, changes: map[string][]record.ModelRouteChange{}}
	rd, err := ledger.OpenReader(dir)
	if err != nil {
		return f
	}
	defer func() { _ = rd.Close() }()
	count := modelroute.RequestCounter(ms)
	for e, err := range rd.Iter() {
		if err != nil {
			break
		}
		switch e.Kind {
		case record.KindSSLRequest:
			count(e, f.requests)
		case record.KindGap:
			var p record.GapPayload
			if e.DecodePayload(&p) != nil || p.Why != record.GapModelRouteChanged || p.ModelRoute == nil {
				continue
			}
			f.changes[p.ModelRoute.Model] = append(f.changes[p.ModelRoute.Model], *p.ModelRoute)
		}
	}
	return f
}

func readOverlay(dir, run string) (*modelroutes.Overlay, error) {
	o, err := modelroutes.Read(dir, run)
	if errors.Is(err, os.ErrNotExist) {
		return modelroutes.New(run), nil
	}
	return o, err
}

// option is m's route name as an Option.
func option(m agent.ModelEndpoint, name string) Option {
	r, _ := modelroute.Resolve(m, name)
	return Option{Name: r.Name, Authority: r.Authority(), TLS: r.TLS}
}

// State is the run's model endpoints, each with the route in force, the routes it may take and the requests by each.
func (s *Service) State(run string) (*State, error) {
	dir, err := s.runDir(run)
	if err != nil {
		return nil, err
	}
	ms, err := models(dir)
	if err != nil {
		return nil, err
	}
	o, err := readOverlay(dir, run)
	if err != nil {
		return nil, err
	}
	fc := readFacts(dir, ms)
	held, _, _ := runlock.ProbeLock(dir)
	st := &State{Run: run, Running: held}
	for _, m := range ms {
		auth := m.ModelAuthority()
		row := Model{Endpoint: auth, Provider: m.Provider, Changes: fc.changes[auth]}
		live := ""
		if e, ok := o.Lookup(auth); ok {
			live, row.By, row.At = e.Route, e.By, e.At
		}
		now, _ := modelroute.Resolve(m, live)
		row.Route, row.SendsTo = now.Name, now.Authority()
		for _, name := range modelroute.Names(m) {
			opt := option(m, name)
			opt.Current = name == now.Name
			opt.Requests = fc.requests[[2]string{auth, name}]
			row.Options = append(row.Options, opt)
		}
		st.Models = append(st.Models, row)
	}
	return st, nil
}

// HasRoutes reports whether run's contract declares any route (the page's run picker).
func (s *Service) HasRoutes(run string) bool {
	dir, err := s.runDir(run)
	if err != nil {
		return false
	}
	ms, err := models(dir)
	if err != nil {
		return false
	}
	for _, m := range ms {
		if len(m.Routes) > 0 {
			return true
		}
	}
	return false
}

// overlayBase is the sha256 of the overlay file now, "" when there is none.
func overlayBase(dir string) (string, error) {
	b, err := modelroutes.SHA256Base(dir)
	if err != nil || b == nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func (s *Service) plan(run, endpoint, route string) (*Plan, string, agent.ModelEndpoint, error) {
	var m agent.ModelEndpoint
	if !modelroutes.ValidModel(endpoint) || !modelroutes.ValidRoute(route) {
		return nil, "", m, ErrNoEndpoint
	}
	dir, err := s.runDir(run)
	if err != nil {
		return nil, "", m, err
	}
	ms, err := models(dir)
	if err != nil {
		return nil, "", m, err
	}
	found := false
	for _, x := range ms {
		if x.ModelAuthority() == endpoint {
			m, found = x, true
			break
		}
	}
	if !found {
		return nil, "", m, ErrNoEndpoint
	}
	if _, declared := modelroute.Resolve(m, route); !declared {
		return nil, "", m, ErrNoRoute
	}
	o, err := readOverlay(dir, run)
	if err != nil {
		return nil, "", m, err
	}
	from := modelroute.Direct
	if e, ok := o.Lookup(endpoint); ok {
		from = e.Route
	}
	p := &Plan{Run: run, Endpoint: endpoint, From: option(m, from), To: option(m, route), Widens: modelroute.Widens(from, route)}
	// A Locked run is never looser than its contract while it runs (ADR 0125), and its contract starts every endpoint on
	// direct: any other route is refused, while direct is taken, as a live block's removal is. The route alone decides
	// it, not the overlay, so the writers' lock has nothing to decide again.
	if route != modelroute.Direct {
		if err := runact.CheckLoosening(dir, run); err != nil {
			if errors.Is(err, runact.ErrNotRunning) {
				err = ErrNotRunning
			}
			return p, dir, m, err
		}
	}
	if p.Widens {
		base, err := overlayBase(dir)
		if err != nil {
			return nil, "", m, err
		}
		p.Ack = ackOf(run, endpoint, route, base)
	}
	return p, dir, m, nil
}

// Plan previews sending endpoint's requests in run by route (a declared route, or direct).
func (s *Service) Plan(run, endpoint, route string) (*Plan, error) {
	p, _, _, err := s.plan(run, endpoint, route)
	return p, err
}

// Set puts route in force for endpoint for the rest of the run. One that widens needs ack, Plan's acknowledgement
// against the overlay as it still stands. Every change is refused to a caller inside a run.
func (s *Service) Set(ctx context.Context, run, endpoint, route, ack string) (*Plan, error) {
	p, dir, m, err := s.plan(run, endpoint, route)
	if err != nil {
		return p, err
	}
	gov := s.governed
	if gov == nil {
		gov = runact.SelfGoverned
	}
	if in, _ := gov(); in { // fails closed: a cgroup it cannot judge refuses too
		return p, ErrGoverned
	}
	if held, _, err := runlock.ProbeLock(dir); err != nil {
		return p, err
	} else if !held {
		return p, ErrNotRunning
	}
	by := modelroutes.By("dashboard")
	if s.beforeLock != nil {
		s.beforeLock()
	}
	var ackErr error
	_, err = modelroutes.Update(ctx, dir, run, func(o *modelroutes.Overlay) (bool, error) {
		// Whether it widens is decided again on the overlay under the writers' lock: a change made between plan's read
		// and this lock (a clear from another terminal) must not turn a no-op into a widening without its
		// acknowledgement.
		from := modelroute.Direct
		if e, ok := o.Lookup(endpoint); ok {
			from = e.Route
		}
		p.From, p.Widens = option(m, from), modelroute.Widens(from, route)
		if p.Widens {
			// The acknowledgement binds the overlay the preview showed, checked under the writers' lock.
			base, err := overlayBase(dir)
			if err != nil {
				return false, err
			}
			if !ackOK(ack, run, endpoint, route, base) {
				ackErr = ErrAck
				return false, nil
			}
		}
		changed, err := o.Set(endpoint, route, by, s.now())
		p.Changed = changed
		return changed, err
	})
	if ackErr != nil {
		return p, ackErr
	}
	return p, err
}

// Clear sends endpoint's requests to the endpoint itself again: Set to direct, which needs no acknowledgement.
func (s *Service) Clear(ctx context.Context, run, endpoint string) (*Plan, error) {
	return s.Set(ctx, run, endpoint, modelroute.Direct, "")
}

var (
	keyOnce sync.Once
	procKey [32]byte
)

// key is this process's random acknowledgement key: an acknowledgement does not outlive the dashboard that made it.
func key() []byte {
	keyOnce.Do(func() {
		_, _ = rand.Read(procKey[:]) // never fails: since Go 1.24 crypto/rand crashes the program itself instead
	})
	return procKey[:]
}

// ackOf binds a change to the overlay it was previewed against (base: the overlay file's sha256, "" for none).
func ackOf(run, endpoint, route, base string) string {
	m := hmac.New(sha256.New, key())
	for _, s := range []string{ackDomain, run, endpoint, route, base} {
		m.Write([]byte(s))
		m.Write([]byte{0})
	}
	return hex.EncodeToString(m.Sum(nil))
}

// ackOK reports whether ack is the acknowledgement of this change against this base.
func ackOK(ack, run, endpoint, route, base string) bool {
	return hmac.Equal([]byte(ack), []byte(ackOf(run, endpoint, route, base)))
}
