// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/registry"
	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// CompileContext carries only the selected offline compiler inputs. Environment
// secret values never cross the pipe. Selected identity/path inputs are carried
// separately. The helper cannot reload or select configuration.
type CompileContext struct {
	ChainAnchor string
	OwnBinary   string
	RuntimeDirs []string
	EnvNames    []string
	Caller      *config.CallerContext
	// MountInfo and Now allow deterministic offline checks without probing mounts.
	// A nil MountInfo selects the compiler default.
	MountInfo *string
	Now       *time.Time
}

func (c CompileContext) options() []agent.CompileOption {
	opts := []agent.CompileOption{agent.WithRuntimeDir(c.RuntimeDirs...), agent.WithOwnBinaries(c.OwnBinary), agent.WithEnviron(c.EnvNames)}
	if c.Caller != nil {
		opts = append(opts, agent.WithCallerContext(*c.Caller), agent.WithRuntimeDir(c.Caller.RuntimeDirs...), agent.WithClock(func() time.Time { return c.Caller.CheckedAt }))
	}
	if c.ChainAnchor != "" {
		opts = append(opts, agent.WithChainAnchor(c.ChainAnchor))
	}
	if c.MountInfo != nil {
		opts = append(opts, agent.WithMountInfo(*c.MountInfo))
	}
	if c.Now != nil {
		opts = append(opts, agent.WithClock(func() time.Time { return *c.Now }))
	}
	return opts
}

type checkRequest struct {
	Operation, Path  string
	Payload          []byte
	Caller           *config.CallerContext
	Places           registry.Places
	Entry            Entry
	Data             []byte
	DataPresent      bool
	ReadError        wireError
	Expected         string
	Owner            *int
	OwnerPresent     bool
	MountInfoPresent bool
	UnknownOwner     bool
	machine          *config.Machine
	Context          []byte
	PATH             string
	Tiers            []backend.Tier
	CompileContext   CompileContext
	KeepTableFor     string
	// Within is how long the worker's own clock runs once it reports ready (a duration, never a wall-clock time: the
	// caller's clock starts before the helper exists): the most the caller may allow, its cap and a backstop. The
	// caller decides when the check ends; the worker's clock only ends an operation whose caller has gone. Zero
	// means the most.
	Within time.Duration
	// Local says the caller classed the location as local (location.go): the helper's own check bound is then the local
	// one and an interrupted source is in the disk's words.
	Local bool
}

type wireError struct {
	Message                                        string
	Missing, NotDir, Loop, Untrusted, Guard, Bound bool
	IO, Disconnected                               bool
}

func packError(err error) wireError {
	if err == nil {
		return wireError{}
	}
	return wireError{Message: err.Error(), Missing: errors.Is(err, os.ErrNotExist), NotDir: errors.Is(err, syscall.ENOTDIR), Loop: errors.Is(err, syscall.ELOOP), Untrusted: errors.Is(err, config.ErrUntrusted), Guard: errors.Is(err, rulefile.ErrGuard), Bound: errors.Is(err, registry.ErrCatalogBound), IO: errors.Is(err, syscall.EIO), Disconnected: errors.Is(err, syscall.ENOTCONN)}
}

func (e wireError) error() error {
	if e.Message == "" {
		return nil
	}
	var causes []error
	for _, c := range []struct {
		yes bool
		err error
	}{{e.Missing, os.ErrNotExist}, {e.NotDir, syscall.ENOTDIR}, {e.Loop, syscall.ELOOP}, {e.Untrusted, config.ErrUntrusted}, {e.Guard, rulefile.ErrGuard}, {e.Bound, registry.ErrCatalogBound}, {e.IO, syscall.EIO}, {e.Disconnected, syscall.ENOTCONN}} {
		if c.yes {
			causes = append(causes, c.err)
		}
	}
	return &replyError{message: e.Message, causes: causes}
}

type replyError struct {
	message string
	causes  []error
}

func (e *replyError) Error() string   { return e.message }
func (e *replyError) Unwrap() []error { return e.causes }

type listedEntry struct {
	registry.Entry
	Err         wireError
	Dev, Ino    uint64
	HasIdentity bool
	DataPresent bool
}

func (e listedEntry) sameFile(other listedEntry) bool {
	return e.HasIdentity && other.HasIdentity && e.Dev == other.Dev && e.Ino == other.Ino
}

type listedRoot struct{ Path, Kind, State, Err string }
type checkReply struct {
	Payload    []byte
	Path       string
	OK         bool
	Entry      Entry
	Show       *Show
	Entries    []listedEntry
	Roots      []listedRoot
	Incomplete bool
}

func requestCheck(ctx context.Context, req checkRequest) (checkReply, error) {
	// The two budgets are exchange's (a scope's, see WithBudget); the caller's own deadline still applies.
	var reply checkReply
	if err := refuseExpired(ctx); err != nil {
		return reply, err
	}
	ctx = WithCallerContext(ctx)
	if req.machine != nil {
		snapshot := req.machine.Snapshot()
		encoded, err := json.Marshal(snapshot)
		if err != nil {
			return reply, fmt.Errorf("encode compile context: %w", err)
		}
		req.Context = encoded
	}
	req.DataPresent = req.Data != nil
	req.OwnerPresent = req.Owner != nil
	req.MountInfoPresent = req.CompileContext.MountInfo != nil
	req.Caller = CallerContext(ctx)
	// The class of the location, decided once for this check from the mount table (location.go).
	ctx = withClass(ctx, requestLocations(&req)...)
	req.Local = localCheck(ctx)
	req.Within = workerWithin(ctx)

	data, err := encodeCheck(req)
	if err != nil {
		return reply, err
	}
	data, err = exchange(ctx, data)
	if err != nil {
		return reply, err
	}
	if err := decodeCheck(data, &reply); err != nil {
		return reply, fmt.Errorf("filesystem reply: %w", err)
	}
	if reply.Entry.Diagnostics == nil {
		reply.Entry.Diagnostics = []Diagnostic{}
	}
	for i := range reply.Entries {
		if reply.Entries[i].DataPresent && reply.Entries[i].Data == nil {
			reply.Entries[i].Data = []byte{}
		}
	}
	// The deadline also wins a race with decoding a reply.
	if err := ctx.Err(); err != nil {
		return checkReply{}, err
	}
	return reply, nil
}

func handleRequestContext(parent context.Context, data []byte) ([]byte, error) {
	var req checkRequest
	if err := decodeCheck(data, &req); err != nil {
		return nil, err
	}
	req.restoreZeros()
	if req.Caller == nil {
		return nil, errors.New("missing caller context")
	}
	parent = context.WithValue(parent, callerContextKey{}, req.Caller)

	// The worker has decoded the request; the next thing it does is touch the location. Say so before the clock of
	// the location budget starts, here and in the caller.
	if ready, ok := parent.Value(helperReadyKey{}).(func() error); ok {
		if err := ready(); err != nil {
			return nil, err
		}
	}
	within := req.Within
	most := locationCap() + workerBackstop()
	if req.Local {
		most = localCap() + workerBackstop()
	}
	if within <= 0 || within > most {
		within = most
	}
	reply := checkReply{}
	// The location clock of this operation: it runs only while the operation touches the location (PauseLocation).
	clock, cancel := newLocationClock(parent, within)
	defer cancel()
	var ctx context.Context = clock
	if req.Local {
		ctx = context.WithValue(ctx, localKey{}, true)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch req.Operation {
	case "place":
		reply.Path, reply.OK = walkPath(req.Path)
	case "registry":
		entries, roots := catalogRegistry(req.Places, ctx)
		for _, e := range entries {
			dev, ino, ok := e.FileIdentity()
			reply.Entries = append(reply.Entries, listedEntry{e.Entry, packError(e.Err), dev, ino, ok, e.Data != nil})
		}
		for _, r := range roots {
			msg := ""
			if r.Err != nil {
				msg = r.Err.Error()
				if errors.Is(r.Err, syscall.EIO) || errors.Is(r.Err, syscall.ENOTCONN) {
					msg = CheckUnavailable(r.Err).Error()
				}
			}
			reply.Roots = append(reply.Roots, listedRoot{r.Path, r.Kind, r.State, msg})
		}
	case "source":
		if req.Context == nil {
			return nil, errors.New("missing compile context")
		}
		var snapshot config.Snapshot
		if err := json.Unmarshal(req.Context, &snapshot); err != nil {
			return nil, fmt.Errorf("decode compile context: %w", err)
		}
		m := snapshot.Restore()
		e := req.Entry
		e.data, e.readErr, e.expected, e.owner, e.unknownOwner = req.Data, req.ReadError.error(), req.Expected, req.Owner, req.UnknownOwner
		c := Catalog{machine: m}
		o := Options{Machine: m, Places: req.Places, PATH: req.PATH, Tiers: req.Tiers, CompileContext: req.CompileContext, KeepTableFor: req.KeepTableFor}
		c.checkSource(ctx, &e, o, readSource)
		if e.table != nil {
			show, err := c.Describe(e)
			if err != nil {
				return nil, err
			}
			reply.Show = &show
		}
		reply.Entry, reply.Incomplete = e, c.Incomplete
	default:
		handle, ok := helperOperations[req.Operation]
		if !ok {
			return nil, errors.New("unknown filesystem check")
		}
		var err error
		reply.Payload, err = handle(ctx, req.Payload)
		if err != nil {
			return nil, err
		}
	}
	return encodeCheck(reply)
}

// The private business protocol keeps source bytes raw. Base64 JSON made a
// bounded registry reply exceed its five-second check deadline under load.
// Configuration alone remains JSON so its complete snapshot keeps the config
// package's established codecs for address and duration types.
func encodeCheck(value any) ([]byte, error) {
	var buffer bytes.Buffer
	if err := gob.NewEncoder(&buffer).Encode(value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func decodeCheck(data []byte, value any) error {
	return gob.NewDecoder(bytes.NewReader(data)).Decode(value)
}

// Gob omits zero-valued scalar fields even through a non-nil pointer. Preserve
// the distinction between root ownership and unknown ownership, and between an
// explicitly disabled mount probe and the default mountinfo probe.
func (req *checkRequest) restoreZeros() {
	if req.DataPresent && req.Data == nil {
		req.Data = []byte{}
	}
	if req.OwnerPresent && req.Owner == nil {
		req.Owner = new(int)
	}
	if req.MountInfoPresent && req.CompileContext.MountInfo == nil {
		req.CompileContext.MountInfo = new(string)
	}
}
