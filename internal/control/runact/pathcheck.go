// SPDX-License-Identifier: Apache-2.0

package runact

import (
	"context"
	"errors"
	"time"

	"github.com/attention-span-ai/tego/internal/control/pathcheck"
	"github.com/attention-span-ai/tego/internal/liveblock"
)

var alternateErrors = []error{ErrBadRun, ErrBadAsk, ErrBadAlternate}

type alternateRequest struct {
	Root, Run, Ask, Path string
	Always               bool
}
type alternateReply struct {
	Answered Answered
	Error    string
	Kinds    []int
}

func init() {
	pathcheck.Register("control.alternate", func(parent context.Context, payload []byte) ([]byte, error) {
		var req alternateRequest
		if err := pathcheck.Decode(payload, &req); err != nil {
			return nil, err
		}
		ctx, cancel := pathcheck.Context(parent)
		defer cancel()
		value, err := Alternate(ctx, req.Root, req.Run, req.Ask, req.Path, req.Always)
		reply := alternateReply{Answered: value}
		if err != nil {
			reply.Error = pathcheck.LocationError(err).Error()
			for i, e := range alternateErrors {
				if errors.Is(err, e) {
					reply.Kinds = append(reply.Kinds, i)
				}
			}
		}
		return pathcheck.Encode(reply)
	})
}
func alternateRemote(ctx context.Context, root, run, ask, path string, always bool) (Answered, error) {
	ctx, cancel := pathcheck.Bound(ctx)
	defer cancel()
	var reply alternateReply
	if err := pathcheck.Call(pathcheck.WithLocations(ctx, root, path), "control.alternate", alternateRequest{Root: root, Run: run, Ask: ask, Path: path, Always: always}, &reply); err != nil {
		return Answered{}, err
	}
	if reply.Error != "" {
		var causes []error
		for _, kind := range reply.Kinds {
			if kind >= 0 && kind < len(alternateErrors) {
				causes = append(causes, alternateErrors[kind])
			}
		}
		return reply.Answered, &pathcheck.RemoteError{Message: reply.Error, Causes: causes}
	}
	return reply.Answered, nil
}

type blockRequest struct {
	Root, Run, Kind, Value, Via string
	Add, Link                   bool
	Until                       time.Time
	Own                         Owned
}
type blockReply struct {
	Terminal string
	Blocked  Blocked
	Error    string
	Kinds    []int
}

var blockErrors = []error{ErrGoverned, ErrBadRun, ErrNotRunning, ErrNoTimeLimits, ErrOldLauncher, ErrReadsUnseen, liveblock.ErrInvalid, liveblock.ErrStarting, liveblock.ErrStartUnreadable, ErrOverlayMoved, ErrNoWords}

func init() {
	pathcheck.Register("control.block", func(parent context.Context, payload []byte) ([]byte, error) {
		var req blockRequest
		if err := pathcheck.Decode(payload, &req); err != nil {
			return nil, err
		}
		ctx, cancel := pathcheck.Context(parent)
		defer cancel()
		value, err := blockUntil(ctx, req.Root, req.Run, req.Kind, req.Value, req.Add, req.Until, req.Via, req.Link, req.Own)
		reply := blockReply{Blocked: value}
		if err != nil {
			reply.Error = pathcheck.LocationError(err).Error()
			reply.Terminal = liveblock.RunWords(err)
			for i, e := range blockErrors {
				if errors.Is(err, e) {
					reply.Kinds = append(reply.Kinds, i)
				}
			}
		}
		return pathcheck.Encode(reply)
	})
}
func blockRemote(ctx context.Context, req blockRequest) (Blocked, error) {
	ctx, cancel := pathcheck.Bound(ctx)
	defer cancel()
	var reply blockReply
	if err := pathcheck.Call(pathcheck.WithLocations(ctx, req.Root), "control.block", req, &reply); err != nil {
		return Blocked{}, err
	}
	if reply.Error != "" {
		var causes []error
		for _, kind := range reply.Kinds {
			if kind >= 0 && kind < len(blockErrors) {
				causes = append(causes, blockErrors[kind])
			}
		}
		return reply.Blocked, &remoteBlockError{RemoteError: &pathcheck.RemoteError{Message: reply.Error, Causes: causes}, terminal: reply.Terminal}
	}
	return reply.Blocked, nil
}

// The helper preserves the same refusal's terminal words as well as its page
// words and sentinel causes. No policy is reconstructed from a display reply.
type remoteBlockError struct {
	*pathcheck.RemoteError
	terminal string
}

func (e *remoteBlockError) RunWords() string { return e.terminal }
