// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/control/pathcheck"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

type guideReply struct {
	State guide.State
	Built bool
}

type guideRequest struct {
	Inputs  []byte
	Machine []byte
}

type guideFileRequest struct {
	Home string
	UID  int
	Boot string
	Now  time.Time
}

type guideFileKeys struct{ Check, Scan string }

func init() {
	pathcheck.Register("control.guide-key", func(ctx context.Context, payload []byte) ([]byte, error) {
		var req guideFileRequest
		if err := pathcheck.Decode(payload, &req); err != nil {
			return nil, err
		}
		if req.Now.IsZero() {
			return nil, errors.New("missing guide evaluation time")
		}
		keys := guideFileKeys{Scan: guide.ReadScan(req.Home, req.UID, req.Boot, req.Now).Key()}
		if fi, err := os.Lstat(guide.CheckPath(req.Home)); err == nil {
			keys.Check = strconv.FormatInt(fi.Size(), 10) + "@" + strconv.FormatInt(fi.ModTime().UnixNano(), 10)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return pathcheck.Encode(keys)
	})
	pathcheck.Register("control.guide", func(ctx context.Context, payload []byte) ([]byte, error) {
		var req guideRequest
		if err := pathcheck.Decode(payload, &req); err != nil {
			return nil, err
		}
		var in guide.Inputs
		if err := json.Unmarshal(req.Inputs, &in); err != nil {
			return nil, err
		}
		if in.Caller == nil {
			return nil, errors.New("missing guide caller context")
		}
		if in.Now.IsZero() {
			return nil, errors.New("missing guide evaluation time")
		}
		if req.Machine != nil {
			var snapshot config.Snapshot
			if err := json.Unmarshal(req.Machine, &snapshot); err != nil {
				return nil, err
			}
			in.Machine = snapshot.Restore()
		}
		in.Scan = guide.ReadScan(in.Home, in.UID, in.Host.BootID, in.Now)
		state := guide.Compute(ctx, in)
		encoded, err := json.Marshal(guideReply{State: *state, Built: state.Next.Built()})
		if err != nil {
			return nil, err
		}
		return pathcheck.Encode(encoded)
	})
}
func guideInputsForCaller(ctx context.Context, in guide.Inputs) (context.Context, guide.Inputs) {
	if in.Caller != nil {
		ctx = contracts.ContextWithCaller(ctx, *in.Caller)
	} else {
		ctx = contracts.WithCallerContext(ctx)
		in.Caller = contracts.CallerContext(ctx)
	}
	if in.Now.IsZero() {
		in.Now = in.Caller.CheckedAt
	}
	return ctx, in
}

func checkedGuide(ctx context.Context, in guide.Inputs) (guide.State, bool, error) {
	ctx, in = guideInputsForCaller(ctx, in)
	req := guideRequest{}
	if in.Machine != nil {
		var err error
		req.Machine, err = json.Marshal(in.Machine.Snapshot())
		if err != nil {
			return guide.State{}, false, err
		}
	}
	in.Machine = nil
	in.Scan = nil
	var err error
	req.Inputs, err = json.Marshal(in)
	if err != nil {
		return guide.State{}, false, err
	}
	var encoded []byte
	err = pathcheck.Call(ctx, "control.guide", req, &encoded)
	if err != nil {
		return guide.State{}, false, err
	}
	var reply guideReply
	err = json.Unmarshal(encoded, &reply)
	return reply.State, reply.Built, err
}

// checkedGuideKeys preserves immediate scan/check replacement invalidation while
// keeping all home-path inspection out of the dashboard's own threads.
func checkedGuideKeys(ctx context.Context, in guide.Inputs) (guideFileKeys, error) {
	ctx, in = guideInputsForCaller(ctx, in)
	var keys guideFileKeys
	err := pathcheck.Call(ctx, "control.guide-key", guideFileRequest{in.Home, in.UID, in.Host.BootID, in.Now}, &keys)
	return keys, err
}
