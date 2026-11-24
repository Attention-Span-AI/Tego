// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/control/pathcheck"
	"github.com/attention-span-ai/tego/internal/profilesrc"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

type viewRequest struct {
	Operation, Root, Run, Key, Anchor, PATH string
	Machine                                 []byte
	Profiles                                bool
}
type viewReply struct {
	Contract        Contract
	InForce         *InForceView
	Learned         *Learned
	Drifted         *Drifted
	Origin          RuleOrigin
	Found           bool
	InForceContract Contract
}

func init() {
	pathcheck.Register("control.view", viewOperation)
	pathcheck.Register("control.locations", locationsOperation)
}

func remoteView(o Options) bool {
	if pathcheck.InHelper() {
		return false
	}
	// The binary supplies only profilesrc.Chain. Other implementations are explicit
	// in-memory test sources whose behaviour cannot cross the private pipe.
	if o.Profiles != nil {
		if _, ok := o.Profiles.(*agent.ProfileChain); !ok {
			return false
		}
	}
	return true
}
func viewCall(ctx context.Context, operation, root, run, key, anchor string, o Options) (viewReply, error) {
	ctx = contracts.WithCallerContext(ctx)
	req := viewRequest{Operation: operation, Root: root, Run: run, Key: key, Anchor: anchor, PATH: contracts.CallerContext(ctx).PATH, Profiles: o.Profiles != nil}
	if o.Anchor != "" {
		req.Anchor = o.Anchor
	}
	if o.Machine != nil {
		var err error
		req.Machine, err = json.Marshal(o.Machine.Snapshot())
		if err != nil {
			return viewReply{}, err
		}
	}
	var reply viewReply
	var encoded []byte
	err := pathcheck.Call(ctx, "control.view", req, &encoded)
	if err != nil {
		return reply, err
	}
	err = json.Unmarshal(encoded, &reply)
	if reply.InForce != nil {
		reply.InForce.Contract = reply.InForceContract
	}
	return reply, err
}
func viewOperation(ctx context.Context, payload []byte) ([]byte, error) {
	var req viewRequest
	if err := pathcheck.Decode(payload, &req); err != nil {
		return nil, err
	}
	o := Options{Anchor: req.Anchor, PATH: req.PATH, Caller: contracts.CallerContext(ctx)}
	if req.Machine != nil {
		var snapshot config.Snapshot
		if err := json.Unmarshal(req.Machine, &snapshot); err != nil {
			return nil, err
		}
		o.Machine = snapshot.Restore()
	}
	if req.Profiles {
		o.Profiles = profilesrc.Chain(o.Machine, *o.Caller)
	}
	reply := viewReply{}
	switch req.Operation {
	case "load":
		reply.Contract = Load(ctx, req.Root, req.Run, o)
	case "inforce-copy":
		reply.InForce = inForceWithSource(ctx, req.Root, req.Run, o, false)
	case "inforce":
		reply.InForce = InForce(ctx, req.Root, req.Run, o)
	case "learn":
		reply.Learned = Learn(ctx, req.Root, req.Anchor, req.Run)
	case "drift":
		reply.Drifted = Drift(ctx, req.Root, req.Run, o)
	case "origin":
		reply.Origin, reply.Found = RuleSource(ctx, req.Root, req.Run, req.Key, o)
	}
	reply.Contract.Text, reply.Contract.Table = reply.Contract.Shown()
	if reply.InForce != nil {
		reply.InForceContract = reply.InForce.Contract
		reply.InForceContract.Text, reply.InForceContract.Table = reply.InForceContract.Shown()
	}
	encoded, err := json.Marshal(reply)
	if err != nil {
		return nil, err
	}
	return pathcheck.Encode(encoded)
}

// locationsOperation checks a whole chooser in one exchange. Its fallback keeps
// all recorded entries when one path does not answer.
func locationsOperation(ctx context.Context, payload []byte) ([]byte, error) {
	var entries []ContractRun
	if err := pathcheck.Decode(payload, &entries); err != nil {
		return nil, err
	}
	for i := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		_, err := os.Lstat(entries[i].Path)
		entries[i].Gone = missingLocation(err)
		if err != nil && !entries[i].Gone {
			entries[i].Why = pathcheck.LocationError(err).Error()
		}
		entries[i].Resolved = ""
		if d, err := filepath.EvalSymlinks(filepath.Dir(entries[i].Path)); err == nil {
			resolved := filepath.Join(d, filepath.Base(entries[i].Path))
			if resolved != entries[i].Path {
				entries[i].Resolved = resolved
			}
		}
	}
	return pathcheck.Encode(entries)
}
