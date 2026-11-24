// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"

	"github.com/attention-span-ai/tego/internal/control/pathcheck"
	"github.com/attention-span-ai/tego/internal/guide"
)

type guideBinaryRequest struct{ PATH, Self, Version, Commit string }
type guideBinaryReply struct{ Exe, Build string }

func init() {
	pathcheck.Register("control.guide-binary", func(ctx context.Context, payload []byte) ([]byte, error) {
		var req guideBinaryRequest
		if err := pathcheck.Decode(payload, &req); err != nil {
			return nil, err
		}
		exe := tegoBinary(req.PATH, func() (string, error) { return req.Self, nil })
		reply := guideBinaryReply{Exe: exe}
		if exe != "" {
			reply.Build = guide.BuildIDOf(exe, req.Version, req.Commit)
		}
		return pathcheck.Encode(reply)
	})
}
func checkedGuideBinary(ctx context.Context, path, version, commit string) guideBinaryReply {
	self, _ := selfExecutable()
	var reply guideBinaryReply
	if err := pathcheck.Call(ctx, "control.guide-binary", guideBinaryRequest{path, self, version, commit}, &reply); err != nil {
		return guideBinaryReply{}
	}
	return reply
}
