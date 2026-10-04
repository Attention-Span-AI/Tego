// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"

	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
)

type continuedBindNamer interface {
	SetContinuedBind(func(tid, pid int, startNS, at uint64) (supervisor.BindNaming, bool))
	SetBindResults(bool)
	BindHandoverReady() bool
}

type continuedListenNamer interface {
	SetContinuedListen(func(tid, pid int, startNS, at uint64) (supervisor.ListenNaming, bool))
	SetListenResults(bool)
	ListenHandoverReady() bool
}

func (r *runner) superviseKernelListeners(loop *supervisor.Loop) {
	if recorder, ok := r.kernelRecord.(continuedBindNamer); ok {
		recorder.SetContinuedBind(loop.ContinuedBind)
		proof, ok := r.handle.(interface{ BindOutcomes() bool })
		recorder.SetBindResults(ok && proof.BindOutcomes() && r.planeDecides())
	}
	if recorder, ok := r.kernelRecord.(continuedListenNamer); ok {
		recorder.SetContinuedListen(loop.ContinuedListen)
		proof, ok := r.handle.(interface{ ListenOutcomes() bool })
		recorder.SetListenResults(ok && proof.ListenOutcomes() && r.planeDecides())
	}
}

func (r *runner) kernelBindHandoff(ctx context.Context) func() bool {
	reading := r.kernelConnects(ctx)
	return func() bool {
		recorder, ok := r.kernelRecord.(continuedBindNamer)
		return ok && recorder.BindHandoverReady() && reading()
	}
}

func (r *runner) kernelListenHandoff(ctx context.Context) func() bool {
	reading := r.kernelConnects(ctx)
	return func() bool {
		recorder, ok := r.kernelRecord.(continuedListenNamer)
		return ok && recorder.ListenHandoverReady() && reading()
	}
}
