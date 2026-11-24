// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"context"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

type callerContextKey struct{}

// WithCallerContext freezes process facts for all checks in one request.
func WithCallerContext(ctx context.Context) context.Context {
	if _, ok := ctx.Value(callerContextKey{}).(*config.CallerContext); ok {
		return ctx
	}
	c := config.CaptureCaller()
	return ContextWithCaller(ctx, c)
}

// CallerContext returns explicit caller facts. Outside a session the caller
// captures them once for this exchange. Workers always receive a framed value.
func CallerContext(ctx context.Context) *config.CallerContext {
	if c, ok := ctx.Value(callerContextKey{}).(*config.CallerContext); ok {
		return c
	}
	c := config.CaptureCaller()
	return &c
}

// ContextWithCaller carries an already selected caller value without consulting
// this process. It is used by callers that select a delegated offline context.
func ContextWithCaller(ctx context.Context, caller config.CallerContext) context.Context {
	return context.WithValue(ctx, callerContextKey{}, &caller)
}
