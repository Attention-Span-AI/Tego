// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"context"
	"time"
)

// helperOperations are fixed handlers registered by the binary's linked packages
// during initialization. Neither requests nor paths can select another program.
var helperOperations = map[string]func(context.Context, []byte) ([]byte, error){}

// RegisterHelperOperation registers a binary-private filesystem operation at init.
func RegisterHelperOperation(name string, handle func(context.Context, []byte) ([]byte, error)) {
	if _, exists := helperOperations[name]; exists {
		panic("duplicate filesystem helper operation: " + name)
	}
	helperOperations[name] = handle
}

// HelperExchange performs a registered operation in this binary's bounded helper.
func HelperExchange(ctx context.Context, operation string, payload []byte) ([]byte, error) {
	reply, err := requestCheck(ctx, checkRequest{Operation: operation, Payload: payload})
	return reply.Payload, err
}

// WithHelperDeadline preserves the worker's request-pipe lifetime while deriving
// an operation deadline. Err checks for a closed pipe synchronously, so a resumed
// filesystem read cannot miss cancellation merely because its watcher has not run.
// As with any context check, it cannot recall a write already submitted to the kernel.
func WithHelperDeadline(parent context.Context, deadline time.Time) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithDeadline(parent, deadline)
	lifetime, ok := parent.Value(helperLifetimeKey{}).(*helperLifetime)
	if !ok {
		return ctx, cancel
	}
	return helperDeadlineContext{Context: ctx, lifetime: lifetime, cancel: cancel}, cancel
}

type helperDeadlineContext struct {
	context.Context
	lifetime *helperLifetime
	cancel   context.CancelFunc
}

func (c helperDeadlineContext) Err() error {
	if err := c.Context.Err(); err != nil {
		return err
	}
	if c.lifetime.Err() != nil {
		// Close this context's Done before returning its error, preserving the
		// standard context contract even before parent propagation is scheduled.
		c.cancel()
	}
	return c.Context.Err()
}
