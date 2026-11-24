// SPDX-License-Identifier: Apache-2.0

package draftcompile

import (
	"context"
	"errors"

	"github.com/attention-span-ai/tego/internal/setup"
)

// Compose composes a preset draft in the same bounded child pool as compilation.
// setup.Compose probes write paths and project markers, so it must not run in
// the HTTP worker for client-provided paths. The public result retains the
// contract bytes and all metadata setup.Create needs; it creates no directory.
func Compose(ctx context.Context, o setup.Options) (*setup.Result, error) {
	result, err := Check(ctx, Request{ComposeOptions: &o})
	if err != nil {
		return nil, err
	}
	if result.Composition == nil {
		return nil, errors.New("draft composer returned no composition")
	}
	return result.Composition, nil
}

func composeRequest(o setup.Options) Result {
	result, err := setup.Compose(o)
	if err != nil {
		return Result{Error: err.Error()}
	}
	return Result{Composition: result}
}
