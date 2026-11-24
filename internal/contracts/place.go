// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"context"
	"errors"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

var walkPath = agent.WalkedPath

// PlacePath preserves the kernel walk before a CLI selector is cleaned. The
// walk runs in its own process because it can reach an unanswered mount.
func PlacePath(ctx context.Context, path string) (string, error) {
	placed, err := requestCheck(ctx, checkRequest{Operation: "place", Path: path})
	if err != nil {
		return "", err
	}
	if !placed.OK {
		return "", CheckUnavailable(errors.New("cannot place that path"))
	}
	return placed.Path, nil
}
