// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package cli

import (
	"errors"
	"os"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// envTestChainAnchor is internal/cli's EnvTestChainAnchor (anchor_testhook.go there): a binary built with
// -tags tegotesthooks verifies against the anchor its tests name, where the tego test build anchors, and with the
// variable unset it names none, so the dashboard checks nothing rather than read the developer's own
// ~/.tego/chain.log. A product build does not contain this file; AT_SECURE keeps the product's anchor.
const envTestChainAnchor = "TEGO_TEST_CHAIN_ANCHOR"

func init() {
	if secure, err := config.DetectSecureExec(); err != nil || secure {
		return
	}
	p := os.Getenv(envTestChainAnchor)
	anchorPath = func() (string, error) {
		if p == "" {
			return "", errors.New("this binary is built with tegotesthooks and " + envTestChainAnchor + " is not set")
		}
		return p, nil
	}
}
