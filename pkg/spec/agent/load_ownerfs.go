// SPDX-License-Identifier: Apache-2.0

package agent

import "github.com/attention-span-ai/tego/pkg/spec/config"

// ErrOwnerUnreliable is a rules file on a file system whose owner and permissions tego cannot rely on (ADR 0059,
// amended 2026-11-19): config.ReadRulesFile, the one function every rules file is read through, refuses it.
var ErrOwnerUnreliable = config.ErrOwnerUnreliable
