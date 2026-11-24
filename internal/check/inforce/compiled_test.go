// SPDX-License-Identifier: Apache-2.0

package inforce

import (
	"github.com/attention-span-ai/tego/internal/check/compiledview"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

var (
	ruleKey         = compiledview.RuleKey
	fromSource      = compiledview.FromSource
	stateOf         = compiledview.StateOf
	programSentence = compiledview.ProgramSentence
	limitSentence   = compiledview.LimitSentence
	pathSentence    = compiledview.PathSentence
	short           = compiledview.Short
)

const (
	textAskReadTier         = compiledview.TextAskReadTier
	textBestEffort          = compiledview.TextBestEffort
	textDatagram            = compiledview.TextDatagram
	textEnvRemoved          = compiledview.TextEnvRemoved
	textExecAskReserved     = compiledview.TextExecAskReserved
	textExecAskReservedBest = compiledview.TextExecAskReservedBest
	textGate                = compiledview.TextGate
	textHeld                = compiledview.TextHeld
	textHeldBest            = compiledview.TextHeldBest
	textKernel              = compiledview.TextKernel
	textObserve             = compiledview.TextObserve
	textShadowed            = compiledview.TextShadowed
	textTegoCommands        = compiledview.TextTegoCommands
	textTegoConnect         = compiledview.TextTegoConnect
	textTegoRead            = compiledview.TextTegoRead
	textTegoRequest         = compiledview.TextTegoRequest
)

const (
	kExecAllow  = "exec.allow"
	kNetHTTP    = "net.http"
	kNetIngress = "net.ingress"
)

func newExecNames(rt *agent.RuleTable) struct{ byFile map[string][]int } {
	return struct{ byFile map[string][]int }{compiledview.NewExecNames(rt).ByFile}
}
