// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"

	"github.com/attention-span-ai/tego/pkg/policy/httppolicy"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

type httpPolicySource interface{ HTTPPolicyReady(*httppolicy.Policy) bool }
type proxyPolicySource interface {
	ProxyPolicyReady(*agent.CompiledProxyPolicy) bool
}

func (r *runner) httpPolicyReady() bool {
	if r.rt == nil || r.rt.HTTP == nil || r.rt.Capture != agent.CaptureForwarder || r.deps.Enforce.Tier() == backend.TierObserve {
		return false
	}
	for _, s := range r.sources {
		if s.Name() == string(agent.CaptureForwarder) {
			if hs, ok := s.(httpPolicySource); ok && hs.HTTPPolicyReady(r.rt.HTTP) {
				return true
			}
		}
	}
	return false
}

func (r *runner) requireHTTPPolicy() error {
	if r.rt.HTTP != nil && !r.httpPolicyReady() {
		return fmt.Errorf("runtime: net.http requires its policy-bearing forwarder to be running")
	}
	if r.rt.Proxy != nil {
		if err := r.rt.Proxy.ValidateLimits(r.rt.Limits); err != nil {
			return fmt.Errorf("runtime: %w", err)
		}
		ready := false
		if r.rt.Capture == agent.CaptureForwarder && r.deps.Enforce.Tier() != backend.TierObserve {
			for _, s := range r.sources {
				if ps, ok := s.(proxyPolicySource); s.Name() == string(agent.CaptureForwarder) && ok && ps.ProxyPolicyReady(r.rt.Proxy) {
					ready = true
				}
			}
		}
		if !ready {
			return fmt.Errorf("runtime: net.proxy requires its policy-bearing forwarder to be running")
		}
	}
	return nil
}
