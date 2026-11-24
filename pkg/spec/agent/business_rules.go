// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/bizrule"
)

// BusinessRules pins one canonical business bundle and its intended worker.
// It is launch configuration, not evidence that the host provides the topology.
// ADR 0152 requires run-start checks before any worker or agent is released.
type BusinessRules struct {
	Version      int    `yaml:"version"`
	Topology     string `yaml:"topology"`
	WorkerDigest string `yaml:"worker_digest"`
	BundleSHA256 string `yaml:"bundle_sha256"`
	BundleJSON   string `yaml:"bundle_json"`
}

// BusinessRulesUnavailable is the current product capability, shared by launch
// and doctor. Never replace this refusal with the legacy in-run shim (A017).
const BusinessRulesUnavailable = "business rules unavailable: the root-owned trusted worker, exclusive route and durable admission owner are not implemented; this build refuses business-bearing runs on every tier"

type compiledBusinessRules struct {
	bundle       bizrule.Bundle
	workerDigest string
	topology     string
}

// BusinessRulesConfigured includes both source markers and compiled entries.
// Losing either half must not let a caller fall back to the legacy relay.
func (rt *RuleTable) BusinessRulesConfigured() bool {
	if rt == nil {
		return false
	}
	if len(rt.businessRules) != 0 {
		return true
	}
	if rt.Contract != nil {
		for _, s := range rt.Contract.MCP {
			if s.BusinessRules != nil {
				return true
			}
		}
	}
	return false
}

func businessBundleText(s string) (string, string) {
	if len(s) < 1 || len(s) > bizrule.MaxBundleBytes {
		return fmt.Sprintf("business bundle must contain 1..%d bytes", bizrule.MaxBundleBytes), "write canonical business v1 JSON with no trailing LF"
	}
	return "", ""
}

func businessDigestText(s string) (string, string) {
	if len(s) == 64 {
		ok := true
		for _, c := range []byte(s) {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				ok = false
				break
			}
		}
		if ok {
			return "", ""
		}
	}
	return "business digest must be 64 lowercase hexadecimal characters", "pin the SHA-256 of the canonical bundle or trusted worker manifest"
}

// decodeBusinessRules delegates all v1 validation to the frozen evaluator's
// decoder. Only after success may this layer inspect the runtime capability
// subset; it never duplicates or relaxes money predicates.
func decodeBusinessRules(server string, b *BusinessRules) (bizrule.Bundle, error) {
	if b == nil {
		return bizrule.Bundle{}, fmt.Errorf("business rules missing")
	}
	if b.Version != 1 || b.Topology != "trusted-stdio-worker-v1" {
		return bizrule.Bundle{}, fmt.Errorf("business rules require version 1 and topology trusted-stdio-worker-v1")
	}
	if msg, _ := businessDigestText(b.WorkerDigest); msg != "" {
		return bizrule.Bundle{}, fmt.Errorf("worker_digest: %s", msg)
	}
	if msg, _ := businessDigestText(b.BundleSHA256); msg != "" {
		return bizrule.Bundle{}, fmt.Errorf("bundle_sha256: %s", msg)
	}
	if msg, _ := businessBundleText(b.BundleJSON); msg != "" {
		return bizrule.Bundle{}, errors.New(msg)
	}
	bundle, err := bizrule.DecodeBundle([]byte(b.BundleJSON))
	if err != nil {
		return bizrule.Bundle{}, fmt.Errorf("business bundle: %w", err)
	}
	if bundle.Digest() != b.BundleSHA256 {
		return bizrule.Bundle{}, fmt.Errorf("business bundle digest does not match bundle_sha256")
	}
	var profile struct {
		Server string `json:"server"`
		Rules  []struct {
			Kind     string   `json:"kind"`
			Currency string   `json:"currency"`
			Codes    []string `json:"codes"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(bundle.Canonical(), &profile); err != nil {
		return bizrule.Bundle{}, fmt.Errorf("business capability profile: %w", err)
	}
	if profile.Server != server {
		return bizrule.Bundle{}, fmt.Errorf("business bundle server must equal mcp name %q", server)
	}
	var currencies, perCall int
	for _, rule := range profile.Rules {
		switch rule.Kind {
		case "currencies":
			currencies++
			if !slices.Equal(rule.Codes, []string{"USD"}) {
				return bizrule.Bundle{}, fmt.Errorf("slice 1 requires currencies exactly [USD]")
			}
		case "per_call":
			perCall++
			if rule.Currency != "USD" {
				return bizrule.Bundle{}, fmt.Errorf("slice 1 requires a USD per_call cap")
			}
		default:
			return bizrule.Bundle{}, fmt.Errorf("business rule kind %q is not supported in slice 1; cumulative caps and human approval remain unavailable", rule.Kind)
		}
	}
	if currencies != 1 || perCall != 1 {
		return bizrule.Bundle{}, fmt.Errorf("slice 1 requires exactly one USD currencies rule and one USD per_call cap")
	}
	return bundle, nil
}

func validateBusinessRules(ds *diags, c *Contract) {
	count := 0
	for i, s := range c.MCP {
		if s.BusinessRules == nil {
			continue
		}
		count++
		at := c.origins["mcp."+strconv.Itoa(i)+".business_rules"]
		if _, err := decodeBusinessRules(s.Name, s.BusinessRules); err != nil {
			ds.errorf(c.origins["mcp."+strconv.Itoa(i)+".business_rules.bundle_json"], CodeSchema, "mcp %q: %s", s.Name, err)
		}
		if s.Tools == nil {
			ds.errorf(at, CodeSchema, "mcp %q business_rules requires tools: for the relay", s.Name)
		}
		if s.Tools != nil && len(s.Tools.Ask) != 0 {
			ds.errorf(at, CodeSchema, "mcp %q business rules cannot discharge tools.ask; human approval is unavailable in slice 1", s.Name)
		}
		if s.URL != "" {
			ds.errorf(at, CodeSchema, "mcp %q business rules refuse HTTP; a trusted stdio worker is required", s.Name)
		}
		if !slices.Equal(s.Command, []string{"/opt/tego/workers/square/node", "/opt/tego/workers/square/server.js"}) {
			ds.errorf(at, CodeSchema, "mcp %q business rules require the pinned trusted-worker command [/opt/tego/workers/square/node, /opt/tego/workers/square/server.js]", s.Name)
		}
	}
	if count > 1 {
		ds.errorf(c.origins["mcp"], CodeSchema, "slice 1 accepts one business rule bundle per contract")
	}
}

func (k *compiler) businessRules() {
	// Compile revalidates exported contract fields: a caller can mutate them after
	// Load. Hashing that mutation must not turn malformed bytes into compiled pins.
	validateBusinessRules(&k.ds, k.c)
	for i, s := range k.c.MCP {
		if s.BusinessRules == nil {
			continue
		}
		b, err := decodeBusinessRules(s.Name, s.BusinessRules)
		if err != nil {
			continue
		} // the diagnostic above prevents returning a table
		if k.rt.businessRules == nil {
			k.rt.businessRules = make(map[string]compiledBusinessRules)
		}
		k.rt.businessRules[s.Name] = compiledBusinessRules{bundle: b, workerDigest: s.BusinessRules.WorkerDigest, topology: s.BusinessRules.Topology}
		k.ds.warnf(k.pos("mcp."+strconv.Itoa(i)+".business_rules"), CodeUnenforced, "%s", BusinessRulesUnavailable)
		if k.o.observe || k.rt.Tier != backend.TierBPFLSM || k.rt.Record != RecordFull {
			k.ds.errorf(k.pos("mcp."+strconv.Itoa(i)+".business_rules"), CodeSchema, "business rules require an enforcing bpflsm run and record: full; other tiers, record-only runs and incomplete recording cannot establish the root-owned admission owner")
		}
	}
}
