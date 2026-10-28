// SPDX-License-Identifier: Apache-2.0

package record

import (
	jsonv2 "encoding/json/v2"
	"regexp"
	"slices"
	"strings"
)

// The fields MinorCredentialsAndMCPTools adds (ADR 0126 §5).
const (
	credentialKey = "credential"
	mcpToolKey    = "mcp_tool"
)

// credentialNameRE is a credential's name rule (pkg/spec/agent's credentials: names, the vault's entries).
var credentialNameRE = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)

// credMCPReasons are the reasons added at MinorCredentialsAndMCPTools.
var credMCPReasons = [...]Reason{ReasonCredentialNotAllowed, ReasonCredentialRevoked, ReasonCredentialUnavailable,
	ReasonMCPToolDenied}

// mcpToolDecisions are MCPToolChange.Decision's values.
var mcpToolDecisions = [...]string{MCPToolAllow, MCPToolAsk, MCPToolDeny, MCPToolReset}

// credMCPRule reports whether rule is one MinorCredentialsAndMCPTools added: credential[<name>], or an mcp[<s>] rule
// of the relay (mcp[<s>].tools.*, mcp[<s>].live[...], mcp[<s>].relay).
func credMCPRule(rule string) bool {
	if strings.HasPrefix(rule, "credential[") {
		return true
	}
	if !strings.HasPrefix(rule, "mcp[") {
		return false
	}
	_, rest, ok := strings.Cut(rule, "].")
	return ok && (strings.HasPrefix(rest, "tools.") || strings.HasPrefix(rest, "live[") || rest == "relay")
}

// validateCredMCP is ValidateAt's check of the vault's and the MCP relay's fields (MinorCredentialsAndMCPTools), on e
// and its payload's members fields:
//   - below the revision, one of its four reasons, one of its rules, a credential, a why mcp-tool-changed or an
//     mcp_tool are refused [below-minor];
//   - credential is on a net line only, names a credential by its rule and, on an allowed line, a version of 1 or more
//     [credential];
//   - mcp_tool is on a gap what=enforce why mcp-tool-changed and only there, every such line has one, with a server,
//     a tool, a decision of allow, ask, deny or reset and a serial of 1 or more [mcp-tool];
//   - a member a case-insensitive reader would take for either but spelt otherwise is refused [field-case].
//
// by and at are not checked, for live_block's reason: the overlay's writer is the run's user.
func (e *Event) validateCredMCP(minor int, fields []field) error {
	if minor < MinorCredentialsAndMCPTools {
		if slices.Contains(credMCPReasons[:], e.Reason) {
			return fieldErr("below-minor", "reason", "%q is added at record_minor %d, the ledger is at %d", e.Reason,
				MinorCredentialsAndMCPTools, minor)
		}
		if credMCPRule(e.Rule) {
			return fieldErr("below-minor", "rule", "%q is added at record_minor %d, the ledger is at %d", e.Rule,
				MinorCredentialsAndMCPTools, minor)
		}
	}
	var cred, tool []byte
	var why, what string
	for _, fl := range fields {
		switch {
		case fl.key == credentialKey:
			cred = fl.val
		case fl.key == mcpToolKey:
			tool = fl.val
		case fl.key == "why":
			_ = jsonv2.Unmarshal(fl.val, &why) // not a string: "" matches no rule here
		case fl.key == "what":
			_ = jsonv2.Unmarshal(fl.val, &what) // as why
		case foldEqual(fl.key, credentialKey):
			return fieldErr("field-case", string(e.Kind)+"."+credentialKey, "the key %q is not spelt %q", fl.key, credentialKey)
		case foldEqual(fl.key, mcpToolKey):
			return fieldErr("field-case", string(e.Kind)+"."+mcpToolKey, "the key %q is not spelt %q", fl.key, mcpToolKey)
		}
	}
	if err := e.validateCredential(minor, cred); err != nil {
		return err
	}
	if e.Kind != KindGap {
		if tool != nil {
			return fieldErr("mcp-tool", string(e.Kind)+"."+mcpToolKey, "on a %s line, not a gap why %q", e.Kind, GapMCPToolChanged)
		}
		return nil
	}
	return validateMCPTool(minor, what, why, tool)
}

// validateCredential checks a line's credential, raw (nil when absent).
func (e *Event) validateCredential(minor int, raw []byte) error {
	if raw == nil {
		return nil
	}
	f := string(e.Kind) + "." + credentialKey
	if e.Kind != KindNet {
		return fieldErr("credential", f, "on a %s line: only a net line names a credential", e.Kind)
	}
	var c CredentialUse
	if err := decodeField(f, raw, &c); err != nil {
		return err
	}
	if err := belowMinor(f, true, minor, MinorCredentialsAndMCPTools); err != nil {
		return err
	}
	switch {
	case !credentialNameRE.MatchString(c.Name):
		return fieldErr("credential", f+".name", "%q is not a credential name (^[a-z0-9-]{1,40}$)", c.Name)
	case c.Version < 0:
		return fieldErr("credential", f+".version", "%d: a vault numbers its versions from 1", c.Version)
	case e.Verdict == VerdictAllow && c.Version < 1:
		return fieldErr("credential", f+".version", "%d on an allowed line: an injected value has a version from 1", c.Version)
	}
	return nil
}

// validateMCPTool checks a gap's mcp_tool, raw (nil when absent), against its what and why.
func validateMCPTool(minor int, what, why string, raw []byte) error {
	const f = "gap." + mcpToolKey
	if why == GapMCPToolChanged && minor < MinorCredentialsAndMCPTools {
		return fieldErr("below-minor", "gap.why", "why %q is added at record_minor %d, the ledger is at %d", why,
			MinorCredentialsAndMCPTools, minor)
	}
	if raw == nil {
		if why == GapMCPToolChanged {
			return fieldErr("mcp-tool", f, "a why %q line without %s", why, mcpToolKey)
		}
		return nil
	}
	var c MCPToolChange
	if err := decodeField(f, raw, &c); err != nil {
		return err
	}
	if err := belowMinor(f, true, minor, MinorCredentialsAndMCPTools); err != nil {
		return err
	}
	switch {
	case why != GapMCPToolChanged:
		return fieldErr("mcp-tool", f, "on a gap why %q, not %q", why, GapMCPToolChanged)
	case what != GapEnforce:
		return fieldErr("mcp-tool", f, "on a gap what %q, not %q", what, GapEnforce)
	case c.Server == "" || c.Tool == "":
		return fieldErr("mcp-tool", f, "names no server or no tool")
	case !slices.Contains(mcpToolDecisions[:], c.Decision):
		return fieldErr("mcp-tool", f+".decision", "%q is not one of %s", c.Decision, strings.Join(mcpToolDecisions[:], ", "))
	case c.Serial == 0:
		return fieldErr("mcp-tool", f+".serial", "0: an overlay numbers its changes from 1")
	}
	return nil
}
