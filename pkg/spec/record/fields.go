// SPDX-License-Identifier: Apache-2.0

package record

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// This file validates the fields of the reserved record revisions (minors 30 to 34): their
// grammars, their codes and the revision below which each is refused.

// The grammars of the reserved revisions' fields. Each is frozen with its revision: a line written at that revision holds
// exactly what these accept, whatever a later revision allows.
const (
	// StoppedByPattern is the grammar of the reserved run_end.stopped_by (minor 30).
	StoppedByPattern = `^(person:p-[0-9a-f]{16}|device:d-[0-9a-f]{16}|service:deploy-[a-z][a-z0-9-]{0,47})$`
	// DeploymentIDPattern is a deployment id: dep_ and 26 characters of the run id's base32-Crockford alphabet.
	DeploymentIDPattern = `^dep_[0-9a-hjkmnp-tv-z]{26}$`
	// DeploymentNamePattern is a deployment's name.
	DeploymentNamePattern = `^[a-z][a-z0-9-]{0,47}$`
	// SHA256HexPattern is a lowercase hex sha256.
	SHA256HexPattern = `^[0-9a-f]{64}$`
	// RunIDPattern is a run id (spec/identity/RUN-IDENTITY.md R2).
	RunIDPattern = `^r-[0-9a-f]{8}-[0-9a-z]{13}-[0-9a-z]{6}$`
	// SecretNamePattern is a secret's name.
	SecretNamePattern = `^[a-z0-9][a-z0-9_-]{0,63}$`
	// EnvNamePattern is an environment variable's name.
	EnvNamePattern = `^[A-Za-z_][A-Za-z0-9_]{0,255}$`
	// ShareNamePattern is a share's name.
	ShareNamePattern = `^[a-z0-9][a-z0-9_-]{0,63}$`
	// MaxSharePathBytes bounds a share's path (PATH_MAX).
	MaxSharePathBytes = 4096

	// MaxSecrets bounds run_start.secrets, MaxShares run_start.shares and MaxRedactions a line's redactions (two
	// versions of each of MaxSecrets secrets, a rotation's old and new). The reserved revisions' fields stay on their line whatever
	// their size (R10 never moves one to a blob, so Verify and every reader read what was checked), and at these bounds
	// a run_start holding every list at its longest still fits the ledger's line bound, 2 MiB.
	MaxSecrets    = 64
	MaxShares     = 64
	MaxRedactions = 2 * MaxSecrets
)

var (
	stoppedByRe  = regexp.MustCompile(StoppedByPattern)
	deploymentID = regexp.MustCompile(DeploymentIDPattern)
	deployName   = regexp.MustCompile(DeploymentNamePattern)
	sha256Hex    = regexp.MustCompile(SHA256HexPattern)
	runIDRe      = regexp.MustCompile(RunIDPattern)
	secretNameRe = regexp.MustCompile(SecretNamePattern)
	envNameRe    = regexp.MustCompile(EnvNamePattern)
	shareNameRe  = regexp.MustCompile(ShareNamePattern)

	deployTriggers = [...]string{DeployTriggerStart, DeployTriggerRestart, DeployTriggerCrashRestart, DeployTriggerBoot,
		DeployTriggerUpdate}
	changeClasses = [...]string{ChangeTighten, ChangeWiden, ChangeNeutral}
	vaultPeers    = [...]string{VaultPeerSameUID, VaultPeerSudo}
	vaultMemories = [...]string{VaultMemoryMemfdSecret, VaultMemoryMlock}
	shareModes    = [...]string{ShareModeRO, ShareModeAsk, ShareModeRW}
)

// The reserved fields' value sets, as detached copies. Editing one does not change validation.
var (
	DeployTriggers = slices.Clone(deployTriggers[:])
	ChangeClasses  = slices.Clone(changeClasses[:])
	VaultPeers     = slices.Clone(vaultPeers[:])
	VaultMemories  = slices.Clone(vaultMemories[:])
	ShareModes     = slices.Clone(shareModes[:])
)

// fieldCodes are the codes a FieldError carries, one per rule.
var fieldCodes = [...]string{
	"below-minor", "record-minor", "field-case",
	"stopped-by", "stopped-by-reason",
	"deployment", "deployment-id", "deployment-name", "deployment-revision", "deployment-revision-hash",
	"deployment-instance", "deployment-trigger", "deployment-previous-run", "deployment-change", "deployment-change-from",
	"deployment-change-class",
	"secrets", "secret-name", "secret-version", "secret-deliver", "secret-env", "secret-exposure", "secret-duplicate",
	"vault", "vault-peer", "vault-memory", "vault-secrets",
	"redactions", "redaction-secret", "redaction-version", "redaction-count", "redaction-duplicate",
	"shares", "share-name", "share-path", "share-mode", "share-duplicate",
	"live-block", "live-control",
	"credential", "mcp-tool",
	"live-mode", "live-fence",
	"model-route",
}

// FieldCodes lists every FieldError code. Editing it does not change validation.
var FieldCodes = slices.Clone(fieldCodes[:])

// FieldError is a refused field of a reserved revision: malformed, or in a ledger below its revision. It is
// an ErrInvalidEvent (errors.Is); Code names the rule (FieldCodes) and Field the key, as run_start.deployment.id. Why
// quotes any value it repeats, so a control byte in a line never reaches a terminal through the error.
type FieldError struct {
	Code  string
	Field string
	Why   string
}

func (e *FieldError) Error() string {
	return "record: invalid field " + e.Field + ": " + e.Why + " [" + e.Code + "]"
}

// Unwrap makes every FieldError an ErrInvalidEvent.
func (e *FieldError) Unwrap() error { return ErrInvalidEvent }

// FieldCode returns the code of the FieldError in err's chain, or "" when there is none.
func FieldCode(err error) string {
	var fe *FieldError
	if errors.As(err, &fe) {
		return fe.Code
	}
	return ""
}

func fieldErr(code, field, format string, args ...any) error {
	return &FieldError{Code: code, Field: field, Why: fmt.Sprintf(format, args...)}
}

// belowMinor refuses a field present in a ledger below the revision that added it.
func belowMinor(field string, present bool, minor, need int) error {
	if present && minor < need {
		return fieldErr("below-minor", field, "added at record_minor %d, the ledger is at %d", need, minor)
	}
	return nil
}

// ValidateFields checks run_start's reserved-revision blocks against p.RecordMinor, the ledger's revision: each block is
// refused below its revision [below-minor] and by its rule's code when malformed. The launcher runs it on its
// RunStartExtras before the run exists; Event.ValidateAt runs it on a decoded run_start. A list that is present and
// empty is refused, since a run with none has no list, and so is one longer than its bound (MaxSecrets, MaxShares).
func (p *RunStartPayload) ValidateFields() error {
	m := p.RecordMinor
	for _, b := range []struct {
		field   string
		present bool
		need    int
	}{
		{"run_start.deployment", p.Deployment != nil, MinorDeployment},
		{"run_start.secrets", p.Secrets != nil, MinorSecrets},
		{"run_start.vault", p.Vault != nil, MinorSecrets},
		{"run_start.shares", p.Shares != nil, MinorShares},
	} {
		if err := belowMinor(b.field, b.present, m, b.need); err != nil {
			return err
		}
	}
	if p.Deployment != nil {
		if err := p.Deployment.validate(); err != nil {
			return err
		}
	}
	if (p.Secrets != nil) != (p.Vault != nil) {
		return fieldErr("vault-secrets", "run_start.vault", "secrets and vault are written together (secrets %t, vault %t)",
			p.Secrets != nil, p.Vault != nil)
	}
	if p.Secrets != nil {
		if err := validateSecrets(p.Secrets); err != nil {
			return err
		}
		if err := p.Vault.validate(); err != nil {
			return err
		}
	}
	if p.Shares != nil {
		if err := validateShares(p.Shares); err != nil {
			return err
		}
	}
	return p.validateLiveMode()
}

func (d *Deployment) validate() error {
	const f = "run_start.deployment."
	switch {
	case !deploymentID.MatchString(d.ID):
		return fieldErr("deployment-id", f+"id", "%q is not %s", d.ID, DeploymentIDPattern)
	case !deployName.MatchString(d.Name):
		return fieldErr("deployment-name", f+"name", "%q is not %s", d.Name, DeploymentNamePattern)
	case d.Revision < 1:
		return fieldErr("deployment-revision", f+"revision", "%d is not 1 or more", d.Revision)
	case !sha256Hex.MatchString(d.RevisionHash):
		return fieldErr("deployment-revision-hash", f+"revision_hash", "%q is not a lowercase hex sha256", d.RevisionHash)
	case d.Instance < 1:
		return fieldErr("deployment-instance", f+"instance", "%d is not 1 or more", d.Instance)
	case !slices.Contains(deployTriggers[:], d.Trigger):
		return fieldErr("deployment-trigger", f+"trigger", "%q is not one of %q", d.Trigger, deployTriggers)
	case d.PreviousRun != "" && !runIDRe.MatchString(d.PreviousRun):
		return fieldErr("deployment-previous-run", f+"previous_run", "%q is not a run id", d.PreviousRun)
	}
	c := d.Change
	switch {
	case c == nil:
		return nil
	case d.Trigger != DeployTriggerUpdate:
		return fieldErr("deployment-change", f+"change", "written only with trigger %q, not %q", DeployTriggerUpdate, d.Trigger)
	case c.FromRevision < 1 || c.FromRevision == d.Revision:
		return fieldErr("deployment-change-from", f+"change.from_revision", "%d is not 1 or more and other than revision %d",
			c.FromRevision, d.Revision)
	case !slices.Contains(changeClasses[:], c.Class):
		return fieldErr("deployment-change-class", f+"change.class", "%q is not one of %q", c.Class, changeClasses)
	}
	return nil
}

func validateSecrets(ss []SecretUse) error {
	const f = "run_start.secrets"
	if len(ss) == 0 || len(ss) > MaxSecrets {
		return fieldErr("secrets", f, "a list of %d entries, not 1 to %d", len(ss), MaxSecrets)
	}
	names, envs := map[string]bool{}, map[string]bool{}
	for i, s := range ss {
		switch {
		case !secretNameRe.MatchString(s.Name):
			return fieldErr("secret-name", f+".name", "entry %d: %q is not %s", i, s.Name, SecretNamePattern)
		case s.Version < 1:
			return fieldErr("secret-version", f+".version", "entry %d: %d is not 1 or more", i, s.Version)
		case s.Deliver != SecretDeliverEnv:
			return fieldErr("secret-deliver", f+".deliver", "entry %d: %q is not %q", i, s.Deliver, SecretDeliverEnv)
		case !envNameRe.MatchString(s.Env):
			return fieldErr("secret-env", f+".env", "entry %d: %q is not %s", i, s.Env, EnvNamePattern)
		case s.Exposure != SecretExposureAgent:
			return fieldErr("secret-exposure", f+".exposure", "entry %d: %q is not %q", i, s.Exposure, SecretExposureAgent)
		case names[s.Name] || envs[s.Env]:
			return fieldErr("secret-duplicate", f, "entry %d: secret %q or variable %q is listed twice", i, s.Name, s.Env)
		}
		names[s.Name], envs[s.Env] = true, true
	}
	return nil
}

func (v *VaultUse) validate() error {
	switch {
	case !slices.Contains(vaultPeers[:], v.Peer):
		return fieldErr("vault-peer", "run_start.vault.peer", "%q is not one of %q", v.Peer, vaultPeers)
	case !slices.Contains(vaultMemories[:], v.Memory):
		return fieldErr("vault-memory", "run_start.vault.memory", "%q is not one of %q", v.Memory, vaultMemories)
	}
	return nil
}

func validateShares(ss []ShareUse) error {
	const f = "run_start.shares"
	if len(ss) == 0 || len(ss) > MaxShares {
		return fieldErr("shares", f, "a list of %d entries, not 1 to %d", len(ss), MaxShares)
	}
	names, paths := map[string]bool{}, map[string]bool{}
	for i, s := range ss {
		switch {
		case !shareNameRe.MatchString(s.Name):
			return fieldErr("share-name", f+".name", "entry %d: %q is not %s", i, s.Name, ShareNamePattern)
		case !cleanAbsPath(s.Path):
			return fieldErr("share-path", f+".path", "entry %d: %q is not a clean absolute path of at most %d bytes "+
				"of UTF-8 without a control character", i, s.Path, MaxSharePathBytes)
		case !slices.Contains(shareModes[:], s.Mode):
			return fieldErr("share-mode", f+".mode", "entry %d: %q is not one of %q", i, s.Mode, shareModes)
		case names[s.Name] || paths[s.Path]:
			return fieldErr("share-duplicate", f, "entry %d: share %q or path %q is listed twice", i, s.Name, s.Path)
		}
		names[s.Name], paths[s.Path] = true, true
	}
	return nil
}

// cleanAbsPath reports a path that is absolute, not /, and already clean (no ., .., // or trailing /), at most
// MaxSharePathBytes of valid UTF-8 with no C0 or C1 control character and no DEL.
func cleanAbsPath(p string) bool {
	if len(p) < 2 || len(p) > MaxSharePathBytes || p[0] != '/' || path.Clean(p) != p || !utf8.ValidString(p) {
		return false
	}
	return !strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r >= 0x7f && r < 0xa0 })
}

// ValidateFields checks run_end's stopped_by in a ledger at revision minor: refused below MinorStoppedBy
// [below-minor], when it is no principal reference [stopped-by], and on a run_end whose reason is not stopped
// [stopped-by-reason]. An empty StoppedBy is a run_end without the field.
func (p *RunEndPayload) ValidateFields(minor int) error {
	if p.StoppedBy == "" {
		return nil
	}
	const f = "run_end.stopped_by"
	if err := belowMinor(f, true, minor, MinorStoppedBy); err != nil {
		return err
	}
	if !stoppedByRe.MatchString(p.StoppedBy) {
		return fieldErr("stopped-by", f, "%q is not %s", p.StoppedBy, StoppedByPattern)
	}
	if p.Reason != RunEndStopped {
		return fieldErr("stopped-by-reason", f, "on a run_end whose reason is %q, not %q", p.Reason, RunEndStopped)
	}
	return nil
}

// ValidateRedactions checks a line's redactions in a ledger at revision minor: refused below MinorSecrets
// [below-minor], as an empty list or one longer than MaxRedactions [redactions], by each entry's rule, and when one
// secret version is listed twice [redaction-duplicate]. nil is a line with none.
func ValidateRedactions(rs []Redaction, minor int) error {
	if rs == nil {
		return nil
	}
	const f = RedactionsKey
	if err := belowMinor(f, true, minor, MinorSecrets); err != nil {
		return err
	}
	if len(rs) == 0 || len(rs) > MaxRedactions {
		return fieldErr("redactions", f, "a list of %d entries, not 1 to %d", len(rs), MaxRedactions)
	}
	type version struct {
		secret string
		n      int64
	}
	seen := map[version]bool{}
	for i, r := range rs {
		switch {
		case !secretNameRe.MatchString(r.Secret):
			return fieldErr("redaction-secret", f+".secret", "entry %d: %q is not %s", i, r.Secret, SecretNamePattern)
		case r.Version < 1:
			return fieldErr("redaction-version", f+".version", "entry %d: %d is not 1 or more", i, r.Version)
		case r.Count < 1:
			return fieldErr("redaction-count", f+".count", "entry %d: %d is not 1 or more", i, r.Count)
		case seen[version{r.Secret, r.Version}]:
			return fieldErr("redaction-duplicate", f, "entry %d: secret %q version %d is listed twice", i, r.Secret, r.Version)
		}
		seen[version{r.Secret, r.Version}] = true
	}
	return nil
}

// mvpKey is one payload key of a reserved revision and the kind whose payload holds it ("" for every kind).
type mvpKey struct {
	key  string
	kind Kind
}

var mvpKeys = [...]mvpKey{
	{"deployment", KindRunStart}, {"secrets", KindRunStart}, {"vault", KindRunStart}, {"shares", KindRunStart},
	{"stopped_by", KindRunEnd}, {RedactionsKey, ""},
	{"live_mode", KindRunStart}, {"live_fence", KindRunStart},
}

// IsMVPField reports whether key, a payload key of a line of kind k, is a field of a reserved revision, or a key a
// reader matching names without regard to case takes for one (foldEqual). The ledger's Writer never moves such a key
// to a blob (R10): the field stays on its line, where ValidateAt and Verify check it and every reader reads it, and its
// size is bounded here (MaxSecrets, MaxShares, MaxRedactions, MaxSharePathBytes) instead.
func IsMVPField(k Kind, key string) bool {
	for _, m := range mvpKeys {
		if (m.kind == "" || m.kind == k) && foldEqual(key, m.key) {
			return true
		}
	}
	return false
}

// ValidateAt applies Validate's rules and then those of the fields of the reserved record revisions (minors 30 to 34) to a line
// of a ledger at revision minor, the ledger's run_start record_minor; on a run_start, minor must be that line's own
// record_minor [record-minor]. Each field is read exactly, as a reader holding only the line would: a key, at the top
// level or inside a block, that a reader matching names without regard to case would take for a field but that is not
// spelt as the field is (foldEqual) [field-case], and a repeated key, a null anywhere, invalid UTF-8 or a value of the
// wrong JSON type inside a field, are refused by the code of the key they are under. Other unknown keys inside a block
// are ignored, as unknown payload keys are (docs/VERSIONING.md §2). A line with none of these fields passes exactly
// when Validate does. The ledger's Writer applies the same rules to each line it writes (MarshalLineAt) and Verify to
// each line it reads.
func (e *Event) ValidateAt(minor int) error {
	if err := e.Validate(); err != nil {
		return err
	}
	var fields []field
	if len(bytes.TrimSpace(e.Payload)) != 0 {
		var err error
		if fields, err = objectFields(e.Payload); err != nil {
			return fmt.Errorf("%w: payload: %w", ErrInvalidEvent, err)
		}
	}
	return e.validateMVP(minor, fields)
}

// RunStartMinor is the record_minor of e, a run_start: the revision of the ledger the line opens, which ValidateAt
// takes for every line of that ledger, and the Writer, its resume and Verify with it. It is read exactly, as
// runStartMinor says; a payload without the key is revision 0.
func (e *Event) RunStartMinor() (int, error) {
	if e.Kind != KindRunStart {
		return 0, fmt.Errorf("%w: a %s line has no record_minor", ErrInvalidEvent, e.Kind)
	}
	if len(bytes.TrimSpace(e.Payload)) == 0 {
		return 0, nil
	}
	fields, err := objectFields(e.Payload)
	if err != nil {
		return 0, fmt.Errorf("%w: payload: %w", ErrInvalidEvent, err)
	}
	return runStartMinor(fields)
}

// runStartMinor reads record_minor from a run_start's payload members exactly: the member spelt record_minor, written
// as a non-negative JSON integer with no sign, fraction or exponent, or 0 when there is none. A member a reader
// matching names without regard to case would take for it (foldEqual) is refused [field-case], since encoding/json
// takes the last of the copies and the line's sorted keys put them in another order on the disk than in the payload
// written; null and any other value are refused [record-minor].
func runStartMinor(fields []field) (int, error) {
	const key, f = "record_minor", "run_start.record_minor"
	var raw []byte
	for _, fl := range fields {
		switch {
		case fl.key == key:
			raw = fl.val
		case foldEqual(fl.key, key):
			return 0, fieldErr("field-case", f, "the key %q is not spelt %q", fl.key, key)
		}
	}
	if raw == nil {
		return 0, nil
	}
	if len(raw) > 1 && raw[0] == '0' || strings.TrimLeft(string(raw), "0123456789") != "" {
		return 0, fieldErr("record-minor", f, "%q is not a revision, a JSON integer of 0 or more", raw)
	}
	n, err := strconv.Atoi(string(raw))
	if err != nil {
		return 0, fieldErr("record-minor", f, "%q is not a revision: %v", raw, err)
	}
	return n, nil
}

// validateMVP is ValidateAt's check of the reserved revisions' fields, on e, already valid,
// and its payload's members fields. A line
// holding none of them allocates nothing here.
func (e *Event) validateMVP(minor int, fields []field) error {
	if err := validateLiveRule(e.Rule, minor); err != nil {
		return err
	}
	if e.Kind == KindGap {
		if err := validateLiveGap(minor, fields); err != nil {
			return err
		}
	}
	if err := e.validateCredMCP(minor, fields); err != nil {
		return err
	}
	if err := e.validateModelRoute(minor, fields); err != nil {
		return err
	}
	var raw map[string][]byte
	for _, fl := range fields {
		for _, k := range mvpKeys {
			switch {
			case k.kind != "" && k.kind != e.Kind:
			case fl.key == k.key:
				if raw == nil {
					raw = map[string][]byte{}
				}
				raw[k.key] = fl.val
			case foldEqual(fl.key, k.key):
				return fieldErr("field-case", string(e.Kind)+"."+k.key, "the key %q is not spelt %q", fl.key, k.key)
			}
		}
	}
	switch e.Kind {
	case KindRunStart:
		if err := validateRunStartAt(minor, fields, raw); err != nil {
			return err
		}
	case KindRunEnd:
		if b, ok := raw["stopped_by"]; ok {
			p := RunEndPayload{Reason: string(e.Reason)}
			if err := decodeField("run_end.stopped_by", b, &p.StoppedBy); err != nil {
				return err
			}
			if p.StoppedBy == "" {
				return fieldErr("stopped-by", "run_end.stopped_by", "an empty principal")
			}
			if err := p.ValidateFields(minor); err != nil {
				return err
			}
		}
	}
	b, ok := raw[RedactionsKey]
	if !ok {
		return nil
	}
	rs := []Redaction{}
	if err := decodeField(RedactionsKey, b, &rs); err != nil {
		return err
	}
	return ValidateRedactions(rs, minor)
}

func validateRunStartAt(minor int, fields []field, raw map[string][]byte) error {
	rm, err := runStartMinor(fields)
	if err != nil {
		return err
	}
	if rm != minor {
		return fieldErr("record-minor", "run_start.record_minor", "%d, read as the ledger's revision %d", rm, minor)
	}
	p := RunStartPayload{RecordMinor: minor}
	// A present list starts non-nil, so an empty one is refused rather than read as absent.
	if _, ok := raw["secrets"]; ok {
		p.Secrets = []SecretUse{}
	}
	if _, ok := raw["shares"]; ok {
		p.Shares = []ShareUse{}
	}
	for _, b := range []struct {
		key string
		v   any
	}{{"deployment", &p.Deployment}, {"secrets", &p.Secrets}, {"vault", &p.Vault}, {"shares", &p.Shares},
		{"live_mode", &p.LiveMode}, {"live_fence", &p.LiveFence}} {
		if v, ok := raw[b.key]; ok {
			if err := decodeField("run_start."+b.key, v, b.v); err != nil {
				return err
			}
		}
	}
	return p.ValidateFields()
}

// fieldKeyCodes maps a field's key path, array indices dropped, to the code a malformed value there is refused with.
var fieldKeyCodes = map[string]string{
	"run_end.stopped_by":                        "stopped-by",
	"run_start.deployment":                      "deployment",
	"run_start.deployment.id":                   "deployment-id",
	"run_start.deployment.name":                 "deployment-name",
	"run_start.deployment.revision":             "deployment-revision",
	"run_start.deployment.revision_hash":        "deployment-revision-hash",
	"run_start.deployment.instance":             "deployment-instance",
	"run_start.deployment.trigger":              "deployment-trigger",
	"run_start.deployment.previous_run":         "deployment-previous-run",
	"run_start.deployment.change":               "deployment-change",
	"run_start.deployment.change.from_revision": "deployment-change-from",
	"run_start.deployment.change.class":         "deployment-change-class",
	"run_start.secrets":                         "secrets",
	"run_start.secrets.name":                    "secret-name",
	"run_start.secrets.version":                 "secret-version",
	"run_start.secrets.deliver":                 "secret-deliver",
	"run_start.secrets.env":                     "secret-env",
	"run_start.secrets.exposure":                "secret-exposure",
	"run_start.vault":                           "vault",
	"run_start.vault.peer":                      "vault-peer",
	"run_start.vault.memory":                    "vault-memory",
	RedactionsKey:                               "redactions",
	RedactionsKey + ".secret":                   "redaction-secret",
	RedactionsKey + ".version":                  "redaction-version",
	RedactionsKey + ".count":                    "redaction-count",
	"run_start.shares":                          "shares",
	"run_start.shares.name":                     "share-name",
	"run_start.shares.path":                     "share-path",
	"run_start.shares.mode":                     "share-mode",
	"gap.live_block":                            "live-block",
	"gap.live_block.op":                         "live-block",
	"gap.live_block.kind":                       "live-block",
	"gap.live_block.value":                      "live-block",
	"gap.live_block.rule":                       "live-block",
	"gap.live_block.by":                         "live-block",
	"gap.live_block.serial":                     "live-block",
	"gap.live_block.at":                         "live-block",
	"gap.live_block.until":                      "live-block",
	"gap.live_block.refused":                    "live-block",
	"run_start.live_mode":                       "live-mode",
	"run_start.live_fence":                      "live-fence",
	"run_start.live_fence.sha256":               "live-fence",
	"run_start.live_fence.entries":              "live-fence",
	"run_start.live_fence.entries.kind":         "live-fence",
	"run_start.live_fence.entries.value":        "live-fence",
	"run_start.live_fence.entries.source":       "live-fence",
	"run_start.live_fence.entries.rule":         "live-fence",
	"run_start.live_fence.entries.name":         "live-fence",
	"gap.live_control":                          "live-control",
	"gap.live_control.op":                       "live-control",
	"gap.live_control.by":                       "live-control",
	"gap.live_control.serial":                   "live-control",
	"gap.live_control.at":                       "live-control",
	"net.credential":                            "credential",
	"net.credential.name":                       "credential",
	"net.credential.version":                    "credential",
	"gap.mcp_tool":                              "mcp-tool",
	"gap.mcp_tool.server":                       "mcp-tool",
	"gap.mcp_tool.tool":                         "mcp-tool",
	"gap.mcp_tool.decision":                     "mcp-tool",
	"gap.mcp_tool.by":                           "mcp-tool",
	"gap.mcp_tool.serial":                       "mcp-tool",
	"gap.mcp_tool.at":                           "mcp-tool",
	"ssl_request.route":                         "model-route",
	"ssl_request.route.name":                    "model-route",
	"ssl_request.route.authority":               "model-route",
	"net.route":                                 "model-route",
	"net.route.name":                            "model-route",
	"net.route.authority":                       "model-route",
	"gap.model_route":                           "model-route",
	"gap.model_route.model":                     "model-route",
	"gap.model_route.route":                     "model-route",
	"gap.model_route.authority":                 "model-route",
	"gap.model_route.by":                        "model-route",
	"gap.model_route.serial":                    "model-route",
	"gap.model_route.at":                        "model-route",
}

// codeAt is the code of the innermost known key on the path the JSON Pointer ptr leads to inside field, and that key.
func codeAt(field, ptr string) (code, at string) {
	at = field
	for seg := range strings.SplitSeq(strings.TrimPrefix(ptr, "/"), "/") {
		if seg == "" || strings.Trim(seg, "0123456789") == "" {
			continue // an array index
		}
		if _, ok := fieldKeyCodes[at+"."+seg]; !ok {
			break
		}
		at += "." + seg
	}
	return fieldKeyCodes[at], at
}

// fieldChildren maps a block's key path in fieldKeyCodes to its members' key paths.
var fieldChildren = func() map[string][]string {
	m := map[string][]string{}
	for k := range fieldKeyCodes {
		if i := strings.LastIndexByte(k, '.'); i > 0 {
			if _, ok := fieldKeyCodes[k[:i]]; ok {
				m[k[:i]] = append(m[k[:i]], k)
			}
		}
	}
	return m
}()

// foldEqual reports whether a reader that matches member names without regard to case takes a and b for one name:
// each rune folded to the least of its Unicode simple-fold orbit, as encoding/json does (so "revision_haſh" is
// "revision_hash"), and '_' and '-' dropped, as encoding/json/v2's case-insensitive matching does. A line holding such
// a variant of a field's name is refused rather than read two ways. It allocates nothing: the Writer runs it on every
// payload key of every line.
func foldEqual(a, b string) bool {
	for {
		var ra, rb rune
		ra, a = nextFolded(a)
		rb, b = nextFolded(b)
		if ra != rb {
			return false
		}
		if ra < 0 {
			return true
		}
	}
}

// nextFolded is s's first rune other than '_' and '-', folded (leastFold), and the rest of s after it; -1 at the end.
func nextFolded(s string) (rune, string) {
	for s != "" {
		r, n := utf8.DecodeRuneInString(s)
		s = s[n:]
		if r != '_' && r != '-' {
			return leastFold(r), s
		}
	}
	return -1, s
}

// leastFold is the least rune of r's simple-fold orbit.
func leastFold(r rune) rune {
	least := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		least = min(least, f)
	}
	return least
}

// memberName checks name, a member of the block at key path path ("" inside a member no field names), and returns
// the member's key path when the block names it as a field ("" otherwise).
func memberName(path, name string) (string, error) {
	if path == "" {
		return "", nil
	}
	if _, ok := fieldKeyCodes[path+"."+name]; ok {
		return path + "." + name, nil
	}
	for _, k := range fieldChildren[path] {
		if member := k[len(path)+1:]; foldEqual(name, member) {
			return "", fieldErr("field-case", k, "the key %q is not spelt %q", name, member)
		}
	}
	return "", nil
}

// decodeField reads one reserved field's JSON exactly into v: names matched with their case (encoding/json/v2), and a
// member whose name folds to a field of its block but is spelt otherwise [field-case], a repeated name, a null
// anywhere, invalid UTF-8 or a value of the wrong type refused, each by the code of the key it is under.
func decodeField(field string, raw []byte, v any) error {
	// One frame per open object or array: the key path its values are at ("" inside a member no field names), and,
	// for an object, whether the next token is a member name and the key path of the member that name opened.
	type frame struct {
		obj, name  bool
		path, next string
	}
	var stack []frame
	d := jsontext.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := d.ReadToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			var se *jsontext.SyntacticError
			ptr := ""
			if errors.As(err, &se) {
				ptr = string(se.JSONPointer)
			}
			code, at := codeAt(field, ptr)
			return fieldErr(code, at, "not well-formed I-JSON: %v", err)
		}
		if tok.Kind() == 'n' {
			code, at := codeAt(field, string(d.StackPointer()))
			return fieldErr(code, at, "null, which no field ValidateAt checks admits")
		}
		if k := tok.Kind(); k == '}' || k == ']' {
			stack = stack[:len(stack)-1]
			continue
		}
		path := field
		if n := len(stack); n > 0 {
			top := &stack[n-1]
			switch {
			case top.obj && top.name:
				top.name = false
				if top.next, err = memberName(top.path, tok.String()); err != nil {
					return err
				}
				continue
			case top.obj:
				path, top.name = top.next, true
			default:
				path = top.path
			}
		}
		switch tok.Kind() {
		case '{':
			stack = append(stack, frame{obj: true, name: true, path: path})
		case '[':
			stack = append(stack, frame{path: path})
		}
	}
	if err := jsonv2.Unmarshal(raw, v); err != nil {
		var se *jsonv2.SemanticError
		ptr := ""
		if errors.As(err, &se) {
			ptr = string(se.JSONPointer)
		}
		code, at := codeAt(field, ptr)
		return fieldErr(code, at, "a value of the wrong type: %v", err)
	}
	return nil
}
