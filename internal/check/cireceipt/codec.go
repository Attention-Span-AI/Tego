// SPDX-License-Identifier: Apache-2.0

package cireceipt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

var (
	hashPattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	objectIDPattern   = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	idPattern         = regexp.MustCompile(`^[1-9][0-9]*$`)
	releasePattern    = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
)

// shape is deliberately explicit: required/null/type rules cannot be lost in
// zero values when encoding/json fills a struct (ADR 0143).
type shape struct {
	kind     byte
	fields   map[string]shape
	elem     *shape
	optional bool
}

var (
	str         = shape{kind: 's'}
	integer     = shape{kind: 'i'}
	boolean     = shape{kind: 'b'}
	maybeString = shape{kind: '?'}
)

func obj(fields map[string]shape) shape { return shape{kind: 'o', fields: fields} }
func arr(elem shape) shape              { return shape{kind: 'a', elem: &elem} }

func provenanceShape(runners bool) shape {
	fields := map[string]shape{}
	for _, key := range strings.Fields("server_url repository repository_id repository_owner_id visibility source_sha source_ref workflow_ref workflow_sha job_workflow_ref job_workflow_sha event run_id run_attempt agent_job signing_job step matrix_key action_sha checkout_sha") {
		fields[key] = str
	}
	fields["pull_request_head_sha"] = maybeString
	if runners {
		runner := obj(map[string]shape{"environment": str, "image": str, "version": str, "arch": str})
		fields["agent_runner"], fields["signer_runner"] = runner, runner
	}
	return obj(fields)
}

func manifestShape() shape {
	digest := obj(map[string]shape{"file": str, "sha256": str})
	binary := obj(map[string]shape{"asset": str, "binary_sha256": str})
	return obj(map[string]shape{
		"schema":  str,
		"receipt": obj(map[string]shape{"file": str, "bytes": integer, "sha256": str}),
		"record":  obj(map[string]shape{"file": str, "run": str, "bytes": integer, "sha256": str, "lines": integer, "head": str, "ended": boolean}),
		"anchor":  digest, "teardown": digest, "signer_check": digest,
		"contract": obj(map[string]shape{"file": str, "file_sha256": str, "compiled_hash": str}),
		"tego":     obj(map[string]shape{"version": str, "commit": str, "checksums_sha256": str, "producer": binary, "signer": binary}),
		"artifact": obj(map[string]shape{"agent_id": str, "inventory_sha256": str}),
		"github":   provenanceShape(true),
	})
}

func expectShape() shape {
	return obj(map[string]shape{
		"schema": str, "github": provenanceShape(false),
		"tego":    obj(map[string]shape{"version": str, "commit": str}),
		"attempt": obj(map[string]shape{"started_at": str, "completed_at": str}),
	})
}

func decodeStrict(data []byte, limit int, s shape, out any) error {
	if len(data) > limit {
		return fmt.Errorf("JSON exceeds %d bytes", limit)
	}
	if !utf8.Valid(data) {
		return errors.New("JSON contains invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := readShape(d, s, "$", 0); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value or bytes")
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	return nil
}

func readShape(d *json.Decoder, s shape, path string, depth int) error {
	if depth > 32 {
		return fmt.Errorf("%s: JSON nesting exceeds 32", path)
	}
	tok, err := d.Token()
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	bad := func() error { return fmt.Errorf("%s: wrong JSON type", path) }
	switch s.kind {
	case 's':
		if _, ok := tok.(string); !ok {
			return bad()
		}
	case '?':
		if tok != nil {
			if _, ok := tok.(string); !ok {
				return bad()
			}
		}
	case 'b':
		if _, ok := tok.(bool); !ok {
			return bad()
		}
	case 'i':
		n, ok := tok.(json.Number)
		if !ok {
			return bad()
		}
		if _, err := strconv.ParseUint(n.String(), 10, 63); err != nil {
			return fmt.Errorf("%s: expected an exact nonnegative integer", path)
		}
	case 'o':
		if tok != json.Delim('{') {
			return bad()
		}
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return bad()
			}
			if seen[name] {
				return fmt.Errorf("%s.%s: duplicate key", path, name)
			}
			seen[name] = true
			child, ok := s.fields[name]
			if !ok {
				return fmt.Errorf("%s.%s: unknown key", path, name)
			}
			if err := readShape(d, child, path+"."+name, depth+1); err != nil {
				return err
			}
		}
		for key, field := range s.fields {
			if !seen[key] && !field.optional {
				return fmt.Errorf("%s.%s: missing key", path, key)
			}
		}
		if close, err := d.Token(); err != nil || close != json.Delim('}') {
			return bad()
		}
	case 'a':
		if tok != json.Delim('[') {
			return bad()
		}
		for i := 0; d.More(); i++ {
			if err := readShape(d, *s.elem, fmt.Sprintf("%s[%d]", path, i), depth+1); err != nil {
				return err
			}
		}
		if close, err := d.Token(); err != nil || close != json.Delim(']') {
			return bad()
		}
	default:
		return fmt.Errorf("%s: unsupported decoder shape", path)
	}
	return nil
}

// DecodeManifest refuses unknown/duplicate/missing/null/wrong-type fields,
// unsupported versions, unsafe filenames and malformed provenance.
func DecodeManifest(data []byte) (Manifest, error) {
	var m Manifest
	if err := decodeStrict(data, MaxManifestBytes, manifestShape(), &m); err != nil {
		return m, err
	}
	if m.Schema != ManifestSchema {
		return m, fmt.Errorf("unsupported manifest schema %q", m.Schema)
	}
	for _, pair := range [][2]string{{m.Receipt.File, "receipt.json"}, {m.Record.File, "run/events.jsonl"}, {m.Anchor.File, "anchor-line.txt"}, {m.Contract.File, "contract.yaml"}, {m.Teardown.File, "run-status.json"}, {m.SignerCheck.File, "signer-check.json"}} {
		if pair[0] != pair[1] {
			return m, fmt.Errorf("file must be exactly %s", pair[1])
		}
	}
	for key, hash := range map[string]string{"receipt.sha256": m.Receipt.SHA256, "record.sha256": m.Record.SHA256, "record.head": m.Record.Head, "anchor.sha256": m.Anchor.SHA256, "contract.file_sha256": m.Contract.FileSHA256, "contract.compiled_hash": m.Contract.CompiledHash, "teardown.sha256": m.Teardown.SHA256, "signer_check.sha256": m.SignerCheck.SHA256, "tego.checksums_sha256": m.Tego.ChecksumsSHA256, "tego.producer.binary_sha256": m.Tego.Producer.SHA256, "tego.signer.binary_sha256": m.Tego.Signer.SHA256, "artifact.inventory_sha256": m.Artifact.InventorySHA256} {
		if !hashPattern.MatchString(hash) {
			return m, fmt.Errorf("%s: expected lowercase SHA-256", key)
		}
	}
	if !identity.RunID(m.Record.Run).Valid() {
		return m, errors.New("record.run: invalid run id")
	}
	if !idPattern.MatchString(m.Artifact.AgentID) {
		return m, errors.New("artifact.agent_id: expected positive decimal string")
	}
	if err := validRelease(m.Tego.Version, m.Tego.Commit); err != nil {
		return m, err
	}
	if !validAsset(m.Tego.Producer.Asset, m.Tego.Version) || !validAsset(m.Tego.Signer.Asset, m.Tego.Version) {
		return m, errors.New("tego assets must name this release's Linux amd64 or arm64 tego executable")
	}
	if err := validProvenance(m.GitHub.Provenance); err != nil {
		return m, err
	}
	for name, runner := range map[string]Runner{"agent_runner": m.GitHub.AgentRunner, "signer_runner": m.GitHub.SignerRunner} {
		if runner.Environment != "github-hosted" || !clean(runner.Image) || !clean(runner.Version) || (runner.Arch != "X64" && runner.Arch != "ARM64") {
			return m, fmt.Errorf("github.%s: require well-formed GitHub-hosted runner metadata", name)
		}
	}
	if m.GitHub.SignerRunner.Arch != "X64" {
		return m, errors.New("github.signer_runner.arch must be X64")
	}
	return m, nil
}

// DecodeExpect reads exact independent expectations, including the attempt window.
func DecodeExpect(data []byte) (Expect, error) {
	var e Expect
	if err := decodeStrict(data, MaxManifestBytes, expectShape(), &e); err != nil {
		return e, err
	}
	if e.Schema != ExpectSchema {
		return e, fmt.Errorf("unsupported expectation schema %q", e.Schema)
	}
	if err := validProvenance(e.GitHub); err != nil {
		return e, err
	}
	if err := validRelease(e.Tego.Version, e.Tego.Commit); err != nil {
		return e, err
	}
	start, err := utc(e.Attempt.StartedAt)
	if err != nil {
		return e, fmt.Errorf("attempt.started_at: %w", err)
	}
	end, err := utc(e.Attempt.CompletedAt)
	if err != nil {
		return e, fmt.Errorf("attempt.completed_at: %w", err)
	}
	if end.Before(start) {
		return e, errors.New("attempt.completed_at precedes started_at")
	}
	return e, nil
}

func utc(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || !strings.HasSuffix(s, "Z") {
		return time.Time{}, errors.New("expected RFC3339 UTC with Z")
	}
	return t, nil
}

func validRelease(version, commit string) error {
	if !releasePattern.MatchString(version) || !objectIDPattern.MatchString(commit) {
		return errors.New("tego version/commit must name an exact release and full repository object id")
	}
	return nil
}

func validAsset(asset, version string) bool {
	prefix := "tego_" + strings.TrimPrefix(version, "v") + "_linux_"
	return asset == prefix+"amd64" || asset == prefix+"arm64"
}

func clean(s string) bool {
	if s == "" || len(s) > 4096 {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validProvenance(g Provenance) error {
	if g.ServerURL != "https://github.com" || !repositoryPattern.MatchString(g.Repository) {
		return errors.New("github server/repository is malformed")
	}
	for key, value := range map[string]string{"repository_id": g.RepositoryID, "repository_owner_id": g.RepositoryOwnerID, "run_id": g.RunID, "run_attempt": g.RunAttempt} {
		if !idPattern.MatchString(value) {
			return fmt.Errorf("github.%s: expected positive decimal string", key)
		}
	}
	for key, value := range map[string]string{"source_sha": g.SourceSHA, "workflow_sha": g.WorkflowSHA, "job_workflow_sha": g.JobWorkflowSHA, "action_sha": g.ActionSHA, "checkout_sha": g.CheckoutSHA} {
		if !objectIDPattern.MatchString(value) {
			return fmt.Errorf("github.%s: expected full repository object id", key)
		}
	}
	if g.CheckoutSHA != g.SourceSHA {
		return errors.New("github.checkout_sha differs from source_sha")
	}
	if g.Visibility != "public" && g.Visibility != "private" && g.Visibility != "internal" {
		return errors.New("github.visibility is unknown")
	}
	if g.AgentJob != "agent" || g.SigningJob != "sign" || g.Step != "collect" {
		return errors.New("github job/step identifiers differ from pinned configuration")
	}
	if !clean(g.SourceRef) || !strings.HasPrefix(g.SourceRef, "refs/") || len(g.SourceRef) == len("refs/") || !clean(g.MatrixKey) {
		return errors.New("github source_ref/matrix_key malformed")
	}
	if !validWorkflowRef(g.WorkflowRef) || !validWorkflowRef(g.JobWorkflowRef) {
		return errors.New("github workflow references must be exact repository workflow paths at a ref")
	}
	if !strings.HasPrefix(g.WorkflowRef, g.Repository+"/.github/workflows/") {
		return errors.New("caller workflow belongs to another repository")
	}
	switch g.Event {
	case "push", "schedule", "workflow_dispatch":
		if g.PullRequestHeadSHA != nil {
			return errors.New("github.pull_request_head_sha must be null outside pull_request")
		}
	case "pull_request":
		if g.PullRequestHeadSHA == nil || !objectIDPattern.MatchString(*g.PullRequestHeadSHA) {
			return errors.New("github.pull_request_head_sha required for pull_request")
		}
	default:
		return errors.New("github.event is not eligible")
	}
	return nil
}

func validWorkflowRef(s string) bool {
	if !clean(s) || strings.ContainsAny(s, "\\?#") || strings.Count(s, "@") != 1 {
		return false
	}
	at := strings.LastIndexByte(s, '@')
	if at < 1 || at == len(s)-1 {
		return false
	}
	parts := strings.Split(s[:at], "/")
	if len(parts) != 5 || parts[2] != ".github" || parts[3] != "workflows" || !repositoryPattern.MatchString(strings.Join(parts[:2], "/")) {
		return false
	}
	return (strings.HasSuffix(parts[4], ".yml") || strings.HasSuffix(parts[4], ".yaml")) && !strings.Contains(parts[4], "..")
}
