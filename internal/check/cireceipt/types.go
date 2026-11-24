// SPDX-License-Identifier: Apache-2.0

package cireceipt

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const (
	// ManifestSchema identifies the complete CI evidence manifest.
	ManifestSchema = "tego.ci-receipt/1"
	// ExpectSchema identifies independent CI provenance expectations.
	ExpectSchema = "tego.ci-expect/1"
	// ResultSchema identifies the verification result.
	ResultSchema = "tego.ci-verify/1"
	// MaxManifestBytes bounds both manifest and expectation input.
	MaxManifestBytes = 64 << 10
)

// File identifies exact retained bytes, including their relative filename.
type File struct {
	File   string `json:"file"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// DigestFile identifies a retained file that has no separate size assertion.
type DigestFile struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

// Record identifies every complete line and byte of one ended run.
type Record struct {
	File   string `json:"file"`
	Run    string `json:"run"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	Lines  uint64 `json:"lines"`
	Head   string `json:"head"`
	Ended  bool   `json:"ended"`
}

// Contract keeps the YAML byte digest separate from the compiled hash.
type Contract struct {
	File         string `json:"file"`
	FileSHA256   string `json:"file_sha256"`
	CompiledHash string `json:"compiled_hash"`
}

// Binary identifies one named Linux release asset, independently of its architecture.
type Binary struct {
	Asset  string `json:"asset"`
	SHA256 string `json:"binary_sha256"`
}

// Tego identifies the release and the independently installed executables.
type Tego struct {
	Version         string `json:"version"`
	Commit          string `json:"commit"`
	ChecksumsSHA256 string `json:"checksums_sha256"`
	Producer        Binary `json:"producer"`
	Signer          Binary `json:"signer"`
}

// Artifact identifies the agent job's artifact and sorted inventory.
type Artifact struct {
	AgentID         string `json:"agent_id"`
	InventorySHA256 string `json:"inventory_sha256"`
}

// Provenance names the exact independent repository, workflows, jobs and attempt.
type Provenance struct {
	ServerURL          string  `json:"server_url"`
	Repository         string  `json:"repository"`
	RepositoryID       string  `json:"repository_id"`
	RepositoryOwnerID  string  `json:"repository_owner_id"`
	Visibility         string  `json:"visibility"`
	SourceSHA          string  `json:"source_sha"`
	SourceRef          string  `json:"source_ref"`
	WorkflowRef        string  `json:"workflow_ref"`
	WorkflowSHA        string  `json:"workflow_sha"`
	JobWorkflowRef     string  `json:"job_workflow_ref"`
	JobWorkflowSHA     string  `json:"job_workflow_sha"`
	Event              string  `json:"event"`
	RunID              string  `json:"run_id"`
	RunAttempt         string  `json:"run_attempt"`
	AgentJob           string  `json:"agent_job"`
	SigningJob         string  `json:"signing_job"`
	Step               string  `json:"step"`
	MatrixKey          string  `json:"matrix_key"`
	ActionSHA          string  `json:"action_sha"`
	CheckoutSHA        string  `json:"checkout_sha"`
	PullRequestHeadSHA *string `json:"pull_request_head_sha"`
}

// Runner is workflow/API metadata, not a certificate claim about an image.
type Runner struct {
	Environment string `json:"environment"`
	Image       string `json:"image"`
	Version     string `json:"version"`
	Arch        string `json:"arch"`
}

// GitHub adds the two distinct runners to provenance.
type GitHub struct {
	Provenance
	AgentRunner  Runner `json:"agent_runner"`
	SignerRunner Runner `json:"signer_runner"`
}

// Manifest has exactly the fields in ADR 0143's complete required shape.
type Manifest struct {
	Schema      string     `json:"schema"`
	Receipt     File       `json:"receipt"`
	Record      Record     `json:"record"`
	Anchor      DigestFile `json:"anchor"`
	Contract    Contract   `json:"contract"`
	Teardown    DigestFile `json:"teardown"`
	SignerCheck DigestFile `json:"signer_check"`
	Tego        Tego       `json:"tego"`
	Artifact    Artifact   `json:"artifact"`
	GitHub      GitHub     `json:"github"`
}

// ReleaseIdentity is the exact release the independent expectations require.
type ReleaseIdentity struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// Attempt is an independent exact-attempt time window, in UTC.
type Attempt struct {
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at"`
}

// Expect comes from trusted configuration and exact-attempt metadata, never evidence.
type Expect struct {
	Schema  string          `json:"schema"`
	GitHub  Provenance      `json:"github"`
	Tego    ReleaseIdentity `json:"tego"`
	Attempt Attempt         `json:"attempt"`
}

// Release supplies independently authenticated checksums. Verify does not obtain
// trust from a file in the evidence directory or authenticate these bytes itself.
type Release struct {
	Version   string
	Commit    string
	Checksums []byte
}

// Input supplies evidence and independent trust separately. ScratchDir is a
// caller-owned directory for private copies; it must not be inside Directory.
type Input struct {
	Directory   string
	Expectation []byte
	Release     Release
	Checker     Binary
	By          receipt.MadeBy
	ScratchDir  string
	Bundles     BundleVerifier
}

// Check states which statement a single comparison supports.
type Check struct {
	Name      string `json:"name"`
	Result    string `json:"result"`
	Statement string `json:"statement"`
	Why       string `json:"why"`
}

// BundleInput contains only the exact private copies used for all other checks.
// Implementations must check both blobs against independent trust and all fields
// in BundleChecks, using the exact immutable bundle they authenticated.
type BundleInput struct {
	Manifest       []byte
	Receipt        []byte
	ManifestBundle []byte
	ReceiptBundle  []byte
	Expect         Expect
}

// BundleResult reports complete bundle/certificate checks and the two verified
// transparency integration times. Missing checks never count as a pass.
type BundleResult struct {
	Checks          []Check
	IntegratedTimes []time.Time
}

// BundleVerifier authenticates blobs and certified identities. CosignVerifier
// supplies the production implementation using independent tool and root trust.
type BundleVerifier interface {
	Verify(context.Context, BundleInput) (BundleResult, error)
}

// BundleChecks names every mandatory check, once for each blob. Certificate
// extension parsing belongs to the BundleVerifier and may not be skipped.
func BundleChecks() []string {
	var names []string
	for _, blob := range []string{"receipt", "manifest"} {
		for _, field := range []string{"blob", "trusted-roots", "inclusion", "certificate-validity", "issuer", "signer-uri", "signer-digest", "runner", "source-uri", "source-digest", "source-ref", "repository-id", "owner-id", "config-uri", "config-digest", "trigger", "invocation", "visibility", "san", "legacy-consistency"} {
			names = append(names, blob+"."+field)
		}
	}
	return names
}

// Result distinguishes consistency from the still required bundle checks.
type Result struct {
	Schema            string      `json:"schema"`
	Result            string      `json:"result"`
	SignerURI         string      `json:"signer_uri"`
	SignerDigest      string      `json:"signer_digest"`
	CallerURI         string      `json:"caller_uri"`
	CallerDigest      string      `json:"caller_digest"`
	Repository        string      `json:"repository"`
	RepositoryID      string      `json:"repository_id"`
	RepositoryOwnerID string      `json:"repository_owner_id"`
	SourceSHA         string      `json:"source_sha"`
	RunID             string      `json:"run_id"`
	RunAttempt        string      `json:"run_attempt"`
	Trigger           string      `json:"trigger"`
	RunnerEnvironment string      `json:"runner_environment"`
	IntegratedTimes   []time.Time `json:"integrated_times"`
	ReceiptSHA256     string      `json:"receipt_sha256"`
	Ended             bool        `json:"ended"`
	CoverageComplete  bool        `json:"coverage_complete"`
	RunFacts          *RunFacts   `json:"run_facts"`
	Checks            []Check     `json:"checks"`
	NotCompared       []string    `json:"not_compared"`
	Limits            []string    `json:"limits"`
}

// RunFacts discloses record assertions the compiled YAML hash does not capture.
type RunFacts struct {
	EffectiveHash          string                `json:"effective_hash,omitempty"`
	BaselineSHA256         string                `json:"baseline_sha256,omitempty"`
	BaselineEvidenceSHA256 string                `json:"baseline_evidence_sha256,omitempty"`
	Tier                   string                `json:"tier"`
	Capabilities           map[string]bool       `json:"capabilities"`
	BestEffort             []string              `json:"best_effort"`
	ReadsNotified          *record.ReadsNotified `json:"reads_notified"`
	RuntimeGrants          []string              `json:"runtime_grants"`
	RunCommandGrant        string                `json:"run_command_grant"`
}

// ExitCode follows the receipt convention: mismatch 1, uncertainty 125, full match 0.
func (r *Result) ExitCode() int {
	switch r.Result {
	case "match":
		return identity.ExitOK
	case "mismatch":
		return identity.ExitFinding
	default:
		return identity.ExitError
	}
}

// JSON writes the versioned machine-readable result.
func (r *Result) JSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Text prints the independent identities and the statement each check supports.
func (r *Result) Text(w io.Writer) error {
	var b strings.Builder
	if !r.CoverageComplete {
		b.WriteString("Incomplete: complete coverage has not been established.\n")
	}
	if r.Result == "match" {
		b.WriteString("CI receipt: full ended match.\n")
	} else {
		fmt.Fprintf(&b, "CI receipt: %s.\n", record.Printable(r.Result))
		b.WriteString("Expected (not established):\n")
	}
	fmt.Fprintf(&b, "Workflow: %s at %s\nCaller: %s at %s\nRepository: %s (id %s, owner %s)\nSource: %s\nRun: %s attempt %s, trigger %s, runner %s\nReceipt SHA-256: %s\n",
		record.Printable(r.SignerURI), record.Printable(r.SignerDigest), record.Printable(r.CallerURI), record.Printable(r.CallerDigest), record.Printable(r.Repository), record.Printable(r.RepositoryID), record.Printable(r.RepositoryOwnerID), record.Printable(r.SourceSHA), record.Printable(r.RunID), record.Printable(r.RunAttempt), record.Printable(r.Trigger), record.Printable(r.RunnerEnvironment), r.ReceiptSHA256)
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "  %s %s: %s; %s\n", record.Printable(c.Name), record.Printable(c.Result), record.Printable(c.Statement), record.Printable(c.Why))
	}
	for _, l := range r.Limits {
		fmt.Fprintf(&b, "Limit: %s\n", l)
	}
	_, err := io.WriteString(w, b.String())
	return err
}
