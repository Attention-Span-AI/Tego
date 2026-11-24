// SPDX-License-Identifier: Apache-2.0

package cireceipt

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil/jsonschema"
	"github.com/attention-span-ai/tego/pkg/spec/runstatus"
)

// Every required key is exercised at its actual nesting path, including object
// fields. Zero values and null must not silently stand in for missing evidence.
func TestManifestAndExpectRequireEveryField(t *testing.T) {
	f := evidence(t, "amd64")
	for _, test := range []struct {
		name   string
		data   []byte
		decode func([]byte) error
		schema shape
	}{
		{"manifest", asJSON(t, f.manifest), func(b []byte) error { _, err := DecodeManifest(b); return err }, manifestShape()},
		{"expect", f.input.Expectation, func(b []byte) error { _, err := DecodeExpect(b); return err }, expectShape()},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, path := range requiredPaths(test.schema, nil) {
				t.Run(strings.Join(path, "."), func(t *testing.T) {
					for _, mode := range []string{"missing", "wrong-type", "null"} {
						t.Run(mode, func(t *testing.T) {
							var value map[string]any
							if err := json.Unmarshal(test.data, &value); err != nil {
								t.Fatal(err)
							}
							parent := value
							for _, key := range path[:len(path)-1] {
								parent = parent[key].(map[string]any)
							}
							key := path[len(path)-1]
							if mode == "null" && key == "pull_request_head_sha" {
								return
							}
							switch mode {
							case "missing":
								delete(parent, key)
							case "wrong-type":
								parent[key] = []any{}
							case "null":
								parent[key] = nil
							}
							if err := test.decode(asJSON(t, value)); err == nil {
								t.Fatal("malformed required field accepted")
							}
						})
					}
				})
			}
			for _, mode := range []string{"unknown", "nested-unknown", "duplicate", "nested-duplicate", "trailing", "oversize", "fraction", "exponent", "negative", "overflow", "invalid-utf8", "unsupported"} {
				t.Run(mode, func(t *testing.T) {
					data := append([]byte{}, test.data...)
					switch mode {
					case "unknown":
						data = append([]byte(`{"unknown":true,`), data[1:]...)
					case "nested-unknown":
						data = bytes.Replace(data, []byte(`"github":{`), []byte(`"github":{"unknown":true,`), 1)
					case "duplicate":
						data = append([]byte(`{"schema":"discarded",`), data[1:]...)
					case "nested-duplicate":
						data = bytes.Replace(data, []byte(`"github":{`), []byte(`"github":{"server_url":"https://github.com",`), 1)
					case "trailing":
						data = append(data, []byte(` {}`)...)
					case "oversize":
						data = append(data, bytes.Repeat([]byte{' '}, MaxManifestBytes)...)
					case "fraction", "exponent", "negative", "overflow":
						if test.name != "manifest" {
							return
						}
						bad := map[string]string{"fraction": "1.5", "exponent": "1e0", "negative": "-1", "overflow": "9223372036854775808"}[mode]
						var m map[string]any
						if err := json.Unmarshal(data, &m); err != nil {
							t.Fatal(err)
						}
						m["receipt"].(map[string]any)["bytes"] = json.Number(bad)
						data = asJSON(t, m)
					case "invalid-utf8":
						data = bytes.Replace(data, []byte(`"single"`), []byte{'"', 0xff, '"'}, 1)
					case "unsupported":
						data = bytes.Replace(data, []byte(`/1"`), []byte(`/99"`), 1)
					}
					if err := test.decode(data); err == nil {
						t.Fatal("malformed object accepted")
					}
				})
			}
		})
	}
}

func requiredPaths(s shape, prefix []string) [][]string {
	var paths [][]string
	for key, child := range s.fields {
		path := append(append([]string{}, prefix...), key)
		if !child.optional {
			paths = append(paths, path)
		}
		if child.kind == 'o' {
			paths = append(paths, requiredPaths(child, path)...)
		}
	}
	return paths
}

func TestProvenanceReferenceValidation(t *testing.T) {
	f := evidence(t, "amd64")
	for _, test := range []struct {
		name  string
		valid bool
		edit  func(*Provenance)
	}{
		{"head-ref", true, func(g *Provenance) { g.SourceRef = "refs/heads/main" }},
		{"tag-ref", true, func(g *Provenance) { g.SourceRef = "refs/tags/v0.2.0" }},
		{"workflow-ref", true, func(g *Provenance) {
			g.WorkflowRef = "owner/project/.github/workflows/check.yaml@refs/tags/v0.2.0"
			g.JobWorkflowRef = "Attention-Span-AI/Tego/.github/workflows/receipt-ci.yml@" + testCommit
		}},
		{"empty-ref-suffix", false, func(g *Provenance) { g.SourceRef = "refs/" }},
		{"caller-extra-separator", false, func(g *Provenance) {
			g.WorkflowRef = "owner/project/.github/workflows/check@other.yml@refs/heads/main"
		}},
		{"signer-extra-separator", false, func(g *Provenance) {
			g.JobWorkflowRef = "Attention-Span-AI/Tego/.github/workflows/check@other.yml@" + testCommit
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			m, e := f.manifest, f.expect
			test.edit(&m.GitHub.Provenance)
			test.edit(&e.GitHub)
			_, manifestErr := DecodeManifest(asJSON(t, m))
			_, expectErr := DecodeExpect(asJSON(t, e))
			for name, err := range map[string]error{"manifest": manifestErr, "expect": expectErr} {
				if (err == nil) != test.valid {
					t.Errorf("%s accepted = %v, want %v: %v", name, err == nil, test.valid, err)
				}
			}
		})
	}
}

func TestMalformedManifestValuesRefused(t *testing.T) {
	f := evidence(t, "amd64")
	for _, test := range []struct {
		name string
		edit func(*Manifest)
	}{
		{"receipt-path", func(m *Manifest) { m.Receipt.File = "../receipt.json" }},
		{"duplicate-filenames", func(m *Manifest) { m.Receipt.File = "contract.yaml" }},
		{"absolute-path", func(m *Manifest) { m.Record.File = "/run/events.jsonl" }},
		{"uppercase-hash", func(m *Manifest) { m.Record.Head = strings.Repeat("A", 64) }},
		{"short-hash", func(m *Manifest) { m.Anchor.SHA256 = "abc" }},
		{"run-id", func(m *Manifest) { m.Record.Run = "wrong" }},
		{"artifact-id", func(m *Manifest) { m.Artifact.AgentID = "0" }},
		{"version", func(m *Manifest) { m.Tego.Version = "dev+dirty" }},
		{"commit", func(m *Manifest) { m.Tego.Commit = "abc" }},
		{"producer-asset", func(m *Manifest) { m.Tego.Producer.Asset = "tego_0.2.0_darwin_arm64" }},
		{"asset-version", func(m *Manifest) { m.Tego.Signer.Asset = "tego_0.3.0_linux_amd64" }},
		{"server", func(m *Manifest) { m.GitHub.ServerURL = "https://example.com" }},
		{"repository", func(m *Manifest) { m.GitHub.Repository = "owner/project/extra" }},
		{"repository-id", func(m *Manifest) { m.GitHub.RepositoryID = "01" }},
		{"attempt", func(m *Manifest) { m.GitHub.RunAttempt = "0" }},
		{"owner-id", func(m *Manifest) { m.GitHub.RepositoryOwnerID = "-1" }},
		{"source-sha", func(m *Manifest) { m.GitHub.SourceSHA = "abc" }},
		{"checkout", func(m *Manifest) { m.GitHub.CheckoutSHA = strings.Repeat("e", 40) }},
		{"visibility", func(m *Manifest) { m.GitHub.Visibility = "unknown" }},
		{"agent-job", func(m *Manifest) { m.GitHub.AgentJob = "other" }},
		{"signing-job", func(m *Manifest) { m.GitHub.SigningJob = "other" }},
		{"step", func(m *Manifest) { m.GitHub.Step = "other" }},
		{"source-ref", func(m *Manifest) { m.GitHub.SourceRef = "main" }},
		{"matrix", func(m *Manifest) { m.GitHub.MatrixKey = "\nforged" }},
		{"caller", func(m *Manifest) { m.GitHub.WorkflowRef = "other/repository/.github/workflows/ci.yml@refs/heads/main" }},
		{"reusable-path", func(m *Manifest) { m.GitHub.JobWorkflowRef = "Attention-Span-AI/Tego/../ci.yml@main" }},
		{"runner", func(m *Manifest) { m.GitHub.AgentRunner.Environment = "self-hosted" }},
		{"image", func(m *Manifest) { m.GitHub.AgentRunner.Image = "" }},
		{"runner-arch", func(m *Manifest) { m.GitHub.SignerRunner.Arch = "ARM64" }},
		{"pr-head-on-push", func(m *Manifest) { head := testCommit; m.GitHub.PullRequestHeadSHA = &head }},
		{"missing-pr-head", func(m *Manifest) { m.GitHub.Event = "pull_request" }},
		{"target-event", func(m *Manifest) { m.GitHub.Event = "pull_request_target" }},
		{"workflow-run", func(m *Manifest) { m.GitHub.Event = "workflow_run" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var m Manifest
			if err := json.Unmarshal(asJSON(t, f.manifest), &m); err != nil {
				t.Fatal(err)
			}
			test.edit(&m)
			if _, err := DecodeManifest(asJSON(t, m)); err == nil {
				t.Fatal("malformed field accepted")
			}
		})
	}
}

func TestIndependentExpectationAndReplayRefused(t *testing.T) {
	for _, mode := range []string{"missing", "attempt", "run", "matrix", "source", "caller", "signer", "ids", "time-order", "non-utc", "bad-time", "event"} {
		t.Run(mode, func(t *testing.T) {
			f := evidence(t, "amd64")
			e := f.expect
			switch mode {
			case "missing":
				f.input.Expectation = nil
			case "attempt":
				e.GitHub.RunAttempt = "3"
			case "run":
				e.GitHub.RunID = "457"
			case "matrix":
				e.GitHub.MatrixKey = "other"
			case "source":
				e.GitHub.SourceSHA = strings.Repeat("e", 40)
				e.GitHub.CheckoutSHA = e.GitHub.SourceSHA
			case "caller":
				e.GitHub.WorkflowSHA = strings.Repeat("e", 40)
			case "signer":
				e.GitHub.JobWorkflowSHA = strings.Repeat("e", 40)
			case "ids":
				e.GitHub.RepositoryID = "124"
			case "time-order":
				e.Attempt.CompletedAt = "2026-11-11T00:00:00Z"
			case "non-utc":
				e.Attempt.StartedAt = "2026-11-11T01:00:00+00:00"
			case "bad-time":
				e.Attempt.StartedAt = "yesterday"
			case "event":
				e.GitHub.Event = "issue_comment"
			}
			if mode != "missing" {
				f.input.Expectation = asJSON(t, e)
			}
			if r := verify(t, f.input); r.ExitCode() == 0 {
				t.Fatal("replay/malformed expectations accepted")
			}
			if r := verify(t, f.input); r.Result != "mismatch" {
				t.Fatalf("expected mismatch: %s", r.Result)
			}
		})
	}
}

func TestRetainedComparisonStrictShape(t *testing.T) {
	f := evidence(t, "amd64")
	data, err := json.Marshal(receiptCheckForTest(t, f))
	if err != nil {
		t.Fatal(err)
	}
	var original map[string]any
	if err := json.Unmarshal(data, &original); err != nil {
		t.Fatal(err)
	}
	for key := range original {
		t.Run(key, func(t *testing.T) {
			for _, mode := range []string{"missing", "null", "wrong"} {
				t.Run(mode, func(t *testing.T) {
					var m map[string]any
					if err := json.Unmarshal(data, &m); err != nil {
						t.Fatal(err)
					}
					switch mode {
					case "missing":
						delete(m, key)
					case "null":
						m[key] = nil
					case "wrong":
						m[key] = map[string]any{}
					}
					if _, err := decodeSaved(asJSON(t, m)); err == nil {
						t.Fatal("malformed retained comparison accepted")
					}
				})
			}
		})
	}
}

func receiptCheckForTest(t *testing.T, f fixture) any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.input.Directory, "signer-check.json"))
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestVersionedSchemasMatchOutput(t *testing.T) {
	f := evidence(t, "arm64")
	r := verify(t, f.input)
	for name, value := range map[string]any{"manifest": f.manifest, "expect": f.expect, "verify": r} {
		t.Run(name, func(t *testing.T) {
			var doc any
			if err := json.Unmarshal(asJSON(t, value), &doc); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("..", "..", "..", "spec", "ci-receipt", "v1", name+".schema.json")
			jsonschema.Validate(t, path, doc)
			object := doc.(map[string]any)
			for key := range object {
				bad := map[string]any{}
				for k, v := range object {
					if k != key {
						bad[k] = v
					}
				}
				if err := jsonschema.Check(path, bad); err == nil {
					t.Fatalf("schema accepts missing %s", key)
				}
			}
		})
	}
	// A refused record may disclose unknown or unsupported run assertions. The
	// result schema must still describe the error response without inventing them.
	r.RunFacts = &RunFacts{Tier: "observe", BestEffort: []string{}, RuntimeGrants: []string{}}
	var refused any
	if err := json.Unmarshal(asJSON(t, r), &refused); err != nil {
		t.Fatal(err)
	}
	jsonschema.Validate(t, filepath.Join("..", "..", "..", "spec", "ci-receipt", "v1", "verify.schema.json"), refused)
}

func TestRunStatusSchemaAgreement(t *testing.T) {
	path := filepath.Join("..", "..", "..", "spec", "run-status", "v1", "schema.json")
	for _, status := range []runstatus.Status{
		{Schema: runstatus.Schema, Run: "r-3f9c2a1b-0dllq06ts7400-k7m2pq", Scope: "/sys/fs/cgroup/fixture/run.scope", CgroupID: "42", Removed: true},
		{Schema: runstatus.Schema, Run: "r-3f9c2a1b-0dllq06ts7400-k7m2pq"},
	} {
		var doc any
		if err := json.Unmarshal(asJSON(t, status), &doc); err != nil {
			t.Fatal(err)
		}
		jsonschema.Validate(t, path, doc)
	}
}

func TestManifestScalarEditsAndWorkflowAssertions(t *testing.T) {
	f := evidence(t, "amd64")
	withBundles(t, &f, bundleFixture{})
	if r := verify(t, f.input); r.Result != "match" {
		t.Fatalf("unchanged evidence must match before edits: %s %+v", r.Result, r.Checks)
	}
	// The bundle fixture accepts the supplied bytes. These fields have no
	// independent expected values, so a well-formed change remains only the
	// workflow's assertion. All other scalar edits must fail a local check.
	assertions := map[string]bool{
		"artifact.agent_id":         true,
		"github.agent_runner.image": true, "github.agent_runner.version": true,
		"github.signer_runner.image": true, "github.signer_runner.version": true,
	}
	original := asJSON(t, f.manifest)
	for _, path := range requiredPaths(manifestShape(), nil) {
		var m map[string]any
		if err := json.Unmarshal(original, &m); err != nil {
			t.Fatal(err)
		}
		parent := m
		for _, key := range path[:len(path)-1] {
			parent = parent[key].(map[string]any)
		}
		key := path[len(path)-1]
		if _, object := parent[key].(map[string]any); object {
			continue
		}
		name := strings.Join(path, ".")
		t.Run(name, func(t *testing.T) {
			switch value := parent[key].(type) {
			case string:
				switch {
				case hashPattern.MatchString(value) || objectIDPattern.MatchString(value):
					first := "a"
					if value[0] == 'a' {
						first = "b"
					}
					parent[key] = first + value[1:]
				case idPattern.MatchString(value):
					parent[key] = value + "1"
				default:
					parent[key] = value + "x"
				}
			case float64:
				parent[key] = value + 1
			case bool:
				parent[key] = !value
			case nil:
				parent[key] = testCommit
			default:
				t.Fatalf("unexpected scalar type %T", value)
			}
			write(t, f.input.Directory, "manifest.json", asJSON(t, m))
			r := verify(t, f.input)
			if assertions[name] {
				if r.Result != "match" {
					t.Fatalf("workflow assertion was treated as independently compared: %s %+v", r.Result, r.Checks)
				}
			} else if r.Result != "mismatch" {
				t.Fatalf("edited compared scalar did not fail: %s %+v", r.Result, r.Checks)
			}
		})
	}
}
