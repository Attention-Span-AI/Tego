// SPDX-License-Identifier: Apache-2.0

package cireceipt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"github.com/attention-span-ai/tego/pkg/spec/runstatus"
)

var testCommit = strings.Repeat("c", 40)
var testProducer = strings.Repeat("a", 64)
var testSigner = strings.Repeat("b", 64)

type fixture struct {
	input    Input
	manifest Manifest
	expect   Expect
}

func write(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(name)), data, 0o600); err != nil {
		t.Fatal(err)
	}
}
func asJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func evidence(t *testing.T, arch string) fixture {
	return evidenceRun(t, arch, "r-3f9c2a1b-0dllq06ts7400-k7m2pq")
}

func evidenceRun(t *testing.T, arch, run string) fixture {
	return evidenceRunMode(t, arch, run, false)
}

func evidenceRunMode(t *testing.T, arch, run string, baseline bool) fixture {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "run"), 0o700); err != nil {
		t.Fatal(err)
	}
	by := receipt.MadeBy{TegoVersion: "0.2.0", Commit: testCommit}
	start := record.RunStartPayload{TegoVersion: by.TegoVersion, Commit: by.Commit, Tier: "landlock", Capture: "forwarder", ContractHash: strings.Repeat("d", 64), RecordMinor: record.MinorLearn,
		Command: []string{"/bin/true"}, Cwd: "/workspace", Capabilities: map[string]bool{string(backend.CapRecordExecOpenNet): true, string(backend.CapRecordReads): true}, ReadsNotified: &record.ReadsNotified{Notified: true, Why: record.ReadsNotifiedWhyFull},
		BestEffort: []string{"fs.write"}, RuntimeGrants: []string{"net.capture[127.0.0.1:1]"}, RunCommandGrant: "/bin/true"}
	if baseline {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "baseline", "applied.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		e, err := record.Decode(bytes.Split(data, []byte{'\n'})[0])
		if err != nil {
			t.Fatal(err)
		}
		var p record.RunStartPayload
		if err := e.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		start.RecordMinor, start.ContractHash, start.EffectiveHash, start.Baseline = p.RecordMinor, p.ContractHash, p.EffectiveHash, p.Baseline
	}
	var raw bytes.Buffer
	prev := ""
	for i, payload := range []any{start, record.RunEndPayload{Reason: record.RunEndExit}} {
		kind := record.KindRunStart
		if i == 1 {
			kind = record.KindRunEnd
		}
		e := record.Event{V: record.Version, Seq: uint64(i), Prev: prev, Run: run, Agent: "fixture", PID: 1, TID: 1, Cgroup: 42, Kind: kind, Source: record.SourceSupervisor, TS: time.Date(2026, 11, 11, 1, 0, i, 0, time.UTC), MonoNS: uint64(1_000_000_000 + i*1_000_000_000)}
		if err := e.SetPayload(payload); err != nil {
			t.Fatal(err)
		}
		line, err := e.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		raw.Write(line)
		raw.WriteByte('\n')
		prev = e.ID
	}
	write(t, dir, "run/events.jsonl", raw.Bytes())
	r, err := ledger.OpenReader(filepath.Join(dir, "run"))
	if err != nil {
		t.Fatal(err)
	}
	rc, err := receipt.Compute(context.Background(), r, receipt.Options{Bind: &by, BinarySHA256: testProducer})
	if closeErr := r.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	var receiptJSON bytes.Buffer
	if err := rc.JSON(&receiptJSON); err != nil {
		t.Fatal(err)
	}
	write(t, dir, "receipt.json", receiptJSON.Bytes())
	write(t, dir, "anchor-line.txt", []byte(run+" "+prev+"\n"))
	write(t, dir, "contract.yaml", []byte("name: fixture\n"))
	status := runstatus.Status{Schema: runstatus.Schema, Run: run, Scope: "/sys/fs/cgroup/fixture/run.scope", CgroupID: "42", Removed: true}
	write(t, dir, "run-status.json", asJSON(t, status))
	check := receipt.Check(context.Background(), receipt.CheckInput{Receipt: filepath.Join(dir, "receipt.json"), Record: filepath.Join(dir, "run"), By: by, RequireEnded: true, StatusFile: filepath.Join(dir, "run-status.json")})
	if check.Result != receipt.CheckMatch || !check.Complete {
		var b bytes.Buffer
		_ = check.JSON(&b)
		t.Fatalf("fixture check: %s", b.Bytes())
	}
	write(t, dir, "signer-check.json", asJSON(t, check))
	producerAsset := "tego_0.2.0_linux_" + arch
	checksums := []byte(testProducer + "  " + producerAsset + "\n" + testSigner + "  tego_0.2.0_linux_" + otherArch(arch) + "\n")
	signer := Binary{Asset: "tego_0.2.0_linux_amd64", SHA256: testSigner}
	if arch == "amd64" {
		signer.SHA256 = testProducer
	}
	github := Provenance{ServerURL: "https://github.com", Repository: "owner/project", RepositoryID: "123", RepositoryOwnerID: "45", Visibility: "public", SourceSHA: testCommit, SourceRef: "refs/heads/main", WorkflowRef: "owner/project/.github/workflows/ci.yml@refs/heads/main", WorkflowSHA: testCommit, JobWorkflowRef: "Attention-Span-AI/Tego/.github/workflows/ci-receipt.yml@" + testCommit, JobWorkflowSHA: testCommit, Event: "push", RunID: "456", RunAttempt: "2", AgentJob: "agent", SigningJob: "sign", Step: "collect", MatrixKey: "single", ActionSHA: testCommit, CheckoutSHA: testCommit}
	manifest := Manifest{Schema: ManifestSchema, Receipt: File{File: "receipt.json", Bytes: int64(receiptJSON.Len()), SHA256: digest(receiptJSON.Bytes())}, Record: Record{File: "run/events.jsonl", Run: run, Bytes: int64(raw.Len()), SHA256: digest(raw.Bytes()), Lines: 2, Head: prev, Ended: true}, Anchor: DigestFile{File: "anchor-line.txt", SHA256: digest([]byte(run + " " + prev + "\n"))}, Contract: Contract{File: "contract.yaml", FileSHA256: digest([]byte("name: fixture\n")), CompiledHash: start.ContractHash}, Teardown: DigestFile{File: "run-status.json", SHA256: digest(asJSON(t, status))}, SignerCheck: DigestFile{File: "signer-check.json", SHA256: digest(asJSON(t, check))}, Tego: Tego{Version: by.TegoVersion, Commit: by.Commit, ChecksumsSHA256: digest(checksums), Producer: Binary{Asset: producerAsset, SHA256: testProducer}, Signer: signer}, Artifact: Artifact{AgentID: "789"}, GitHub: GitHub{Provenance: github, AgentRunner: Runner{Environment: "github-hosted", Image: "ubuntu24", Version: "20261111.1", Arch: assetArch(producerAsset)}, SignerRunner: Runner{Environment: "github-hosted", Image: "ubuntu24", Version: "20261111.1", Arch: "X64"}}}
	manifest.Artifact.InventorySHA256 = inventory(t, dir)
	write(t, dir, "manifest.json", asJSON(t, manifest))
	expect := Expect{Schema: ExpectSchema, GitHub: github, Tego: ReleaseIdentity{Version: by.TegoVersion, Commit: by.Commit}, Attempt: Attempt{StartedAt: "2026-11-11T01:00:00Z", CompletedAt: "2026-11-11T01:01:00Z"}}
	return fixture{input: Input{Directory: dir, ScratchDir: t.TempDir(), Expectation: asJSON(t, expect), Release: Release{Version: by.TegoVersion, Commit: by.Commit, Checksums: checksums}, Checker: Binary{Asset: "tego_0.2.0_linux_" + otherArch(arch), SHA256: testSigner}, By: by}, manifest: manifest, expect: expect}
}

func otherArch(arch string) string {
	if arch == "amd64" {
		return "arm64"
	}
	return "amd64"
}

func inventory(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	for _, name := range []string{"anchor-line.txt", "contract.yaml", "receipt.json", "run-status.json", "run/events.jsonl"} {
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "%s %d %s\n", digest(data), len(data), name)
	}
	return digest([]byte(b.String()))
}

func verify(t *testing.T, in Input) *Result {
	t.Helper()
	result, err := Verify(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	var text, js bytes.Buffer
	if err := result.Text(&text); err != nil {
		t.Fatal(err)
	}
	if err := result.JSON(&js); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"signed", "proof", "tamper-proof"} {
		if strings.Contains(text.String(), bad) || strings.Contains(js.String(), bad) {
			t.Fatalf("unavailable public claim %q: %s", bad, text.String())
		}
	}
	if result.ExitCode() != identity.ExitOK && strings.Contains(text.String(), "CI receipt: full ended match") {
		t.Fatal("unsuccessful result claimed full ended match")
	}
	return result
}

func findCheck(r *Result, name string) Check {
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	return Check{}
}

func TestWithoutBundleNeverPasses(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			f := evidence(t, arch)
			r := verify(t, f.input)
			if r.Result != "cannot-check" || r.ExitCode() != identity.ExitError {
				t.Fatalf("%s: %+v", r.Result, r.Checks)
			}
			for _, c := range r.Checks {
				if !strings.HasPrefix(c.Name, "bundle.") && c.Result != receipt.StepPass {
					t.Errorf("%s: %s %s", c.Name, c.Result, c.Why)
				}
			}
			if c := findCheck(r, "bundle.receipt.invocation"); c.Result != receipt.StepNotChecked || c.Why != "not checked: no bundle" {
				t.Fatalf("missing bundle: %+v", c)
			}
			if r.RunFacts == nil || len(r.RunFacts.RuntimeGrants) != 1 || r.RunFacts.RunCommandGrant != "/bin/true" {
				t.Fatal("run assertions were lost")
			}
			entries, err := os.ReadDir(f.input.ScratchDir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("private copies leaked: %v %v", entries, err)
			}
		})
	}
}

func TestEditedBytesAndMixedPairFail(t *testing.T) {
	for _, name := range []string{"receipt.json", "run/events.jsonl", "anchor-line.txt", "contract.yaml", "run-status.json", "signer-check.json"} {
		t.Run(name, func(t *testing.T) {
			f := evidence(t, "amd64")
			data, err := os.ReadFile(filepath.Join(f.input.Directory, filepath.FromSlash(name)))
			if err != nil {
				t.Fatal(err)
			}
			write(t, f.input.Directory, name, append(data, ' '))
			if r := verify(t, f.input); r.ExitCode() != identity.ExitFinding {
				t.Fatalf("edited bytes: %s %+v", r.Result, r.Checks)
			}
		})
	}
	f := evidence(t, "amd64")
	other := evidenceRun(t, "amd64", "r-3f9c2a1b-0dllq06ts7400-k7m2pr")
	data, err := os.ReadFile(filepath.Join(other.input.Directory, "run/events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	write(t, f.input.Directory, "run/events.jsonl", data)
	refreshDigests(t, &f)
	if r := verify(t, f.input); r.ExitCode() != identity.ExitFinding {
		t.Fatal("mixed run pair accepted")
	} else if findCheck(r, "fresh-check").Result != receipt.StepFail {
		t.Fatal("a different internally valid record was not refused by the fresh comparison")
	}
}

func TestDeferredUnendedAndIncompleteFail(t *testing.T) {
	for _, mode := range []string{"deferred", "not-removed", "wrong-run", "wrong-cgroup", "unended", "incomplete"} {
		t.Run(mode, func(t *testing.T) {
			f := evidence(t, "arm64")
			if mode == "unended" || mode == "incomplete" {
				rewriteRun(t, &f, mode)
			} else {
				var s runstatus.Status
				data, err := os.ReadFile(filepath.Join(f.input.Directory, "run-status.json"))
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(data, &s); err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "deferred":
					s.Removed = false
					s.Deferred = true
				case "not-removed":
					s.Removed = false
				case "wrong-run":
					s.Run = "r-3f9c2a1b-0dllq06ts7400-k7m2pr"
				case "wrong-cgroup":
					s.CgroupID = "43"
				}
				write(t, f.input.Directory, "run-status.json", asJSON(t, s))
			}
			refreshDigests(t, &f)
			r := verify(t, f.input)
			if r.ExitCode() != identity.ExitFinding {
				t.Fatalf("%s: %s", mode, r.Result)
			}
			for _, name := range []string{"file.receipt.json", "file.run/events.jsonl", "file.run-status.json", "inventory"} {
				if c := findCheck(r, name); c.Result != receipt.StepPass {
					t.Fatalf("%s failed before semantic check: %+v", name, c)
				}
			}
			if mode == "unended" {
				if findCheck(r, "binding").Result != receipt.StepFail {
					t.Fatal("unended binding was not refused")
				}
			} else if mode == "incomplete" {
				if findCheck(r, "coverage").Result != receipt.StepFail {
					t.Fatal("incomplete coverage was not refused")
				}
			} else if findCheck(r, "teardown").Result != receipt.StepFail {
				t.Fatal("teardown assertion was not refused")
			}
		})
	}
}

func refreshDigests(t *testing.T, f *fixture) {
	t.Helper()
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(f.input.Directory, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	data := read("receipt.json")
	f.manifest.Receipt.Bytes = int64(len(data))
	f.manifest.Receipt.SHA256 = digest(data)
	data = read("run/events.jsonl")
	f.manifest.Record.Bytes = int64(len(data))
	f.manifest.Record.SHA256 = digest(data)
	f.manifest.Anchor.SHA256 = digest(read("anchor-line.txt"))
	f.manifest.Contract.FileSHA256 = digest(read("contract.yaml"))
	f.manifest.Teardown.SHA256 = digest(read("run-status.json"))
	f.manifest.SignerCheck.SHA256 = digest(read("signer-check.json"))
	f.manifest.Artifact.InventorySHA256 = inventory(t, f.input.Directory)
	write(t, f.input.Directory, "manifest.json", asJSON(t, f.manifest))
}

// rewriteRun produces a valid chain and a freshly computed bound receipt, so the
// ended/coverage tests cannot pass merely because a file digest was left stale.
func rewriteRun(t *testing.T, f *fixture, mode string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.input.Directory, "run/events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var events []*record.Event
	for _, line := range bytes.Split(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'}) {
		e, err := record.Decode(line)
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
	}
	if mode == "unended" {
		events = events[:1]
	} else {
		var start record.RunStartPayload
		if err := events[0].DecodePayload(&start); err != nil {
			t.Fatal(err)
		}
		start.Capture = "off"
		if err := events[0].SetPayload(start); err != nil {
			t.Fatal(err)
		}
	}
	var raw bytes.Buffer
	prev := ""
	for _, event := range events {
		event.Prev = prev
		line, err := event.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		raw.Write(line)
		raw.WriteByte('\n')
		prev = event.ID
	}
	write(t, f.input.Directory, "run/events.jsonl", raw.Bytes())
	r, err := ledger.OpenReader(filepath.Join(f.input.Directory, "run"))
	if err != nil {
		t.Fatal(err)
	}
	rc, err := receipt.Compute(context.Background(), r, receipt.Options{Bind: &f.input.By, BinarySHA256: f.manifest.Tego.Producer.SHA256})
	if closeErr := r.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := rc.JSON(&output); err != nil {
		t.Fatal(err)
	}
	write(t, f.input.Directory, "receipt.json", output.Bytes())
	chain := rc.Binding.Chain
	f.manifest.Record.Run, f.manifest.Record.Lines, f.manifest.Record.Head, f.manifest.Record.Ended = chain.Run, chain.Lines, chain.Head, chain.Ended
	write(t, f.input.Directory, "anchor-line.txt", []byte(chain.Run+" "+chain.Head+"\n"))
}

func TestReleaseChecksumsAreIndependent(t *testing.T) {
	for _, mode := range []string{"wrong-producer", "wrong-signer", "wrong-release", "wrong-commit", "duplicate", "traversal", "missing"} {
		t.Run(mode, func(t *testing.T) {
			f := evidence(t, "arm64")
			switch mode {
			case "wrong-producer":
				f.input.Release.Checksums = bytes.ReplaceAll(f.input.Release.Checksums, []byte(testProducer), []byte(strings.Repeat("f", 64)))
				f.manifest.Tego.ChecksumsSHA256 = digest(f.input.Release.Checksums)
				write(t, f.input.Directory, "manifest.json", asJSON(t, f.manifest))
			case "wrong-signer":
				f.manifest.Tego.Signer.SHA256 = strings.Repeat("f", 64)
				write(t, f.input.Directory, "manifest.json", asJSON(t, f.manifest))
			case "wrong-release":
				f.input.Release.Version = "0.2.1"
			case "wrong-commit":
				f.input.Release.Commit = strings.Repeat("f", 40)
			case "duplicate":
				f.input.Release.Checksums = append(f.input.Release.Checksums, f.input.Release.Checksums...)
			case "traversal":
				f.input.Release.Checksums = []byte(testProducer + "  ../tego\n")
			case "missing":
				f.input.Release.Checksums = nil
			}
			r := verify(t, f.input)
			if r.ExitCode() != identity.ExitFinding {
				t.Fatalf("%s: %s", mode, r.Result)
			}
			if mode == "wrong-producer" || mode == "wrong-signer" {
				name := "binary." + strings.TrimPrefix(mode, "wrong-")
				if c := findCheck(r, name); c.Result != receipt.StepFail {
					t.Fatalf("evidence asset mismatch was not refused: %+v", c)
				}
			}
		})
	}
}

func TestChecksumsAuthenticationLimit(t *testing.T) {
	f := evidence(t, "arm64")
	r := verify(t, f.input)
	check := findCheck(r, "release-checksums")
	const why = "the given checksums file's sha256 matches the manifest; this command did not check its signature"
	if check.Result != receipt.StepPass || check.Why != why {
		t.Fatalf("checksum comparison: %+v", check)
	}
	const limit = "The release checksums file was not authenticated by this command."
	var text, js bytes.Buffer
	if err := r.Text(&text); err != nil {
		t.Fatal(err)
	}
	if err := r.JSON(&js); err != nil {
		t.Fatal(err)
	}
	for name, output := range map[string]string{"text": text.String(), "JSON": js.String()} {
		if !strings.Contains(output, limit) || !strings.Contains(output, why) {
			t.Errorf("%s does not disclose checksum authentication limit: %s", name, output)
		}
		if strings.Contains(output, "independently authenticated release checksums") {
			t.Errorf("%s claims checksums authentication: %s", name, output)
		}
	}
}

func TestCheckerIdentityCannotCheck(t *testing.T) {
	for _, mode := range []string{"version", "commit", "dirty", "hash", "asset", "missing"} {
		t.Run(mode, func(t *testing.T) {
			f := evidence(t, "arm64")
			withBundles(t, &f, bundleFixture{})
			switch mode {
			case "version":
				f.input.By.TegoVersion = "0.2.1"
			case "commit":
				f.input.By.Commit = strings.Repeat("f", 40)
			case "dirty":
				f.input.By.TegoVersion += "+dirty"
			case "hash":
				f.input.Checker.SHA256 = strings.Repeat("f", 64)
			case "asset":
				f.input.Checker.Asset = "tego_0.2.1_linux_amd64"
			case "missing":
				f.input.Checker = Binary{}
			}
			r := verify(t, f.input)
			if r.Result != "cannot-check" || r.ExitCode() != identity.ExitError {
				t.Fatalf("checker uncertainty: %s/%d %+v", r.Result, r.ExitCode(), r.Checks)
			}
			if c := findCheck(r, "binary.checker"); c.Result != receipt.StepNotChecked {
				t.Fatalf("checker was not left unchecked: %+v", c)
			}
			for _, name := range []string{"release-checksums", "binary.producer", "binary.signer"} {
				if c := findCheck(r, name); c.Result != receipt.StepPass {
					t.Errorf("checker uncertainty changed evidence comparison %s: %+v", name, c)
				}
			}
			if mode == "version" || mode == "commit" || mode == "dirty" {
				if c := findCheck(r, "fresh-check"); c.Result != receipt.StepNotChecked {
					t.Fatalf("fresh checker uncertainty became a mismatch: %+v", c)
				}
			}
		})
	}
}

func TestTextLabelsUnestablishedIdentities(t *testing.T) {
	for _, result := range []string{"cannot-check", "mismatch", "match"} {
		t.Run(result, func(t *testing.T) {
			r := Result{Result: result, SignerURI: "https://github.com/owner/workflow", SignerDigest: testCommit, CallerURI: "https://github.com/owner/caller", CallerDigest: testCommit, Repository: "owner/project", SourceSHA: testCommit, RunID: "456", RunAttempt: "2"}
			var output bytes.Buffer
			if err := r.Text(&output); err != nil {
				t.Fatal(err)
			}
			const label = "Expected (not established):\nWorkflow:"
			if got := strings.Contains(output.String(), label); got != (result != "match") {
				t.Fatalf("%s expected identity label = %v: %s", result, got, output.String())
			}
			for _, field := range []string{"Workflow:", "Caller:", "Repository:", "Source:", "Run:"} {
				if !strings.Contains(output.String(), field) {
					t.Errorf("missing %s: %s", field, output.String())
				}
			}
		})
	}
}

func TestFileLinksAndSpecialFilesRefused(t *testing.T) {
	for _, mode := range []string{"leaf-link", "directory-link", "hard-link", "directory", "too-large", "missing"} {
		t.Run(mode, func(t *testing.T) {
			f := evidence(t, "amd64")
			path := filepath.Join(f.input.Directory, "contract.yaml")
			if mode == "directory-link" {
				path = filepath.Join(f.input.Directory, "run")
			}
			if mode != "too-large" {
				if err := os.RemoveAll(path); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "leaf-link":
				if err := os.Symlink("receipt.json", path); err != nil {
					t.Fatal(err)
				}
			case "directory-link":
				if err := os.Symlink(t.TempDir(), path); err != nil {
					t.Fatal(err)
				}
			case "hard-link":
				if err := os.Link(filepath.Join(f.input.Directory, "receipt.json"), path); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			case "too-large":
				write(t, f.input.Directory, "contract.yaml", make([]byte, maxContractBytes+1))
			}
			if r := verify(t, f.input); r.Result != "cannot-check" || r.ExitCode() != identity.ExitError || findCheck(r, "files").Result != receipt.StepNotChecked {
				t.Fatalf("unsafe %s: %s", mode, r.Result)
			}
		})
	}
}

type bundleFixture struct {
	mutate func(*BundleResult)
	err    error
}

func (b bundleFixture) Verify(_ context.Context, _ BundleInput) (BundleResult, error) {
	result := BundleResult{IntegratedTimes: []time.Time{time.Date(2026, 11, 11, 1, 0, 20, 0, time.UTC), time.Date(2026, 11, 11, 1, 0, 30, 0, time.UTC)}}
	for _, name := range BundleChecks() {
		result.Checks = append(result.Checks, Check{Name: name, Result: receipt.StepPass, Why: "fixture only"})
	}
	if b.mutate != nil {
		b.mutate(&result)
	}
	return result, b.err
}

func withBundles(t *testing.T, f *fixture, backend BundleVerifier) {
	t.Helper()
	write(t, f.input.Directory, "receipt.sigstore.json", []byte("fixture receipt bundle"))
	write(t, f.input.Directory, "manifest.sigstore.json", []byte("fixture manifest bundle"))
	f.input.Bundles = backend
}

func TestBundleSeamRequiresEveryCertificateCheck(t *testing.T) {
	f := evidence(t, "arm64")
	withBundles(t, &f, bundleFixture{})
	if r := verify(t, f.input); r.ExitCode() != identity.ExitOK {
		t.Fatalf("fixture seam: %s %+v", r.Result, r.Checks)
	}
	for index, name := range BundleChecks() {
		t.Run(name, func(t *testing.T) {
			for _, mode := range []string{"missing", "wrong"} {
				t.Run(mode, func(t *testing.T) {
					f.input.Bundles = bundleFixture{mutate: func(r *BundleResult) {
						if mode == "missing" {
							r.Checks = append(r.Checks[:index], r.Checks[index+1:]...)
						} else {
							r.Checks[index].Result = receipt.StepFail
						}
					}}
					if r := verify(t, f.input); r.ExitCode() == identity.ExitOK {
						t.Fatalf("%s %s accepted", name, mode)
					}
				})
			}
		})
	}
	for _, mode := range []string{"time", "no-times", "error", "duplicate", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			f.input.Bundles = bundleFixture{mutate: func(r *BundleResult) {
				switch mode {
				case "time":
					r.IntegratedTimes[0] = r.IntegratedTimes[0].Add(-time.Hour)
				case "no-times":
					r.IntegratedTimes = nil
				case "duplicate":
					r.Checks = append(r.Checks, r.Checks[0])
				case "unknown":
					r.Checks[0].Name = "invented"
				}
			}}
			if mode == "error" {
				f.input.Bundles = bundleFixture{err: errors.New("fixture trust unavailable")}
			}
			if r := verify(t, f.input); r.ExitCode() == identity.ExitOK {
				t.Fatalf("bundle %s accepted", mode)
			}
		})
	}
}

func TestSavedCheckCannotOmitMandatoryComparison(t *testing.T) {
	f := evidence(t, "amd64")
	data, err := os.ReadFile(filepath.Join(f.input.Directory, "signer-check.json"))
	if err != nil {
		t.Fatal(err)
	}
	saved, err := decodeSaved(data)
	if err != nil {
		t.Fatal(err)
	}
	for index, step := range saved.Checks {
		t.Run(step.Name, func(t *testing.T) {
			copy := *saved
			copy.Checks = append([]receipt.CheckStep{}, saved.Checks...)
			copy.Checks = append(copy.Checks[:index], copy.Checks[index+1:]...)
			if completeCheck(&copy, f.manifest, f.input.Checker) {
				t.Fatal("missing mandatory comparison accepted")
			}
		})
	}
	for _, name := range []string{"time_taken.seconds", "unknown", "binding.binary_sha256"} {
		t.Run(name, func(t *testing.T) {
			copy := *saved
			copy.NotCompared = []string{name}
			if name == "binding.binary_sha256" {
				copy.NotCompared = append(copy.NotCompared, name)
			}
			if completeCheck(&copy, f.manifest, f.input.Checker) {
				t.Fatal("undocumented or duplicate not_compared accepted")
			}
		})
	}
}

func TestScratchDirectoryCannotAliasEvidence(t *testing.T) {
	f := evidence(t, "amd64")
	inside := filepath.Join(f.input.Directory, "scratch")
	if err := os.Mkdir(inside, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(inside, alias); err != nil {
		t.Fatal(err)
	}
	f.input.ScratchDir = alias
	got := verify(t, f.input)
	step := findCheck(got, "files")
	if step.Result != "not-checked" || !strings.Contains(step.Why, "outside evidence") {
		t.Fatalf("scratch alias was accepted: %+v", step)
	}
}

func TestBaselineCIReceiptBinding(t *testing.T) {
	f := evidenceRunMode(t, "amd64", "r-3f9c2a1b-0dllq06ts7400-k7m2pq", true)
	withBundles(t, &f, bundleFixture{})
	r := verify(t, f.input)
	if r.ExitCode() != identity.ExitOK || findCheck(r, "baseline").Result != receipt.StepPass || r.RunFacts == nil || r.RunFacts.EffectiveHash == "" {
		t.Fatalf("baseline CI binding: %+v", r)
	}
	data, err := os.ReadFile(filepath.Join(f.input.Directory, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc["binding"].(map[string]any)["effective_hash"] = strings.Repeat("f", 64)
	write(t, f.input.Directory, "receipt.json", asJSON(t, doc))
	refreshDigests(t, &f)
	r = verify(t, f.input)
	if findCheck(r, "baseline").Result != receipt.StepFail {
		t.Fatalf("edited baseline effective binding accepted: %+v", r)
	}
}
