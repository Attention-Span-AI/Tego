// SPDX-License-Identifier: Apache-2.0

package cireceipt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"github.com/attention-span-ai/tego/pkg/spec/runstatus"
)

const (
	bytesStatement      = "these bytes"
	provenanceStatement = "this workflow, some run"
	matchStatement      = "full ended match"
)

type verifier struct {
	in  Input
	res *Result
	f   *frozen
	m   Manifest
	e   Expect
}

// Verify checks consistency using private copies and independent expectations.
// A missing BundleVerifier always yields cannot-check, never full acceptance.
// Malformed or contradictory evidence is a mismatch; unreadable input is uncertainty.
func Verify(ctx context.Context, in Input) (*Result, error) {
	v := &verifier{in: in, res: &Result{Schema: ResultSchema, Result: "cannot-check", Checks: []Check{}, IntegratedTimes: []time.Time{}, NotCompared: []string{}, Limits: []string{
		"The release checksums file was not authenticated by this command.",
		"Root on the agent runner can still feed fabricated evidence.",
		"Anyone who can change which workflow runs could have supplied different evidence.",
		"True coverage does not mean every action observed.",
		"Absence remains the collector's assertion.",
		"Prices are not reproduced; local rewrite and crash-tail limits remain.",
	}}}
	var err error
	v.e, err = DecodeExpect(in.Expectation)
	if err != nil {
		v.add("expectations", receipt.StepFail, provenanceStatement, err.Error())
		return v.finish(), nil
	}
	g := v.e.GitHub
	v.res.SignerURI = "https://github.com/" + g.JobWorkflowRef
	v.res.SignerDigest = g.JobWorkflowSHA
	v.res.CallerURI = "https://github.com/" + g.WorkflowRef
	v.res.CallerDigest = g.WorkflowSHA
	v.res.Repository, v.res.RepositoryID, v.res.RepositoryOwnerID = g.Repository, g.RepositoryID, g.RepositoryOwnerID
	v.res.SourceSHA, v.res.RunID, v.res.RunAttempt, v.res.Trigger = g.SourceSHA, g.RunID, g.RunAttempt, g.Event
	v.add("expectations", receipt.StepPass, provenanceStatement, "independent exact-attempt expectations are well formed")
	v.f, err = freeze(ctx, in)
	if err != nil {
		v.add("files", receipt.StepNotChecked, bytesStatement, err.Error())
		return v.finish(), nil
	}
	defer func() { _ = os.RemoveAll(v.f.dir) }() // only private copies created by this invocation
	v.add("files", receipt.StepPass, bytesStatement, "bounded regular files frozen privately; no evidence was executed")
	v.m, err = DecodeManifest(v.f.files["manifest.json"])
	if err != nil {
		v.add("manifest", receipt.StepFail, bytesStatement, err.Error())
		return v.finish(), nil
	}
	v.add("manifest", receipt.StepPass, bytesStatement, "complete required manifest shape")
	v.res.RunnerEnvironment = v.m.GitHub.SignerRunner.Environment
	v.res.ReceiptSHA256 = digest(v.f.files["receipt.json"])
	v.metadata()
	v.hashes()
	v.release()
	v.record()
	v.checks(ctx)
	v.bundles(ctx)
	return v.finish(), nil
}

func (v *verifier) add(name, result, statement, why string) {
	v.res.Checks = append(v.res.Checks, Check{Name: name, Result: result, Statement: statement, Why: why})
}
func (v *verifier) test(name, statement string, ok bool, why string) {
	result := receipt.StepFail
	if ok {
		result = receipt.StepPass
	}
	v.add(name, result, statement, why)
}

func (v *verifier) finish() *Result {
	v.res.Result = "match"
	for _, c := range v.res.Checks {
		if c.Result == receipt.StepFail {
			v.res.Result = "mismatch"
			return v.res
		}
		if c.Result != receipt.StepPass {
			v.res.Result = "cannot-check"
		}
	}
	return v.res
}

func (v *verifier) metadata() {
	got, _ := json.Marshal(v.m.GitHub.Provenance)
	want, _ := json.Marshal(v.e.GitHub)
	v.test("provenance", provenanceStatement, bytes.Equal(got, want), "every repository, source, caller, reusable workflow, job, step, matrix and exact-attempt field compared with independent expectations")
	v.test("release-identity", "same release/commit", v.m.Tego.Version == v.e.Tego.Version && v.m.Tego.Commit == v.e.Tego.Commit, "manifest release version and commit compared with independent expectations")
	producerArch := assetArch(v.m.Tego.Producer.Asset)
	v.test("runner-metadata", provenanceStatement, producerArch == v.m.GitHub.AgentRunner.Arch && assetArch(v.m.Tego.Signer.Asset) == v.m.GitHub.SignerRunner.Arch, "both runner environments and image fields are well formed; asset architecture matches each runner; images are workflow/API assertions")
}

func assetArch(s string) string {
	if strings.HasSuffix(s, "_amd64") {
		return "X64"
	}
	if strings.HasSuffix(s, "_arm64") {
		return "ARM64"
	}
	return ""
}

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func (v *verifier) hashes() {
	m := v.m
	for _, f := range []struct {
		name, hash string
		size       int64
	}{
		{m.Receipt.File, m.Receipt.SHA256, m.Receipt.Bytes}, {m.Record.File, m.Record.SHA256, m.Record.Bytes},
		{m.Anchor.File, m.Anchor.SHA256, -1}, {m.Contract.File, m.Contract.FileSHA256, -1},
		{m.Teardown.File, m.Teardown.SHA256, -1}, {m.SignerCheck.File, m.SignerCheck.SHA256, -1},
	} {
		data := v.f.files[f.name]
		v.test("file."+f.name, bytesStatement, digest(data) == f.hash && (f.size < 0 || int64(len(data)) == f.size), "retained bytes match manifest digest and any declared exact size")
	}
	names := []string{m.Receipt.File, m.Record.File, m.Anchor.File, m.Contract.File, m.Teardown.File}
	sort.Strings(names)
	var inventory strings.Builder
	for _, name := range names {
		data := v.f.files[name]
		fmt.Fprintf(&inventory, "%s %d %s\n", digest(data), len(data), name)
	}
	v.test("inventory", bytesStatement, digest([]byte(inventory.String())) == m.Artifact.InventorySHA256, "sorted agent artifact inventory digest matches the five frozen files")
	v.test("anchor", bytesStatement, string(v.f.files[m.Anchor.File]) == m.Record.Run+" "+m.Record.Head+"\n", "anchor is exactly the run, one space, head and newline")
}

func (v *verifier) release() {
	in, m := v.in, v.m
	if in.Release.Version != v.e.Tego.Version || in.Release.Commit != v.e.Tego.Commit {
		v.add("release-checksums", receipt.StepFail, "same release/commit", "given checksums identity must equal the expected exact release/commit")
		return
	}
	assets, err := releaseAssets(in.Release.Checksums)
	if err != nil {
		v.add("release-checksums", receipt.StepFail, "same release/commit", err.Error())
		return
	}
	v.test("release-checksums", bytesStatement, digest(in.Release.Checksums) == m.Tego.ChecksumsSHA256, "the given checksums file's sha256 matches the manifest; this command did not check its signature")
	for name, bin := range map[string]Binary{"producer": m.Tego.Producer, "signer": m.Tego.Signer} {
		v.test("binary."+name, "same release/commit", validAsset(bin.Asset, m.Tego.Version) && hashPattern.MatchString(bin.SHA256) && assets[bin.Asset] == bin.SHA256, "named executable belongs to the given release checksums; different architectures may have different hashes")
	}
	checker := in.Checker
	if in.By.TegoVersion != v.e.Tego.Version || in.By.Commit != v.e.Tego.Commit || !receipt.Exact(in.By) || !validAsset(checker.Asset, v.e.Tego.Version) || !hashPattern.MatchString(checker.SHA256) || assets[checker.Asset] != checker.SHA256 {
		v.add("binary.checker", receipt.StepNotChecked, "same release/commit", "checking executable is not established as a member of the expected exact release; use that release's executable")
		return
	}
	v.add("binary.checker", receipt.StepPass, "same release/commit", "checking executable belongs to the given release checksums and names the expected exact release/commit")
}

type boundView struct {
	V             int                   `json:"receipt_v"`
	Run           string                `json:"run"`
	Tier          string                `json:"tier"`
	Ended         bool                  `json:"ended"`
	ReadsNotified *record.ReadsNotified `json:"reads_notified"`
	Coverage      struct {
		Complete bool `json:"complete"`
	} `json:"coverage"`
	Binding *receipt.Binding `json:"binding"`
}

func (v *verifier) record() {
	var rc boundView
	if err := json.Unmarshal(v.f.files["receipt.json"], &rc); err != nil {
		v.add("binding", receipt.StepFail, matchStatement, "receipt cannot be decoded: "+err.Error())
		return
	}
	v.res.CoverageComplete = rc.Coverage.Complete
	v.test("coverage", matchStatement, rc.Coverage.Complete, "Incomplete when coverage.complete is false; true does not mean every action observed")
	b := rc.Binding
	if rc.V != receipt.Version || b == nil || (b.V != 2 && b.V != receipt.BaselineBindingVersion) || b.Error != "" || b.Chain == nil {
		v.add("binding", receipt.StepFail, matchStatement, "CI evidence requires receipt version 1, binding version 2 or 3, a chain and no binding error")
		return
	}
	c, m := b.Chain, v.m
	good := rc.Run == m.Record.Run && c.Run == m.Record.Run && c.Bytes == m.Record.Bytes && c.SHA256 == m.Record.SHA256 && c.Lines == m.Record.Lines && c.Head == m.Record.Head && c.Ended == m.Record.Ended && rc.Ended == m.Record.Ended && c.Ended && c.TornBytes == 0 && c.NewerLines == 0
	v.test("binding", matchStatement, good, "receipt and manifest agree on every record byte, line, head, run and end; no torn bytes or newer lines")
	v.res.Ended = c.Ended
	v.test("producer-identity", "same release/commit", b.BinarySHA256 == m.Tego.Producer.SHA256 && b.ReceiptBy.TegoVersion == m.Tego.Version && b.ReceiptBy.Commit == m.Tego.Commit && receipt.Exact(b.ReceiptBy), "producer hash matches manifest; receipt release identity excludes executable hash")
	data := v.f.files["run/events.jsonl"]
	nl := bytes.IndexByte(data, '\n')
	if nl < 0 {
		v.add("run-start", receipt.StepFail, matchStatement, "record has no complete run_start line")
		return
	}
	e, err := record.Decode(data[:nl])
	if err != nil {
		v.add("run-start", receipt.StepFail, matchStatement, "record run_start: "+err.Error())
		return
	}
	if e.Kind != record.KindRunStart {
		v.add("run-start", receipt.StepFail, matchStatement, "record does not begin with a readable run_start")
		return
	}
	var start record.RunStartPayload
	if err := e.DecodePayload(&start); err != nil {
		v.add("run-start", receipt.StepFail, matchStatement, err.Error())
		return
	}
	if b.V == receipt.BaselineBindingVersion {
		valid := start.ValidateBaseline() == nil && start.Baseline != nil && b.EffectiveHash == start.EffectiveHash && b.BaselineSHA256 == start.Baseline.SHA256 && b.BaselineEvidenceSHA256 == start.Baseline.EvidenceSHA256
		v.test("baseline", matchStatement, valid, "effective and baseline evidence hashes match recorded facts; contract_hash remains source-only")
	} else if start.BaselineRecorded() {
		v.add("baseline", receipt.StepFail, matchStatement, "baseline record requires receipt binding 3")
		return
	}
	v.test("run-start", matchStatement, e.Run == m.Record.Run && start.TegoVersion == m.Tego.Version && start.Commit == m.Tego.Commit && (start.Tier == "landlock" || start.Tier == "cgroup"), "run_start run, exact release and enforced tier compared")
	got, _ := json.Marshal(b.Capabilities)
	want, _ := json.Marshal(start.Capabilities)
	v.test("contract", "The YAML hash is separate; it does not reproduce compilation with merged defaults and runtime grants", b.ContractHash == m.Contract.CompiledHash && start.ContractHash == m.Contract.CompiledHash && hashPattern.MatchString(start.ContractHash) && start.Capabilities != nil && bytes.Equal(got, want), "compiled contract hash and whole capability map match run_start; YAML file digest checked separately")
	reads, _ := json.Marshal(rc.ReadsNotified)
	recordReads, _ := json.Marshal(start.ReadsNotified)
	v.test("read-mode", matchStatement, start.ReadsNotified != nil && bytes.Equal(reads, recordReads) && rc.Tier == start.Tier, "tier and reads_notified match; best_effort, runtime_grants and run_command_grant retained as record assertions")
	v.res.RunFacts = &RunFacts{EffectiveHash: b.EffectiveHash, BaselineSHA256: b.BaselineSHA256, BaselineEvidenceSHA256: b.BaselineEvidenceSHA256, Tier: start.Tier, Capabilities: start.Capabilities, BestEffort: append([]string{}, start.BestEffort...), ReadsNotified: start.ReadsNotified, RuntimeGrants: append([]string{}, start.RuntimeGrants...), RunCommandGrant: start.RunCommandGrant}
	status, err := runstatus.Decode(v.f.files["run-status.json"])
	if err != nil {
		v.add("teardown", receipt.StepFail, "Absence remains the collector's assertion", err.Error())
		return
	}
	v.test("teardown", "Absence remains the collector's assertion", status.Run == m.Record.Run && e.Cgroup > 0 && status.CgroupID == strconv.FormatUint(e.Cgroup, 10) && status.Removed && !status.Deferred, "copied status matches record run/cgroup and reports confirmed removal without deferred cleanup; this reader cannot inspect the earlier runner")
}

func (v *verifier) checks(ctx context.Context) {
	saved, err := decodeSaved(v.f.files["signer-check.json"])
	if err != nil {
		v.add("saved-check", receipt.StepFail, matchStatement, err.Error())
	} else {
		v.test("saved-check", matchStatement, completeCheck(saved, v.m, v.m.Tego.Signer), "retained comparison requires an ended match, complete coverage and every mandatory comparison")
	}
	fresh := receipt.Check(ctx, receipt.CheckInput{Receipt: filepath.Join(v.f.dir, "receipt.json"), Record: filepath.Join(v.f.dir, "run"), By: v.in.By, RequireEnded: true, StatusFile: filepath.Join(v.f.dir, "run-status.json")})
	v.res.NotCompared = append([]string{}, fresh.NotCompared...)
	if fresh.Result == receipt.CheckCannot {
		v.add("fresh-check", receipt.StepNotChecked, matchStatement, "fresh local comparison could not establish an ended match; local inputs must be readable and the checker must name the expected exact release")
		return
	}
	v.test("fresh-check", matchStatement, completeCheck(fresh, v.m, v.in.Checker), "fresh local comparison requires an ended match, complete coverage and every mandatory comparison")
}

func completeCheck(c *receipt.CheckResult, m Manifest, _ Binary) bool {
	if c.Result != receipt.CheckMatch || !c.Ended || c.Run != m.Record.Run || c.Lines != m.Record.Lines || c.Head != m.Record.Head || c.V != receipt.CheckVersion || (c.BindingVersion != 2 && c.BindingVersion != receipt.BaselineBindingVersion) || !c.CoverageComplete || !c.Complete || c.CheckedBy.TegoVersion != m.Tego.Version || c.CheckedBy.Commit != m.Tego.Commit || c.ReceiptBy == nil || c.ReceiptBy.TegoVersion != m.Tego.Version || c.ReceiptBy.Commit != m.Tego.Commit {
		return false
	}
	seen := map[string]bool{}
	for _, step := range c.Checks {
		if seen[step.Name] || step.Result != receipt.StepPass {
			return false
		}
		seen[step.Name] = true
	}
	for _, name := range []string{"receipt", "binding", "made_by", "run", "chain", "head", "bytes", "facts", "ended", "teardown", "coverage"} {
		if !seen[name] {
			return false
		}
	}
	allowed := map[string]bool{"binding.binary_sha256": true, "tokens.est_cost_usd": true, "tokens.unpriced_responses": true, "coverage.gaps[no-price-table]": true}
	used := map[string]bool{}
	for _, name := range c.NotCompared {
		if !allowed[name] || used[name] {
			return false
		}
		used[name] = true
	}
	return used["binding.binary_sha256"]
}

func (v *verifier) bundles(ctx context.Context) {
	names := BundleChecks()
	if v.in.Bundles == nil || len(v.f.files["receipt.sigstore.json"]) == 0 || len(v.f.files["manifest.sigstore.json"]) == 0 {
		for _, name := range names {
			v.add("bundle."+name, receipt.StepNotChecked, provenanceStatement, "not checked: no bundle")
		}
		v.add("bundle.times", receipt.StepNotChecked, provenanceStatement, "not checked: no bundle")
		return
	}
	checked, err := v.in.Bundles.Verify(ctx, BundleInput{Manifest: append([]byte{}, v.f.files["manifest.json"]...), Receipt: append([]byte{}, v.f.files["receipt.json"]...), ManifestBundle: append([]byte{}, v.f.files["manifest.sigstore.json"]...), ReceiptBundle: append([]byte{}, v.f.files["receipt.sigstore.json"]...), Expect: v.e})
	if err != nil {
		v.add("bundle", receipt.StepNotChecked, provenanceStatement, err.Error())
		return
	}
	seen := map[string]Check{}
	for _, check := range checked.Checks {
		if _, ok := seen[check.Name]; ok {
			v.add("bundle", receipt.StepFail, provenanceStatement, "duplicate bundle check")
			return
		}
		seen[check.Name] = check
	}
	if len(seen) != len(names) {
		v.add("bundle", receipt.StepFail, provenanceStatement, "missing or unknown mandatory bundle checks")
	}
	for _, name := range names {
		c, ok := seen[name]
		if !ok {
			v.add("bundle."+name, receipt.StepNotChecked, provenanceStatement, "required bundle/certificate field was not checked")
			continue
		}
		if c.Result != receipt.StepPass && c.Result != receipt.StepFail && c.Result != receipt.StepNotChecked {
			c.Result = receipt.StepNotChecked
		}
		v.add("bundle."+name, c.Result, provenanceStatement, c.Why)
	}
	start, _ := utc(v.e.Attempt.StartedAt)
	end, _ := utc(v.e.Attempt.CompletedAt)
	ok := len(checked.IntegratedTimes) == 2
	for _, when := range checked.IntegratedTimes {
		if when.Before(start.Add(-60*time.Second)) || when.After(end.Add(60*time.Second)) {
			ok = false
		}
	}
	v.res.IntegratedTimes = append([]time.Time{}, checked.IntegratedTimes...)
	v.test("bundle.times", provenanceStatement, ok, "both verified integration times fall in the independent exact-attempt window with 60 seconds skew")
}

func decodeSaved(data []byte) (*receipt.CheckResult, error) {
	step := obj(map[string]shape{"name": str, "result": str, "why": {kind: 's', optional: true}})
	by := obj(map[string]shape{"tego_version": str, "commit": str})
	s := obj(map[string]shape{"check_v": integer, "binding_v": integer, "result": str, "run": str, "lines": integer, "head": str, "ended": boolean, "coverage_complete": boolean, "complete": boolean, "checks": arr(step), "limits": arr(obj(map[string]shape{"code": str, "why": str})), "not_shown": arr(str), "receipt_by": by, "checked_by": by, "not_compared": arr(str)})
	var c receipt.CheckResult
	if err := decodeStrict(data, maxCheckBytes, s, &c); err != nil {
		return nil, fmt.Errorf("retained comparison: %w", err)
	}
	if c.Checks == nil || c.NotCompared == nil {
		return nil, errors.New("retained comparison has unchecked fields")
	}
	return &c, nil
}
