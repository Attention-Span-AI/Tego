// SPDX-License-Identifier: Apache-2.0

package cireceipt

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/platform/proc"
)

// CosignVerifier verifies immutable v0.3 bundles with a separately trusted cosign
// executable and Sigstore root. SHA256 must come from trusted configuration,
// never from retained evidence. No inherited credential or configuration is used.
type CosignVerifier struct {
	Path        string
	SHA256      string
	TrustedRoot []byte
	ScratchDir  string
	run         func(context.Context, string, []string, []string, string) error
}

// Verify authenticates both exact blobs and compares every certified identity.
func (v CosignVerifier) Verify(ctx context.Context, in BundleInput) (BundleResult, error) {
	return v.verify(ctx, in, false)
}

// VerifyReceipt authenticates a receipt alone. It makes no manifest or teardown
// claim; callers must also perform the ordinary receipt/record comparison.
func (v CosignVerifier) VerifyReceipt(ctx context.Context, data, bundle []byte, e Expect) (BundleResult, error) {
	return v.verify(ctx, BundleInput{Receipt: data, ReceiptBundle: bundle, Expect: e}, true)
}

func (v CosignVerifier) verify(ctx context.Context, in BundleInput, receiptOnly bool) (BundleResult, error) {
	var out BundleResult
	if !filepath.IsAbs(v.Path) || !hashPattern.MatchString(v.SHA256) || len(v.TrustedRoot) == 0 || len(v.TrustedRoot) > maxBundleBytes || v.ScratchDir == "" {
		return out, errors.New("bundle verification requires absolute pinned cosign, independent trusted root and private scratch")
	}
	// Validate caller expectations even when this entrypoint is used without Verify.
	ebytes, err := json.Marshal(in.Expect)
	if err != nil {
		return out, err
	}
	if _, err = DecodeExpect(ebytes); err != nil {
		return out, err
	}
	toolRoot, err := os.OpenRoot(filepath.Dir(v.Path))
	if err != nil {
		return out, err
	}
	tool, err := readRegular(ctx, toolRoot, filepath.Base(v.Path), 256<<20)
	closeErr := toolRoot.Close()
	if err != nil {
		return out, err
	}
	if closeErr != nil {
		return out, closeErr
	}
	if digest(tool) != v.SHA256 {
		return out, errors.New("cosign executable SHA-256 differs from independent pin")
	}
	dir, err := os.MkdirTemp(v.ScratchDir, "cosign-check-")
	if err != nil {
		return out, err
	}
	defer func() { _ = os.RemoveAll(dir) }() // only this verifier's private copies
	for _, name := range []string{"home", "tuf", "xdg"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
			return out, err
		}
	}
	for name, data := range map[string][]byte{"cosign": tool, "trusted_root.json": v.TrustedRoot} {
		mode := os.FileMode(0600)
		if name == "cosign" {
			mode = 0700
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, mode); err != nil {
			return out, err
		}
	}
	env := []string{"PATH=/usr/bin:/bin", "HOME=" + filepath.Join(dir, "home"), "TUF_ROOT=" + filepath.Join(dir, "tuf"), "XDG_CONFIG_HOME=" + filepath.Join(dir, "xdg"), "XDG_CACHE_HOME=" + filepath.Join(dir, "xdg"), "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"}
	run := v.run
	if run == nil {
		run = runCosign
	}
	blobs := []struct {
		name         string
		data, bundle []byte
	}{{"receipt", in.Receipt, in.ReceiptBundle}}
	if !receiptOnly {
		blobs = append(blobs, struct {
			name         string
			data, bundle []byte
		}{"manifest", in.Manifest, in.ManifestBundle})
	}
	for _, b := range blobs {
		cert, when, err := bundleCertificate(b.bundle)
		if err != nil {
			out.Checks = append(out.Checks, Check{Name: b.name + ".blob", Result: receipt.StepFail, Why: fmt.Sprintf("malformed bundle: %v", err)})
			return out, nil
		}
		if err := os.WriteFile(filepath.Join(dir, b.name+".json"), b.data, 0600); err != nil {
			return out, err
		}
		if err := os.WriteFile(filepath.Join(dir, b.name+".sigstore.json"), b.bundle, 0600); err != nil {
			return out, err
		}
		g := in.Expect.GitHub
		args := []string{"verify-blob", filepath.Join(dir, b.name+".json"), "--bundle", filepath.Join(dir, b.name+".sigstore.json"), "--trusted-root", filepath.Join(dir, "trusted_root.json"), "--certificate-identity", "https://github.com/" + g.JobWorkflowRef, "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", "--certificate-github-workflow-repository", g.Repository, "--certificate-github-workflow-sha", g.SourceSHA, "--certificate-github-workflow-ref", g.SourceRef, "--certificate-github-workflow-trigger", g.Event}
		err = run(ctx, filepath.Join(dir, "cosign"), args, env, dir)
		if err != nil {
			out.Checks = append(out.Checks, Check{Name: b.name + ".blob", Result: receipt.StepFail, Why: "pinned cosign refused blob, certificate, trust or inclusion"})
			return out, nil
		}
		for _, field := range []string{"blob", "trusted-roots", "inclusion"} {
			out.Checks = append(out.Checks, Check{Name: b.name + "." + field, Result: receipt.StepPass, Why: "pinned cosign verified exact private bytes against independent roots and transparency proof"})
		}
		checks := certificateChecks(cert, when, in.Expect)
		for _, c := range checks {
			c.Name = b.name + "." + c.Name
			out.Checks = append(out.Checks, c)
		}
		out.IntegratedTimes = append(out.IntegratedTimes, when)
	}
	return out, nil
}

// runCosign runs only after the reader has frozen inputs. receipt never owns
// fanotify marks; proc.Start also refuses an unexpected armed process.
func runCosign(ctx context.Context, path string, args, env []string, dir string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	cmd := proc.Command(path, args...)
	cmd.Env = env
	cmd.Dir = dir
	// Verification output is not a trust channel and may contain untrusted text.
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if _, err := proc.Start(cmd); err != nil {
		return err
	}
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
		return waitErr
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-done // Reap the child; cancellation determines the returned error.
		return ctx.Err()
	} // reap our child after cancellation
}

func bundleCertificate(data []byte) (*x509.Certificate, time.Time, error) {
	var zero time.Time
	if len(data) == 0 || len(data) > maxBundleBytes || !utf8.Valid(data) {
		return nil, zero, errors.New("missing, oversized or invalid UTF-8 bundle")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := uniqueJSON(d, 0); err != nil {
		return nil, zero, err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return nil, zero, errors.New("trailing bundle data")
	}
	// Exact-key maps avoid encoding/json's case-insensitive struct matching.
	// Only the same protobuf JSON field spellings verified by cosign supply claims.
	var top, material, certificate, promise map[string]json.RawMessage
	var entries []map[string]json.RawMessage
	var media, raw, integrated, set string
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, zero, err
	}
	if err := json.Unmarshal(top["mediaType"], &media); err != nil {
		return nil, zero, err
	}
	if media != "application/vnd.dev.sigstore.bundle.v0.3+json" && media != "application/vnd.dev.sigstore.bundle+json;version=0.3" {
		return nil, zero, errors.New("require Sigstore bundle v0.3")
	}
	if err := json.Unmarshal(top["verificationMaterial"], &material); err != nil {
		return nil, zero, err
	}
	if err := json.Unmarshal(material["certificate"], &certificate); err != nil {
		return nil, zero, err
	}
	if err := json.Unmarshal(certificate["rawBytes"], &raw); err != nil {
		return nil, zero, err
	}
	if err := json.Unmarshal(material["tlogEntries"], &entries); err != nil {
		return nil, zero, err
	}
	if len(entries) != 1 {
		return nil, zero, errors.New("require exactly one transparency entry")
	}
	entry := entries[0]
	if err := json.Unmarshal(entry["integratedTime"], &integrated); err != nil {
		return nil, zero, err
	}
	if err := json.Unmarshal(entry["inclusionPromise"], &promise); err != nil {
		return nil, zero, err
	}
	if err := json.Unmarshal(promise["signedEntryTimestamp"], &set); err != nil {
		return nil, zero, err
	}
	proof := entry["inclusionProof"]
	// The SET authenticates integratedTime. An inclusion proof alone does not.
	if len(proof) == 0 || bytes.Equal(proof, []byte("null")) || set == "" {
		return nil, zero, errors.New("require inclusion proof and signed integration time")
	}
	sec, err := strconv.ParseInt(integrated, 10, 64)
	if err != nil || sec <= 0 || strconv.FormatInt(sec, 10) != integrated {
		return nil, zero, errors.New("invalid transparency integration time")
	}
	der, err := base64.StdEncoding.Strict().DecodeString(raw)
	if err != nil {
		return nil, zero, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, zero, err
	}
	return cert, time.Unix(sec, 0).UTC(), nil
}

// uniqueJSON rejects duplicate spellings at every depth before two parsers can
// disagree about the bundle the external verifier and certificate reader saw.
func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("bundle nesting exceeds 32")
	}
	tok, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("duplicate bundle key")
			}
			seen[name] = true
			if err := uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected bundle delimiter")
	}
	_, err = d.Token()
	return err
}

func certificateChecks(cert *x509.Certificate, when time.Time, e Expect) []Check {
	g := e.GitHub
	wants := []struct {
		suffix      int
		name, value string
	}{{8, "issuer", "https://token.actions.githubusercontent.com"}, {9, "signer-uri", "https://github.com/" + g.JobWorkflowRef}, {10, "signer-digest", g.JobWorkflowSHA}, {11, "runner", "github-hosted"}, {12, "source-uri", "https://github.com/" + g.Repository}, {13, "source-digest", g.SourceSHA}, {14, "source-ref", g.SourceRef}, {15, "repository-id", g.RepositoryID}, {17, "owner-id", g.RepositoryOwnerID}, {18, "config-uri", "https://github.com/" + g.WorkflowRef}, {19, "config-digest", g.WorkflowSHA}, {20, "trigger", g.Event}, {21, "invocation", "https://github.com/" + g.Repository + "/actions/runs/" + g.RunID + "/attempts/" + g.RunAttempt}, {22, "visibility", g.Visibility}}
	values := map[int]string{}
	bad := map[int]bool{}
	prefix := "1.3.6.1.4.1.57264.1."
	for _, ext := range cert.Extensions {
		if !strings.HasPrefix(ext.Id.String(), prefix) {
			continue
		}
		suffix, err := strconv.Atoi(strings.TrimPrefix(ext.Id.String(), prefix))
		if err != nil {
			continue
		}
		if _, exists := values[suffix]; exists {
			bad[suffix] = true
		}
		value := string(ext.Value)
		if suffix >= 8 {
			var raw asn1.RawValue
			rest, err := asn1.Unmarshal(ext.Value, &raw)
			if err != nil || len(rest) != 0 || raw.Class != 0 || raw.Tag != asn1.TagUTF8String || raw.IsCompound || !utf8.Valid(raw.Bytes) {
				bad[suffix] = true
			} else {
				value = string(raw.Bytes)
			}
		}
		values[suffix] = value
	}
	var out []Check
	add := func(name string, ok bool, why string) {
		result := receipt.StepFail
		if ok {
			result = receipt.StepPass
		}
		out = append(out, Check{Name: name, Result: result, Why: why})
	}
	for _, want := range wants {
		value, exists := values[want.suffix]
		add(want.name, exists && !bad[want.suffix] && value == want.value, "required certificate extension compared with independent exact expectation")
	}
	add("certificate-validity", !when.Before(cert.NotBefore) && !when.After(cert.NotAfter), "verified integration time falls within leaf certificate validity")
	add("san", len(cert.URIs) == 1 && cert.URIs[0].String() == "https://github.com/"+g.JobWorkflowRef && len(cert.DNSNames) == 0 && len(cert.EmailAddresses) == 0 && len(cert.IPAddresses) == 0, "single URI SAN equals the expected reusable signer workflow")
	legacy := map[int]string{1: "https://token.actions.githubusercontent.com", 2: g.Event, 3: g.SourceSHA, 5: g.Repository, 6: g.SourceRef}
	consistent := true
	for suffix, want := range legacy {
		if got, exists := values[suffix]; exists && (bad[suffix] || got != want) {
			consistent = false
		}
	}
	// Legacy workflow name is a display name, not a certified configuration URI.
	// It has no comparable expected field; if supplied it must still be clean.
	if name, exists := values[4]; exists && (bad[4] || !clean(name)) {
		consistent = false
	}
	add("legacy-consistency", consistent, "present legacy issuer/source/ref/trigger values agree; workflow display name is not an identity")
	return out
}
