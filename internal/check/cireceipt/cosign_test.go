// SPDX-License-Identifier: Apache-2.0

package cireceipt

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

func certificateFixture(t *testing.T, e Expect) *x509.Certificate {
	t.Helper()
	g := e.GitHub
	now, _ := time.Parse(time.RFC3339, e.Attempt.StartedAt)
	uri, err := url.Parse("https://github.com/" + g.JobWorkflowRef)
	if err != nil {
		t.Fatal(err)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test only"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature}
	vals := map[int]string{8: "https://token.actions.githubusercontent.com", 9: uri.String(), 10: g.JobWorkflowSHA, 11: "github-hosted", 12: "https://github.com/" + g.Repository, 13: g.SourceSHA, 14: g.SourceRef, 15: g.RepositoryID, 17: g.RepositoryOwnerID, 18: "https://github.com/" + g.WorkflowRef, 19: g.WorkflowSHA, 20: g.Event, 21: "https://github.com/" + g.Repository + "/actions/runs/" + g.RunID + "/attempts/" + g.RunAttempt, 22: g.Visibility}
	for suffix, value := range vals {
		raw, err := asn1.MarshalWithParams(value, "utf8")
		if err != nil {
			t.Fatal(err)
		}
		c.Extensions = append(c.Extensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, suffix}, Value: raw})
	}
	return c
}

func cryptoBundleFixture(t *testing.T, c *x509.Certificate, when time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clone := *c
	clone.ExtraExtensions = c.Extensions
	der, err := x509.CreateCertificate(rand.Reader, &clone, &clone, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return asJSON(t, map[string]any{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": map[string]any{"certificate": map[string]any{"rawBytes": base64.StdEncoding.EncodeToString(der)}, "tlogEntries": []any{map[string]any{"integratedTime": strconv.FormatInt(when.Unix(), 10), "inclusionProof": map[string]any{"checkpoint": map[string]any{"envelope": "fixture"}}, "inclusionPromise": map[string]any{"signedEntryTimestamp": "Zml4dHVyZQ=="}}}}})
}

func allPass(checks []Check) bool {
	for _, c := range checks {
		if c.Result != "pass" {
			return false
		}
	}
	return true
}

func TestCertificateExactIdentity(t *testing.T) {
	f := evidence(t, "amd64")
	when, _ := time.Parse(time.RFC3339, f.expect.Attempt.StartedAt)
	c := certificateFixture(t, f.expect)
	if checks := certificateChecks(c, when, f.expect); !allPass(checks) || len(checks) != len(BundleChecks())/2-3 {
		t.Fatalf("good certificate: %+v", checks)
	}
	for i, ext := range c.Extensions {
		for _, mode := range []string{"missing", "wrong", "malformed", "duplicate"} {
			t.Run(ext.Id.String()+"/"+mode, func(t *testing.T) {
				clone := *c
				clone.Extensions = append([]pkix.Extension{}, c.Extensions...)
				switch mode {
				case "missing":
					clone.Extensions = append(clone.Extensions[:i], clone.Extensions[i+1:]...)
				case "wrong":
					clone.Extensions[i].Value = []byte{12, 1, 'x'}
				case "malformed":
					clone.Extensions[i].Value = []byte{12, 1, 'x', 0}
				case "duplicate":
					clone.Extensions = append(clone.Extensions, ext)
				}
				if allPass(certificateChecks(&clone, when, f.expect)) {
					t.Fatal("accepted bad required extension")
				}
			})
		}
	}
	for _, mode := range []string{"san", "expired", "legacy", "legacy-duplicate", "config-sha", "attempt", "source-sha", "self-hosted"} {
		t.Run(mode, func(t *testing.T) {
			clone := *c
			clone.Extensions = append([]pkix.Extension{}, c.Extensions...)
			expected := f.expect
			switch mode {
			case "san":
				clone.URIs = nil
			case "expired":
				clone.NotAfter = when.Add(-time.Second)
			case "legacy":
				clone.Extensions = append(clone.Extensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 3}, Value: []byte("wrong")})
			case "legacy-duplicate":
				for range 2 {
					clone.Extensions = append(clone.Extensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 3}, Value: []byte(expected.GitHub.SourceSHA)})
				}
			case "config-sha":
				expected.GitHub.WorkflowSHA = strings.Repeat("f", 40)
			case "attempt":
				expected.GitHub.RunAttempt = "3"
			case "source-sha":
				expected.GitHub.SourceSHA = strings.Repeat("f", 40)
			case "self-hosted":
				for i, e := range clone.Extensions {
					if e.Id[len(e.Id)-1] == 11 {
						clone.Extensions[i].Value = []byte{12, 11, 's', 'e', 'l', 'f', '-', 'h', 'o', 's', 't', 'e', 'd'}
					}
				}
			}
			if allPass(certificateChecks(&clone, when, expected)) {
				t.Fatal("accepted wrong identity")
			}
		})
	}
}

func TestBundleStrictParsing(t *testing.T) {
	f := evidence(t, "amd64")
	when, _ := time.Parse(time.RFC3339, f.expect.Attempt.StartedAt)
	good := cryptoBundleFixture(t, certificateFixture(t, f.expect), when)
	if _, _, err := bundleCertificate(good); err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(good, &obj); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"duplicate", "escaped-duplicate", "trailing", "wrong-version", "missing-cert", "two-entries", "unsigned-time", "missing-proof", "bad-time", "case-alias"} {
		t.Run(name, func(t *testing.T) {
			var obj map[string]any
			if err := json.Unmarshal(good, &obj); err != nil {
				t.Fatal(err)
			}
			m := obj["verificationMaterial"].(map[string]any)
			entry := m["tlogEntries"].([]any)[0].(map[string]any)
			switch name {
			case "wrong-version":
				obj["mediaType"] = "v1"
			case "missing-cert":
				delete(m, "certificate")
			case "two-entries":
				m["tlogEntries"] = []any{entry, entry}
			case "unsigned-time":
				delete(entry, "inclusionPromise")
			case "missing-proof":
				delete(entry, "inclusionProof")
			case "bad-time":
				entry["integratedTime"] = "1e3"
			case "case-alias":
				entry["IntegratedTime"] = entry["integratedTime"]
				delete(entry, "integratedTime")
			}
			data := asJSON(t, obj)
			switch name {
			case "duplicate":
				data = []byte(strings.Replace(string(data), `"mediaType":`, `"mediaType":"x","mediaType":`, 1))
			case "escaped-duplicate":
				data = []byte(strings.Replace(string(data), `"rawBytes":`, `"raw\u0042ytes":"","rawBytes":`, 1))
			case "trailing":
				data = append(data, []byte(" {}")...)
			}
			if _, _, err := bundleCertificate(data); err == nil {
				t.Fatal("accepted malformed bundle")
			}
		})
	}
}

func TestCosignFrozenBoundary(t *testing.T) {
	f := evidence(t, "arm64")
	when, _ := time.Parse(time.RFC3339, f.expect.Attempt.StartedAt)
	receiptBundle := cryptoBundleFixture(t, certificateFixture(t, f.expect), when)
	manifestBundle := cryptoBundleFixture(t, certificateFixture(t, f.expect), when)
	tool := []byte("test tool bytes")
	toolDir := t.TempDir()
	write(t, toolDir, "cosign", tool)
	v := CosignVerifier{Path: filepath.Join(toolDir, "cosign"), SHA256: digest(tool), TrustedRoot: []byte(`{"test":"independent"}`), ScratchDir: t.TempDir()}
	inputs := []struct {
		name         string
		data, bundle []byte
	}{{"receipt", []byte("receipt bytes"), receiptBundle}, {"manifest", []byte("manifest bytes"), manifestBundle}}
	calls := 0
	frozenDir := ""
	v.run = func(_ context.Context, path string, args, env []string, dir string) error {
		if calls >= len(inputs) {
			t.Fatal("unexpected verification call")
		}
		input := inputs[calls]
		calls++
		if filepath.Dir(dir) != v.ScratchDir || path != filepath.Join(dir, "cosign") || path == v.Path {
			t.Fatalf("tool or working directory is outside private scratch: %q %q", path, dir)
		}
		if frozenDir != "" && dir != frozenDir {
			t.Fatal("the two blobs used different frozen input directories")
		}
		frozenDir = dir
		info, err := os.Stat(dir)
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatalf("private scratch mode: %v %v", info, err)
		}
		g := f.expect.GitHub
		wantArgs := []string{"verify-blob", filepath.Join(dir, input.name+".json"), "--bundle", filepath.Join(dir, input.name+".sigstore.json"), "--trusted-root", filepath.Join(dir, "trusted_root.json"), "--certificate-identity", "https://github.com/" + g.JobWorkflowRef, "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", "--certificate-github-workflow-repository", g.Repository, "--certificate-github-workflow-sha", g.SourceSHA, "--certificate-github-workflow-ref", g.SourceRef, "--certificate-github-workflow-trigger", g.Event}
		if !slices.Equal(args, wantArgs) {
			t.Fatalf("verification arguments differ:\ngot  %q\nwant %q", args, wantArgs)
		}
		for name, want := range map[string][]byte{"cosign": tool, "trusted_root.json": v.TrustedRoot, input.name + ".json": input.data, input.name + ".sigstore.json": input.bundle} {
			file := filepath.Join(dir, name)
			got, err := os.ReadFile(file)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("frozen %s bytes differ: %v", name, err)
			}
			mode := os.FileMode(0600)
			if name == "cosign" {
				mode = 0700
			}
			info, err := os.Stat(file)
			if err != nil || info.Mode().Perm() != mode {
				t.Fatalf("frozen %s mode differs: %v %v", name, info, err)
			}
		}
		wantEnv := []string{"PATH=/usr/bin:/bin", "HOME=" + filepath.Join(dir, "home"), "TUF_ROOT=" + filepath.Join(dir, "tuf"), "XDG_CONFIG_HOME=" + filepath.Join(dir, "xdg"), "XDG_CACHE_HOME=" + filepath.Join(dir, "xdg"), "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"}
		if !slices.Equal(env, wantEnv) {
			t.Fatalf("verification environment differs: %q", env)
		}
		return nil
	}
	out, err := v.Verify(context.Background(), BundleInput{Receipt: inputs[0].data, Manifest: inputs[1].data, ReceiptBundle: receiptBundle, ManifestBundle: manifestBundle, Expect: f.expect})
	if err != nil || calls != 2 || len(out.Checks) != len(BundleChecks()) || !allPass(out.Checks) {
		t.Fatalf("result: %+v err %v calls %d", out, err, calls)
	}
	if _, err := os.Stat(frozenDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private frozen inputs were retained: %v", err)
	}
	v.SHA256 = strings.Repeat("0", 64)
	if _, err := v.VerifyReceipt(context.Background(), []byte("r"), receiptBundle, f.expect); err == nil {
		t.Fatal("wrong cosign digest accepted")
	}
	v.SHA256 = digest(tool)
	v.run = func(context.Context, string, []string, []string, string) error { return errors.New("crypto failed") }
	out, err = v.VerifyReceipt(context.Background(), []byte("r"), receiptBundle, f.expect)
	if err != nil || allPass(out.Checks) {
		t.Fatal("cosign failure passed")
	}
}

func TestCosignProcessGateAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runCosign(ctx, "/bin/true", nil, []string{"PATH=/usr/bin:/bin"}, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled verification: %v", err)
	}
	disarm := proc.Arm()
	defer disarm()
	if err := runCosign(context.Background(), "/bin/true", nil, []string{"PATH=/usr/bin:/bin"}, t.TempDir()); !errors.Is(err, proc.ErrArmed) {
		t.Fatalf("armed verification: %v", err)
	}
}

func TestPublicReleaseBundleShape(t *testing.T) {
	data, err := os.ReadFile("testdata/public-release-v0.1.2.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	c, when, err := bundleCertificate(data)
	if err != nil {
		t.Fatal(err)
	}
	required := map[int]bool{8: false, 9: false, 10: false, 11: false, 12: false, 13: false, 14: false, 15: false, 17: false, 18: false, 19: false, 20: false, 21: false, 22: false}
	for _, ext := range c.Extensions {
		oid := ext.Id.String()
		prefix := "1.3.6.1.4.1.57264.1."
		if !strings.HasPrefix(oid, prefix) {
			continue
		}
		suffix, err := strconv.Atoi(strings.TrimPrefix(oid, prefix))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := required[suffix]; ok {
			var value asn1.RawValue
			rest, err := asn1.Unmarshal(ext.Value, &value)
			if err != nil || len(rest) != 0 || value.Tag != asn1.TagUTF8String {
				t.Fatalf("modern extension %d malformed", suffix)
			}
			required[suffix] = true
			t.Logf("extension %d: %s", suffix, value.Bytes)
		}
	}
	for suffix, present := range required {
		if !present {
			t.Errorf("ordinary public release missing modern extension %d", suffix)
		}
	}
	if when.Before(c.NotBefore) || when.After(c.NotAfter) {
		t.Fatal("integration time outside certificate validity")
	}
	t.Logf("public v0.1.2 bundle: v0.3, one transparency entry, SET and inclusion proof, %d modern fields, integration time %s", len(required), when.Format(time.RFC3339))
}
