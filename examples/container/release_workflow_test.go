// SPDX-License-Identifier: Apache-2.0

package container

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type releaseStep struct {
	Name, ID, Uses, Run, Shell, If string
	With, Env                      map[string]string
	ContinueOnError                bool `yaml:"continue-on-error"`
}

type releaseJob struct {
	Needs           yaml.Node
	Permissions     map[string]string
	Steps           []releaseStep
	Env, Outputs    map[string]string
	If              string
	ContinueOnError bool `yaml:"continue-on-error"`
}

type releaseWorkflow struct {
	On          map[string]any
	Permissions map[string]string
	Jobs        map[string]releaseJob
}

func readReleaseWorkflow(t *testing.T) releaseWorkflow {
	t.Helper()
	b, err := os.ReadFile("../../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	var w releaseWorkflow
	if err := yaml.Unmarshal(b, &w); err != nil {
		t.Fatal(err)
	}
	return w
}

func releaseStepNamed(t *testing.T, j releaseJob, name string) releaseStep {
	t.Helper()
	for _, s := range j.Steps {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("missing step %q", name)
	return releaseStep{}
}

func requireReleaseValue(t *testing.T, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v; want %#v", got, want)
	}
}

// This runs in scripts-and-workflows and the unit/private gates, and ships in the public export.
func TestReleaseWorkflow(t *testing.T) {
	w := readReleaseWorkflow(t)
	configBytes, err := os.ReadFile("../../.goreleaser.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var config struct{ Changelog struct{ Disable bool } }
	if err := yaml.Unmarshal(configBytes, &config); err != nil {
		t.Fatal(err)
	}
	// Disabling this pipe also discards --release-notes, producing an empty draft body.
	requireReleaseValue(t, config.Changelog.Disable, false)
	requireReleaseValue(t, w.On, map[string]any{"push": map[string]any{"tags": []any{"v*"}}})
	requireReleaseValue(t, w.Permissions, map[string]string{"contents": "read"})
	needs := map[string][]string{
		"gate": nil, "release": {"gate"}, "reproduce": {"release"},
		"container": {"release", "reproduce"}, "sign": {"release", "reproduce", "container"},
		"publish": {"release", "reproduce", "container", "sign"},
	}
	permissions := map[string]map[string]string{
		"gate": {"contents": "read", "actions": "read"}, "release": {"contents": "write"},
		"reproduce": {"contents": "read"}, "container": {"contents": "read", "packages": "write"},
		"sign":    {"contents": "read", "packages": "write", "id-token": "write", "attestations": "write"},
		"publish": {"contents": "write"},
	}
	requireReleaseValue(t, len(w.Jobs), len(needs))
	pin := regexp.MustCompile(`^[\w./-]+@[0-9a-f]{40}$`)
	for name, job := range w.Jobs {
		t.Run(name, func(t *testing.T) {
			var got []string
			if job.Needs.Kind == yaml.ScalarNode {
				got = []string{job.Needs.Value}
			} else if err := job.Needs.Decode(&got); err != nil {
				t.Fatal(err)
			}
			slices.Sort(got)
			want := slices.Clone(needs[name])
			slices.Sort(want)
			requireReleaseValue(t, got, want)
			requireReleaseValue(t, job.Permissions, permissions[name])
			if job.If != "" || job.ContinueOnError {
				t.Fatal("release jobs must depend on success without an override")
			}
			checkouts := 0
			for _, step := range job.Steps {
				if step.ContinueOnError || step.If != "" {
					t.Fatalf("step %q can bypass failure", step.Name)
				}
				if step.Uses != "" && !pin.MatchString(step.Uses) {
					t.Fatalf("action without a full commit pin: %s", step.Uses)
				}
				if strings.HasPrefix(step.Uses, "actions/checkout@") {
					checkouts++
					requireReleaseValue(t, step.With["ref"], "${{ github.sha }}")
					requireReleaseValue(t, step.With["persist-credentials"], "false")
				}
			}
			wantCheckouts := 0
			if name == "release" || name == "reproduce" || name == "container" {
				wantCheckouts = 1
			}
			requireReleaseValue(t, checkouts, wantCheckouts)
		})
	}
	ciBytes, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var ci releaseWorkflow
	if err := yaml.Unmarshal(ciBytes, &ci); err != nil {
		t.Fatal(err)
	}
	ciTest := releaseStepNamed(t, ci.Jobs["scripts-and-workflows"], "release workflow authority, artifact and digest boundaries")
	requireReleaseValue(t, ciTest.Run, "go test -count=1 ./examples/container/ -run '^TestRelease(Workflow|SigningInputs|AssetStaging)$'")
	for _, handoff := range []struct{ job, action, artifact, path string }{
		{"release", "upload", "release-notes", "${{ runner.temp }}/release-notes.md"},
		{"release", "upload", "release-assets", "${{ runner.temp }}/release-assets"},
		{"release", "upload", "container-binaries", "${{ runner.temp }}/container-binaries"},
		{"container", "download", "container-binaries", "${{ runner.temp }}/container-binaries"},
		{"container", "upload", "image-digest", "${{ runner.temp }}/image-digest.txt"},
		{"sign", "download", "release-assets", "${{ runner.temp }}/release-assets"},
		{"sign", "download", "image-digest", "${{ runner.temp }}/image-digest"},
		{"sign", "upload", "release-signatures", "${{ runner.temp }}/release-assets/*.sigstore.json"},
		{"publish", "download", "release-signatures", "${{ runner.temp }}/release-signatures"},
		{"publish", "download", "release-notes", "${{ runner.temp }}/release-notes"},
	} {
		found := 0
		for _, step := range w.Jobs[handoff.job].Steps {
			if strings.HasPrefix(step.Uses, "actions/"+handoff.action+"-artifact@") && step.With["name"] == handoff.artifact {
				found++
				requireReleaseValue(t, step.With["path"], handoff.path)
				if handoff.action == "download" {
					// No alternate run/repository/token: inputs must come from this gated tag run.
					requireReleaseValue(t, len(step.With), 2)
				} else {
					requireReleaseValue(t, step.With["if-no-files-found"], "error")
				}
			}
		}
		requireReleaseValue(t, found, 1)
	}

	image := w.Jobs["container"]
	requireReleaseValue(t, image.Env["IMAGE"], "ghcr.io/attention-span-ai/tego")
	requireReleaseValue(t, image.Outputs["digest"], "${{ steps.image.outputs.digest }}")
	build := releaseStepNamed(t, image, "build and push the release image")
	for key, want := range map[string]string{
		"context": ".", "file": "examples/container/Dockerfile", "target": "runtime",
		"outputs":   "type=registry,oci-mediatypes=true",
		"platforms": "linux/amd64,linux/arm64", "build-args": "BINARY_SOURCE=verified",
		"build-contexts": "release=${{ runner.temp }}/container-binaries", "push": "true", "provenance": "false",
	} {
		requireReleaseValue(t, build.With[key], want)
	}
	for _, field := range []string{"source", "revision", "version", "licenses", "description"} {
		for _, key := range []string{"labels", "annotations"} {
			if !strings.Contains(build.With[key], "org.opencontainers.image."+field+"=") {
				t.Errorf("missing OCI %s in %s", field, key)
			}
		}
	}
	sign := w.Jobs["sign"]
	// Fulcio's SAN is job_workflow_ref, independent of the job ID/name. The installer builds the same URL.
	requireReleaseValue(t, sign.Env["SIGNER"], "${{ github.server_url }}/${{ github.repository }}/.github/workflows/release.yml@${{ github.ref }}")
	installer, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(installer), `signer="https://github.com/${repo_owner}/${repo_name}/.github/workflows/release.yml@refs/tags/${tag}"`) ||
		!strings.Contains(string(installer), `--cert-identity "$signer" --source-ref "refs/tags/${tag}"`) {
		t.Fatal("installer identity must bind to the workflow and tag")
	}
	allowedActions := []string{"actions/download-artifact", "actions/upload-artifact", "sigstore/cosign-installer", "actions/attest-build-provenance", "docker/login-action"}
	allowedRuns := []string{"verify the signing inputs", "sign the checksums file (keyless)", "verify the signature as an installer will", "sign and verify the image digest (keyless)", "record the signed image digest"}
	buildCommands := regexp.MustCompile(`(?m)(^|[\n;&|]\s*)\s*(go |make\b|goreleaser\b|npm\b|docker\s+build|\./|scripts/|bash\b|sh\b|source\b)`)
	for _, step := range sign.Steps {
		if step.Uses != "" && !slices.Contains(allowedActions, strings.Split(step.Uses, "@")[0]) {
			t.Fatalf("build or unreviewed action in signing job: %s", step.Uses)
		}
		if step.Run != "" && (!slices.Contains(allowedRuns, step.Name) || buildCommands.MatchString(step.Run)) {
			t.Fatalf("build or unreviewed script in signing job: %s", step.Name)
		}
	}
	for _, name := range []string{"verify the signature as an installer will", "sign and verify the image digest (keyless)"} {
		run := releaseStepNamed(t, sign, name).Run
		if !strings.Contains(run, `--certificate-identity "$SIGNER"`) || !strings.Contains(run, "--certificate-oidc-issuer https://token.actions.githubusercontent.com") {
			t.Fatalf("%s does not verify the installer identity and issuer", name)
		}
	}
	verify := releaseStepNamed(t, sign, "verify the signing inputs")
	requireReleaseValue(t, verify.ID, "verify")
	requireReleaseValue(t, verify.Env["EXPECTED_DIGEST"], "${{ needs.container.outputs.digest }}")
	blobSign := releaseStepNamed(t, sign, "sign the checksums file (keyless)")
	requireReleaseValue(t, blobSign.Env["SUMS"], "${{ steps.verify.outputs.sums }}")
	imageSign := releaseStepNamed(t, sign, "sign and verify the image digest (keyless)")
	requireReleaseValue(t, imageSign.Env["DIGEST"], "${{ steps.verify.outputs.digest }}")
	if !strings.Contains(imageSign.Run, `cosign sign --yes "$IMAGE@$DIGEST"`) {
		t.Fatal("image must be signed by verified digest")
	}

	attest := releaseStepNamed(t, sign, "attest build provenance for the image digest")
	requireReleaseValue(t, attest.With, map[string]string{
		"subject-name": "${{ env.IMAGE }}", "subject-digest": "${{ steps.verify.outputs.digest }}",
		"push-to-registry": "true", "create-storage-record": "false",
	})
	files := releaseStepNamed(t, sign, "attest build provenance for every checksummed file")
	requireReleaseValue(t, files.With["subject-checksums"], "${{ steps.verify.outputs.sums }}")
	requireReleaseValue(t, files.With["create-storage-record"], "false")
	requireReleaseValue(t, sign.Outputs["digest"], "${{ steps.verify.outputs.digest }}")
	publish := releaseStepNamed(t, w.Jobs["publish"], "publish the release with its image digest")
	requireReleaseValue(t, publish.Env["DIGEST"], "${{ needs.sign.outputs.digest }}")
	if !strings.Contains(publish.Run, `gh release upload "$TAG" "$bundle"`) ||
		strings.Index(publish.Run, "gh release upload") > strings.Index(publish.Run, "--draft=false") {
		t.Fatal("signature must be uploaded successfully before publishing")
	}
	t.Run("notes", func(t *testing.T) { testReleaseNotes(t, w) })
}

// Exercise the actual isolated signer verification script, including its registry reads, with inert bytes.
// A mock registry is intentional: no network credentials, OIDC token or downloaded project code is executed.
func TestReleaseSigningInputs(t *testing.T) {
	run := releaseStepNamed(t, readReleaseWorkflow(t).Jobs["sign"], "verify the signing inputs").Run
	if run == "" {
		t.Fatal("missing verification script")
	}
	for _, name := range []string{"valid", "valid-no-newline", "unsafe-path-no-newline", "licenses", "missing-binary", "changed-binary", "missing-checksum", "bad-control-pin", "missing-asset", "changed-asset", "missing-sums", "unsafe-path", "missing-digest", "wrong-digest", "registry-digest", "source", "revision", "version", "platform"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			write := func(path string, data []byte) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			assets := filepath.Join(dir, "release-assets")
			var sums strings.Builder
			for _, arch := range []string{"amd64", "arm64"} {
				control := []byte("inert control " + arch)
				hash := sha256.Sum256(control)
				pin := hex.EncodeToString(hash[:])
				if name == "bad-control-pin" {
					pin = "broken pin"
				}
				for bin, data := range map[string][]byte{"tego-control": control, "tego": []byte("inert tego " + pin)} {
					file := fmt.Sprintf("%s_0.1.0_linux_%s", bin, arch)
					if !(name == "missing-checksum" && bin == "tego" && arch == "arm64") {
						fmt.Fprintf(&sums, "%x  %s\n", sha256.Sum256(data), file)
					}
					if name == "missing-binary" && bin == "tego" && arch == "arm64" {
						continue
					}
					if name == "changed-binary" && bin == "tego" && arch == "arm64" {
						data = []byte("changed")
					}
					write(filepath.Join(assets, file), data)
				}
			}
			licence := []byte("inert licence")
			fmt.Fprintf(&sums, "%x  LICENSE\n", sha256.Sum256(licence))
			if name == "changed-asset" {
				licence = []byte("changed")
			}
			if name != "missing-asset" {
				write(filepath.Join(assets, "LICENSE"), licence)
			}

			if name == "unsafe-path" {
				fmt.Fprintf(&sums, "%064d  ../outside\n", 1)
			}
			if name == "unsafe-path-no-newline" {
				// A matching outside file makes this fail only if path validation catches the final line.
				outside := []byte("must not read outside the release assets")
				write(filepath.Join(dir, "outside"), outside)
				fmt.Fprintf(&sums, "%x  ../outside", sha256.Sum256(outside))
			}
			checksumText := sums.String()
			if name == "valid-no-newline" {
				checksumText = strings.TrimSuffix(checksumText, "\n")
			}

			if name != "missing-sums" {
				write(filepath.Join(assets, "tego_0.1.0_checksums.txt"), []byte(checksumText))
			}
			annotations := map[string]string{"source": "https://github.com/Attention-Span-AI/Tego", "revision": "tagged-commit", "version": "0.1.0", "licenses": "Apache-2.0"}
			if _, ok := annotations[name]; ok {
				annotations[name] = "wrong"
			}
			oci := map[string]string{}
			for key, value := range annotations {
				oci["org.opencontainers.image."+key] = value
			}
			platform := "arm64"
			if name == "platform" {
				platform = "386"
			}
			manifest, err := json.Marshal(map[string]any{"annotations": oci, "manifests": []any{
				map[string]any{"platform": map[string]string{"os": "linux", "architecture": "amd64"}},
				map[string]any{"platform": map[string]string{"os": "linux", "architecture": platform}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			digest := fmt.Sprintf("sha256:%x", sha256.Sum256(manifest))
			expected := digest
			if name == "wrong-digest" {
				expected = "sha256:" + strings.Repeat("0", 64)
			}
			if name == "missing-digest" {
				digest = ""
			}
			write(filepath.Join(dir, "image-digest/image-digest.txt"), []byte(digest+"\n"))
			if name == "registry-digest" {
				manifest = append(manifest, '\n')
			}
			write(filepath.Join(dir, "registry.json"), manifest)
			curl := filepath.Join(dir, "bin/curl")
			write(curl, []byte("#!/bin/bash\nset -eu\ncase \"$*\" in\n *ghcr.io/token*) printf '{\"token\":\"test-token\"}' ;;\n *ghcr.io/v2/*/manifests/*) while [ \"$1\" != -o ]; do shift; done; cp \"$RUNNER_TEMP/registry.json\" \"$2\" ;;\n *) exit 1 ;;\nesac\n"))
			if err := os.Chmod(curl, 0700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", run)
			cmd.Env = append(os.Environ(), "RUNNER_TEMP="+dir, "PATH="+filepath.Dir(curl)+":"+os.Getenv("PATH"),
				"TAG=v0.1.0", "EXPECTED_DIGEST="+expected, "GITHUB_OUTPUT="+filepath.Join(dir, "outputs"),
				"GITHUB_ACTOR=test", "GH_TOKEN=inert", "GITHUB_SERVER_URL=https://github.com", "GITHUB_REPOSITORY=Attention-Span-AI/Tego", "GITHUB_SHA=tagged-commit")
			out, err := cmd.CombinedOutput()
			if (err == nil) != strings.HasPrefix(name, "valid") {
				t.Fatalf("verification error = %v: %s", err, out)
			}
		})
	}
}
