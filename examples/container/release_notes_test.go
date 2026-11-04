// SPDX-License-Identifier: Apache-2.0

package container

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Called by TestReleaseWorkflow, including CI's explicit workflow test filter.
func testReleaseNotes(t *testing.T, workflow releaseWorkflow) {
	release := workflow.Jobs["release"]
	build := releaseStepNamed(t, release, "build, and create the draft release")
	requireReleaseValue(t, build.With["args"], "release --clean --release-notes ${{ runner.temp }}/release-notes.md")
	generate := releaseStepNamed(t, release, "the release notes are the tag's changelog section").Run
	checkDraft := releaseStepNamed(t, release, "verify the draft contains the changelog section").Run
	publish := releaseStepNamed(t, workflow.Jobs["publish"], "publish the release with its image digest").Run
	const notes = "\n### Changes\n\n- Notes from the tagged changelog.\n"
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, scenario := range []struct {
		name, phase, mode string
		ok, redraft       bool
	}{
		{"generate", "generate", "ok", true, false},
		{"empty-input", "generate", "empty", false, false},
		{"blank-input", "generate", "blank", false, false},
		{"draft", "draft", "ok", true, false},
		{"empty-draft", "draft", "empty", false, false},
		{"blank-draft", "draft", "blank", false, false},
		{"wrong-draft", "draft", "wrong", false, false},
		{"draft-read-failure", "draft", "error", false, false},
		{"publish", "publish", "ok", true, false},
		{"missing-notes-artifact", "publish", "artifact-missing", false, false},
		{"empty-notes-artifact", "publish", "artifact-empty", false, false},
		{"blank-notes-artifact", "publish", "artifact-blank", false, false},
		{"empty-before-publish", "publish", "empty", false, false},
		{"blank-before-publish", "publish", "blank", false, false},
		{"wrong-before-publish", "publish", "wrong", false, false},
		{"draft-read-failure-before-publish", "publish", "error", false, false},
		{"edit-applied-reports-failure", "publish", "edit-error", false, true},
		{"edit-applied-then-read-fails", "publish", "edit-error-read", false, true},
		{"edit-rejected", "publish", "edit-rejected", false, true},
		{"empty-after-publish", "publish", "post-empty", false, true},
		{"blank-after-publish", "publish", "post-blank", false, true},
		{"wrong-after-publish", "publish", "post-wrong", false, true},
		{"published-read-failure", "publish", "post-error", false, true},
		{"published-state-is-draft", "publish", "post-draft-state", false, true},
		{"published-state-unknown", "publish", "post-unknown-state", false, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			dir := t.TempDir()
			write := func(name, contents string, mode os.FileMode) {
				t.Helper()
				path := filepath.Join(dir, name)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(contents), mode); err != nil {
					t.Fatal(err)
				}
			}
			write("scripts/release.sh", "#!/bin/bash\nprintf '%s' \"$NOTES_FIXTURE\"\n", 0700)
			write("bin/gh", `#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" >> "$NOTES_TEST_ROOT/calls"
case "$1 $2" in
  'release view')
    mode=${DRAFT_MODE:-ok}
    if [ -f "$NOTES_TEST_ROOT/edit-attempted" ]; then
      mode=${POST_MODE:-ok}; touch "$NOTES_TEST_ROOT/read-after-edit"
    fi
    case "$mode" in
      empty) exit 0 ;;
      blank) printf ' \t\n' ;;
      wrong) printf 'Unrelated release body\n' ;;
      error) exit 1 ;;
      draft-state | unknown-state)
        # Emulate gh's --jq error when the workflow requires a public release.
        if [[ "$*" == *'if .isDraft == false'* ]]; then exit 1; fi
        cat "$NOTES_TEST_ROOT/remote-notes.md" ;;
      ok) cat "$NOTES_TEST_ROOT/remote-notes.md"; printf '\n' ;;
      *) exit 1 ;;
    esac ;;
  'release upload') exit 0 ;;
  'release edit')
    if [[ " $* " == *' --draft=false '* ]]; then
      touch "$NOTES_TEST_ROOT/edit-attempted"
      if [ "${EDIT_ERROR:-0}" = before ]; then exit 1; fi
    fi
    for ((i=1; i<=$#; i++)); do
      arg=${!i}
      if [ "$arg" = --notes-file ]; then
        j=$((i+1)); cp "${!j}" "$NOTES_TEST_ROOT/remote-notes.md"
      fi
      if [ "$arg" = --draft=false ]; then touch "$NOTES_TEST_ROOT/published"; fi
      if [ "$arg" = --draft=true ]; then
        rm -f "$NOTES_TEST_ROOT/published"; touch "$NOTES_TEST_ROOT/redrafted"
      fi
    done
    if [[ " $* " == *' --draft=false '* && "${EDIT_ERROR:-0}" = 1 ]]; then exit 1; fi ;;
  *) exit 1 ;;
esac
`, 0700)
			write("remote-notes.md", notes+"\n", 0600) // GoReleaser's body template may add a trailing newline.
			write("release-notes.md", notes, 0600)
			artifact := "release-notes/release-notes.md"
			artifactNotes := notes
			write(artifact, artifactNotes, 0600)
			write("release-signatures/tego_0.1.0_checksums.txt.sigstore.json", "inert bundle", 0600)
			fixture, draftMode, postMode, editError := notes, "ok", "ok", "0"
			script := generate
			switch scenario.phase {
			case "generate":
				switch scenario.mode {
				case "empty":
					fixture = ""
				case "blank":
					fixture = " \n\t\n"
				}
			case "draft":
				script, draftMode = checkDraft, scenario.mode
			case "publish":
				script = publish
				switch {
				case strings.HasPrefix(scenario.mode, "edit-error"):
					editError = "1"
					if scenario.mode == "edit-error-read" {
						postMode = "error"
					}
				case scenario.mode == "edit-rejected":
					editError = "before"
				case scenario.mode == "artifact-missing":
					if err := os.Remove(filepath.Join(dir, artifact)); err != nil {
						t.Fatal(err)
					}
				case scenario.mode == "artifact-empty", scenario.mode == "artifact-blank":
					artifactNotes = ""
					if scenario.mode == "artifact-blank" {
						artifactNotes = " \t\n"
					}
					write(artifact, artifactNotes, 0600)
				case strings.HasPrefix(scenario.mode, "post-"):
					postMode = strings.TrimPrefix(scenario.mode, "post-")
				default:
					draftMode = scenario.mode
				}
			}
			cmd := exec.Command("bash", "-c", script)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "RUNNER_TEMP="+dir, "NOTES_TEST_ROOT="+dir,
				"PATH="+filepath.Join(dir, "bin")+":"+os.Getenv("PATH"), "NOTES_FIXTURE="+fixture,
				"DRAFT_MODE="+draftMode, "POST_MODE="+postMode, "EDIT_ERROR="+editError,
				"TAG=v0.1.0", "DIGEST="+digest, "GITHUB_REPOSITORY=Attention-Span-AI/Tego", "GH_TOKEN=inert")
			out, err := cmd.CombinedOutput()
			if (err == nil) != scenario.ok {
				t.Fatalf("script error = %v: %s", err, out)
			}
			_, redraftErr := os.Stat(filepath.Join(dir, "redrafted"))
			requireReleaseValue(t, redraftErr == nil, scenario.redraft)
			if scenario.phase == "publish" {
				if scenario.mode != "artifact-missing" {
					contents, err := os.ReadFile(filepath.Join(dir, artifact))
					if err != nil {
						t.Fatal(err)
					}
					requireReleaseValue(t, string(contents), artifactNotes)
				}
				if scenario.redraft {
					if _, err := os.Stat(filepath.Join(dir, "read-after-edit")); err != nil {
						t.Fatalf("publication must be read back even after an edit error: %v", err)
					}
				}
				_, publicErr := os.Stat(filepath.Join(dir, "published"))
				requireReleaseValue(t, publicErr == nil, scenario.ok)
				if scenario.ok {
					body, err := os.ReadFile(filepath.Join(dir, "remote-notes.md"))
					if err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(string(body), notes) || !strings.Contains(string(body), "ghcr.io/attention-span-ai/tego@"+digest) {
						t.Fatalf("published body lost the changelog or digest: %s", body)
					}
				}
			}
		})
	}
}
