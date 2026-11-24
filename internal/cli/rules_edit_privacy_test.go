// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestEditorFailureSaysWhyWithoutTheCommand: `tego rules edit` tells apart an editor that was not found, one that
// could not be started, one that exited with a status and one a signal ended; it names the variable that chose the
// editor and never prints the command, which comes from the person's environment and may hold anything; and when
// neither variable is set it says that vi was tried, and blames no variable for it.
func TestEditorFailureSaysWhyWithoutTheCommand(t *testing.T) {
	dir := t.TempDir()
	script := func(name, body string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, c := range []struct {
		name, key, value, want string
	}{
		{"not found", "VISUAL", "qz-absent-editor --wait", "the editor $VISUAL names was not found; print it with: echo $VISUAL; nothing was saved"},
		{"not found by path", "EDITOR", filepath.Join(dir, "qz-absent"), "the editor $EDITOR names was not found; print it with: echo $EDITOR"},
		{"permission denied", "EDITOR", script("qz-noexec", "exit 0", 0o600), "the editor $EDITOR names could not be started: permission denied; print it with: echo $EDITOR"},
		{"exit status", "VISUAL", script("qz-status", "exit 3", 0o700) + " --flag", "the editor $VISUAL names exited with status 3; print it with: echo $VISUAL"},
		{"signal", "EDITOR", script("qz-signal", "kill -TERM $$", 0o700), "the editor $EDITOR names was ended by signal 15 (terminated); print it with: echo $EDITOR"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("VISUAL", "")
			t.Setenv("EDITOR", "")
			t.Setenv(c.key, c.value)
			var out bytes.Buffer
			if _, code := editCopy("agent.yaml", []byte("version: 0"), &out); code == 0 {
				t.Fatal("a failed editor was taken as a finished edit")
			}
			if got := out.String(); !strings.Contains(got, c.want) || strings.Contains(got, "qz-") || strings.Contains(got, "--") {
				t.Fatalf("want %q and no command text, got: %s", c.want, got)
			}
		})
	}
	t.Run("the fallback", func(t *testing.T) {
		t.Setenv("VISUAL", "")
		t.Setenv("EDITOR", "")
		t.Setenv("PATH", dir) // holds no vi
		var out bytes.Buffer
		editCopy("agent.yaml", []byte("version: 0"), &out)
		got := out.String()
		if !strings.Contains(got, "vi, the editor tried when neither VISUAL nor EDITOR is set, was not found; nothing was saved") || strings.Contains(got, "$") {
			t.Fatalf("the fallback's failure blames a variable: %s", got)
		}
	})
}

// TestConfigRefusalNamesTheSettingsFile: a refusal about the settings file $TEGO_CONFIG names prints that file, as it
// prints any settings file: the path is a place, and the person must see which file failed. A value that is not an
// absolute clean path of printable characters failed validation and is not echoed: the message names the variable and
// how to print it.
func TestConfigRefusalNamesTheSettingsFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "qz-machine.yaml")
	if err := os.WriteFile(file, []byte("{}"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o666); err != nil {
		t.Fatal(err)
	}
	_, _, err := config.LoadSources(config.Sources{EnvFile: file}, "", os.Getuid(), config.TrustAbort)
	if err == nil {
		t.Fatal("an untrusted layer was accepted")
	}
	var out bytes.Buffer
	configRefused(&out, "tego run", err)
	if got := out.String(); !strings.Contains(got, file) {
		t.Fatalf("the refusal does not name the settings file %s: %s", file, got)
	}
	// The relative values, and the two absolute ones that are still not places: one that is not clean and one that
	// holds a newline (neither file exists).
	dir := t.TempDir()
	for _, value := range []string{"qz-relative.yaml", "qz/../qz-relative.yaml", dir + "/qz-x/../qz-cfg.yaml", dir + "/qz-a\nb/qz-cfg.yaml"} {
		_, ds, err := config.LoadSources(config.Sources{EnvFile: value}, "", os.Getuid(), config.TrustAbort)
		if err == nil {
			t.Fatalf("$TEGO_CONFIG=%q was accepted", value)
		}
		out.Reset()
		configRefused(&out, "tego run", err)
		got := out.String()
		for _, d := range ds {
			got += d.String() + "\n"
		}
		if strings.Contains(got, "qz-") || !strings.Contains(got, "$TEGO_CONFIG") || !strings.Contains(got, "echo $TEGO_CONFIG") {
			t.Fatalf("a value %q that is not an absolute clean path was echoed, or the variable is not named: %s", value, got)
		}
	}
}
