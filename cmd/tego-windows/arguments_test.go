// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestWSLArguments(t *testing.T) {
	want := []string{"probe", "&", "|", "<", ">", "^", "%VAR%", "!", `say "hi"`, "", "two words", "--", "-c:v", "-x:", "-", "雪 café", strings.Repeat("a", 20000)}
	got, err := wslArguments(want)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got[:6], []string{"--distribution", "tego", "--user", "tego", "--exec", "/usr/local/lib/tego/windows-entry"}) {
		t.Fatal(got[:6])
	}
	raw, err := base64.StdEncoding.DecodeString(got[6])
	if err != nil {
		t.Fatal(err)
	}
	var args []string
	if err := json.Unmarshal(raw, &args); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatal("argument data changed")
	}
}

func TestNoArgumentsIsArray(t *testing.T) {
	got, err := wslArguments(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(got[6])
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "[]" {
		t.Fatalf("got %s", raw)
	}
}

func TestNULIsRefused(t *testing.T) {
	if _, err := wslArguments([]string{"nul\x00arg"}); err == nil {
		t.Fatal("NUL accepted")
	}
}

// A cold start that did not confirm its user scope tells the person to try the same command again, and the command
// that shows why when that fails twice: the doctor command the installer prints, built from the same entry.
func TestStartupFailureWordsSayWhatToDo(t *testing.T) {
	got := startupFailureWords("Linux did not confirm its required user scope within 90 seconds")
	for _, want := range []string{
		"Linux startup did not complete (Linux did not confirm its required user scope within 90 seconds).",
		"type the same command again",
		"nothing was changed by this try",
		"If it fails a second time",
		"wsl -d tego -u tego --exec /usr/local/lib/tego/windows-entry WyJkb2N0b3IiXQ==",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "wsl --status") {
		t.Errorf("still sends the person to wsl --status, which shows nothing about this:\n%s", got)
	}
}

// The launcher tells the person to keep a command or shell attached against WSL's idle shutdown: the words say what
// to do and why in terms a person has, and promise no duration.
func TestKeepAttachedWords(t *testing.T) {
	for _, want := range []string{"Keep a tego command or a Linux shell open", "while an agent works", "when nothing is attached", "ends any run still going"} {
		if !strings.Contains(keepAttachedWords, want) {
			t.Errorf("lacks %q: %s", want, keepAttachedWords)
		}
	}
	for _, bad := range []string{"second", "minute", "24/7", "always", "forever", "background"} {
		if strings.Contains(strings.ToLower(keepAttachedWords), bad) {
			t.Errorf("promises or measures something it must not (%q): %s", bad, keepAttachedWords)
		}
	}
	got := dashboardStoppedWords()
	if !strings.HasPrefix(got, "Stopped the dashboard's connection to your browser. To open the dashboard again, run: tego dashboard\n") || !strings.HasSuffix(got, keepAttachedWords) {
		t.Errorf("the stop line changed or lost the sentence:\n%s", got)
	}
}

// The Windows-only files cannot run here, so this reads them: `tego start` (and setup) says the sentence before it
// opens the project shell, and `tego dashboard --stop` says it through dashboardStoppedWords. A guest row runs the
// real command and reads the console.
func TestLauncherSaysKeepAttachedWhereItSpeaks(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	main := read("main_windows.go")
	start := strings.Index(main, `case len(args) == 1 && (args[0] == "start" || args[0] == "setup"):`)
	if start < 0 {
		t.Fatal("the start case moved: update this test with it")
	}
	arm := main[start:]
	if end := strings.Index(arm, "\n\t}\n\treturn code"); end > 0 {
		arm = arm[:end]
	}
	say, shell := strings.Index(arm, "fmt.Println(keepAttachedWords)"), strings.Index(arm, `linuxCommand([]string{"shell"}`)
	if say < 0 || shell < 0 || say > shell {
		t.Errorf("tego start must say keepAttachedWords before it opens the shell:\n%s", arm)
	}
	if dash := read("dashboard_windows.go"); !strings.Contains(dash, "fmt.Println(dashboardStoppedWords())") {
		t.Error("tego dashboard --stop does not say dashboardStoppedWords after it stopped a relay")
	}
}
