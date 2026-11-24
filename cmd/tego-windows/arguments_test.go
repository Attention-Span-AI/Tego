// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/json"
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
