// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The scripts that drive tego start on a hosted Windows or Mac, and in a guest, answer its first question with
// "Another program". They read the list the guide draws (number_of, to_another_program), because the list follows the
// machine: a demonstration agent is first when no agent is installed and signed in, and last after one that is ready.
// This test draws the guide's real first question for both machine states and holds each driver's own choosing
// function to it: the item a driver picks must be "Another program", so a driver that assumes an order, or a guide
// whose list a driver can no longer read, fails here before a hosted run does.

// driverProbe loads a driver by path and prints what it would answer to the question drawn on its stdin: for the two
// drivers that type a number, that number; for the arrow-key driver, how many times it presses Down.
const driverProbe = `
import importlib.util, sys
spec = importlib.util.spec_from_file_location("driver", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
shown = sys.stdin.buffer.read()
if sys.argv[2] == "number":
    answer = module.number_of(b"Another program")(shown)
    print(answer.decode().strip())
else:
    answer = module.to_another_program(shown)
    assert answer.endswith(module.ENTER), answer
    presses = answer[:-len(module.ENTER)]
    assert presses == module.DOWN * (len(presses) // len(module.DOWN)), answer
    print(len(presses) // len(module.DOWN))
`

func TestHostedDriversChooseAnotherProgramFromTheGuidesRealMenu(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	drivers := []struct{ path, mode string }{
		{"../../test/hosted/mac/mac-install-ci.py", "number"},
		{"../../scripts/windows-hosted-guest.py", "number"},
		{"../../test/vm/guest-proof/drive-start.py", "arrows"},
	}
	// The fixture changes the working directory, so the scripts are found first.
	for i := range drivers {
		abs, err := filepath.Abs(drivers[i].path)
		if err != nil {
			t.Fatal(err)
		}
		drivers[i].path = abs
	}
	item := regexp.MustCompile(`(?m)^[ \t]*(\d+)\. (.*)$`)
	for _, machine := range []struct {
		name  string
		setup func(t *testing.T)
		first string
	}{
		{"no agent installed and signed in", machineNothing, guideDemo.label},
		{"an agent installed and signed in", func(t *testing.T) {
			fakeProgram(t, "claude")
			t.Setenv("ANTHROPIC_API_KEY", "x")
		}, "Claude Code"},
	} {
		t.Run(machine.name, func(t *testing.T) {
			onFixture(t, "fresh")
			noLogins(t)
			machine.setup(t)
			_, drawn, _ := runGuide(t, "")
			// The first question and its prompt: what a driver has seen when it must answer.
			menu, _, found := strings.Cut(drawn, "Enter a number")
			menu += "Enter a number"
			if !found {
				t.Fatalf("the guide drew no numbered first question:\n%s", drawn)
			}
			items := map[int]string{}
			for _, m := range item.FindAllStringSubmatch(menu, -1) {
				n, _ := strconv.Atoi(m[1])
				items[n] = m[2]
			}
			if !strings.HasPrefix(items[1], machine.first) {
				t.Fatalf("the drawn first question is not the one this test reads (item 1 should be %q):\n%s", machine.first, menu)
			}
			for _, d := range drivers {
				cmd := exec.Command(py, "-I", "-c", driverProbe, d.path, d.mode)
				cmd.Stdin = strings.NewReader(menu)
				var out, errs bytes.Buffer
				cmd.Stdout, cmd.Stderr = &out, &errs
				if err := cmd.Run(); err != nil {
					t.Fatalf("%s could not choose from the drawn menu: %v\n%s\nmenu:\n%s", d.path, err, errs.String(), menu)
				}
				n, err := strconv.Atoi(strings.TrimSpace(out.String()))
				if err != nil {
					t.Fatalf("%s answered %q", d.path, out.String())
				}
				if d.mode == "arrows" {
					n++ // presses Down from item 1
				}
				if !strings.HasPrefix(items[n], "Another program") {
					t.Errorf("%s picks item %d (%q) from the guide's menu, not \"Another program\":\n%s", d.path, n, items[n], menu)
				}
			}
		})
	}
}
