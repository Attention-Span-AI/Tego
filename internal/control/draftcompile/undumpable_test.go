// SPDX-License-Identifier: Apache-2.0

package draftcompile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// dumpReport is the request reader of the child TestMain makes of "report-dumpable": at its first read it says on stderr
// whether the process is dumpable then, and ends the request, so the real Helper has made its hold, or not, before this
// runs.
type dumpReport struct{}

func (dumpReport) Read([]byte) (int, error) {
	dumpable, err := sys.Dumpable()
	fmt.Fprintf(os.Stderr, "dumpable=%v err=%v\n", dumpable, err)
	return 0, io.EOF
}

// TestCompilerChildIsUndumpableBeforeItReadsTheDraft: the child re-executes the program image, so it is dumpable again
// whatever the dashboard that started it is, and is handed the draft and the machine's snapshot and answers what the Rules
// page shows. The real Helper, in a real child, has the dumpable flag at 0 by the time it first reads its request.
func TestCompilerChildIsUndumpableBeforeItReadsTheDraft(t *testing.T) {
	cmd := exec.Command(os.Args[0], Argument)
	request, err := json.Marshal(Request{Text: []byte("report-dumpable")})
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdin = bytes.NewReader(request)
	var errs bytes.Buffer
	cmd.Stderr = &errs
	if err := cmd.Run(); err == nil {
		t.Fatal("the child that reads an empty request ended well")
	}
	if got := errs.String(); got != "dumpable=false err=<nil>\n" {
		t.Fatalf("the child said %q at its first read; want dumpable=false", got)
	}
}

// TestHelperIsNotRunWhenItCannotBeMadeUndumpable: the hold comes before the first byte of the request, and a child that
// cannot be made undumpable reads nothing, writes nothing and exits 125; a call that is not the helper's holds nothing.
func TestHelperIsNotRunWhenItCannotBeMadeUndumpable(t *testing.T) {
	old := makeUndumpable
	t.Cleanup(func() { makeUndumpable = old })
	var events []string
	makeUndumpable = func() error { events = append(events, "undumpable"); return errors.New("prctl: not permitted") }
	in := &countingReader{}
	var out bytes.Buffer
	if handled, code := Helper([]string{"tego-control", Argument}, in, &out); !handled || code != 125 || in.reads != 0 || out.Len() != 0 {
		t.Errorf("Helper with a failing hold = %v, %d, reads %d, wrote %q; want handled, 125, nothing read or written", handled, code, in.reads, out.String())
	}
	if handled, _ := Helper([]string{"tego-control", "serve"}, in, &out); handled || len(events) != 1 {
		t.Errorf("a call that is not the helper's: handled %v, holds %d (want not handled, and only the first call held)", handled, len(events))
	}
}

type countingReader struct{ reads int }

func (c *countingReader) Read([]byte) (int, error) { c.reads++; return 0, io.EOF }
