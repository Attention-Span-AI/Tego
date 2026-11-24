// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/contracts"
)

// compileHook stands for the draft compiler: a text with "slowtool" is a compile that ran out of time, with
// "gonetool" one whose caller gave up, with "quiettool" one that ran out of time without the machine being to
// blame, with "busytool" one that found no free compiler slot, with "deadtool" one whose compiler could not run, with "broken" a contract that does not compile.
func compileHook(f *fixture) {
	f.s.Compile = func(_ context.Context, _ CheckContext, text []byte) error {
		switch {
		case bytes.Contains(text, []byte("slowtool")):
			return contracts.CompileNotFinished(context.DeadlineExceeded)
		case bytes.Contains(text, []byte("gonetool")):
			return contracts.CompileNotFinished(context.Canceled)
		case bytes.Contains(text, []byte("quiettool")):
			return contracts.CompileNotFinishedUnclear(context.DeadlineExceeded)
		case bytes.Contains(text, []byte("workingtool")):
			return contracts.CompileNotFinishedWorking(context.DeadlineExceeded)
		case bytes.Contains(text, []byte("busytool")):
			return contracts.CompileUnavailable(true, errors.New("busy, try again"))
		case bytes.Contains(text, []byte("deadtool")):
			return contracts.CompileUnavailable(false, errors.New("draft compiler stopped: exit status 3"))
		case bytes.Contains(text, []byte("broken")):
			return errors.New("env.pass.1: this entry is not an environment variable name")
		}
		return nil
	}
}

// A draft compile that did not finish is not "the new contract does not compile": nobody knows, and the page says so
// in the words of a check that did not finish, for a structured edit and for a free one alike. A real compile
// error still says it does not compile.
func TestUnfinishedCompileIsNotACompileError(t *testing.T) {
	f := newFixture(t)
	compileHook(f)
	ref := f.ref(t, f.contract)
	for _, c := range []struct {
		tool, words string
	}{{"slowtool", contracts.CompileUnfinished}, {"gonetool", contracts.CompileCancelled}, {"quiettool", contracts.CompileNoAnswer},
		{"workingtool", contracts.CompileStillWorking}, {"busytool", contracts.CompileBusy}, {"deadtool", contracts.CompileCouldNotRun}} {
		t.Run(c.tool, func(t *testing.T) {
			structured, err := f.s.PlanChange(context.Background(), ChangeReq{Ref: ref.Ref, Base: ref.Base, Edits: []Edit{{"add", "exec.allow", c.tool}}})
			if err != nil {
				t.Fatal(err)
			}
			free, err := f.s.PlanRaw(context.Background(), RawReq{Ref: ref.Ref, Base: ref.Base, Text: []byte(strings.Replace(baseText, "name: tester", "name: "+c.tool, 1))})
			if err != nil {
				t.Fatal(err)
			}
			for what, p := range map[string]*ChangePlan{"structured": structured, "free": free} {
				if !strings.Contains(p.Err, c.words) || !strings.Contains(p.Err, "nothing was written; try again") || strings.Contains(p.Err, "does not compile") {
					t.Fatalf("%s edit: %q", what, p.Err)
				}
				if _, err := f.s.ApplyRaw(context.Background(), RawReq{Ref: ref.Ref, Base: ref.Base, Text: []byte(strings.Replace(baseText, "name: tester", "name: "+c.tool, 1))}); err == nil {
					t.Fatalf("%s edit: a compile that did not finish was written", what)
				}
			}
		})
	}
	if got := f.text(t); got != baseText {
		t.Fatalf("a compile that did not finish changed the contract:\n%s", got)
	}
	// A real compile error says what it always said.
	free, err := f.s.PlanRaw(context.Background(), RawReq{Ref: ref.Ref, Base: ref.Base, Text: []byte(strings.Replace(baseText, "name: tester", "name: broken", 1))})
	if err != nil || !strings.Contains(free.Err, "the new contract does not compile, so nothing was written: ") || strings.Contains(free.Err, "did not finish") {
		t.Fatalf("a real compile error: %v %q", err, free.Err)
	}
	structured, err := f.s.PlanChange(context.Background(), ChangeReq{Ref: ref.Ref, Base: ref.Base, Edits: []Edit{{"add", "exec.allow", "broken"}}})
	if err != nil || !strings.Contains(structured.Err, "does not compile") || strings.Contains(structured.Err, "did not finish") {
		t.Fatalf("a real compile error of a structured edit: %v %q", err, structured.Err)
	}
}
