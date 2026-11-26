// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/internal/testutil/answertest"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// The three answers a test gives a caller: outside every run; inside one (its cgroup path shows it); and unknown,
// as in a cgroup namespace that is not the machine's first one and has no proof.
func answerOutside() runscope.Answer { return answertest.Outside() }

func answerGoverned() runscope.Answer {
	return answertest.Inside(runscope.CauseGoverned)
}

func answerUnknown() runscope.Answer {
	return runscope.Unproven(runscope.CauseUserNamespace, nil)
}

// TestOnlyAnOutsideAnswerPermits walks the one table of answers (answertest.Rows: the zero value, every way of
// being inside, every cause of unknown, outside) over every caller in this package: the guidance lines, the four
// governed refusals (a governance change, a change to another run, setup, learn --save), the entry into a user scope
// and its rehearsal, what the guide is told of this process, and what the scan is handed. Each permits on outside
// alone. The re-entered process's own check is TestScopeProtocolBeforeCommit's (the rows "unknown membership" and
// "the zero answer"); the control plane, the peer check and the scan walk the same table in their own packages.
func TestOnlyAnOutsideAnswerPermits(t *testing.T) {
	for _, row := range answertest.Rows() {
		t.Run(row.Name, func(t *testing.T) {
			scopeStands(t)
			selfAnswer = row.Self
			oldRun := selfRun
			selfRun = func() (string, error) { return "r-own", nil }
			t.Cleanup(func() { selfRun = oldRun })

			if got := hintsOn(io.Discard); got != row.Permits {
				t.Errorf("hintsOn = %v", got)
			}
			var b strings.Builder
			if refused := refuseGoverned("unblock", &b); refused == row.Permits {
				t.Errorf("refuseGoverned refused = %v", refused)
			}
			if refused := refuseCrossRun("block", "r-other", &b); refused == row.Permits {
				t.Errorf("refuseCrossRun refused = %v", refused)
			}
			if refused := refuseSaveGoverned(&b); refused == row.Permits {
				t.Errorf("refuseSaveGoverned refused = %v", refused)
			}
			if refused := refuseSetup("setup", &b); !row.Permits && !refused {
				t.Error("refuseSetup did not refuse")
			} else if row.Permits && refused && os.Geteuid() != 0 {
				t.Errorf("refuseSetup refused an outside caller: %s", b.String())
			}
			if refused := refuseUninstall(&b); refused == row.Permits {
				t.Errorf("refuseUninstall refused = %v", refused)
			}
			if !row.Permits {
				if out := b.String(); strings.Count(out, "["+codeGoverned+"]") < 5 {
					t.Errorf("the refusals do not all carry [%s]:\n%s", codeGoverned, out)
				} else if said := strings.Contains(out, "a governed agent"); said != runscope.SaysGoverned(row.Answer) {
					t.Errorf("\"a governed agent\" said: %v, for an answer whose path shows a run: %v\n%s", said, runscope.SaysGoverned(row.Answer), out)
				}
			}
			moved := 0
			scopeExec = func(context.Context, scopePlan, io.Writer) (int, error) { moved++; return 0, nil }
			ctx := context.WithValue(t.Context(), scopeKey{}, scopeInvocation{argv: []string{"tego", "run", "missing"}})
			enterUserScope(ctx, io.Discard)
			rehearseUserScope(context.WithValue(t.Context(), scopeKey{}, scopeInvocation{argv: []string{"tego", "doctor"}}), io.Discard)
			if want := map[bool]int{true: 2, false: 0}[row.Permits]; moved != want {
				t.Errorf("the entry and its rehearsal started %d scopes; want %d", moved, want)
			}
			if as := guide.Invoker(selfAnswer()); as.InRun == row.Permits {
				t.Errorf("guide.Invoker says InRun %v", as.InRun)
			}
			if handed := scanInputs().Caller.Membership; handed.Outside() != row.Permits {
				t.Errorf("the scan was handed an answer whose Outside() is %v", handed.Outside())
			}
		})
	}
}

// TestNothingOfTheAnswerIsHandedOn: the request that crosses to the re-entered process carries the command and the
// environment and no answer, and the re-entered process asks the rule itself before it confirms placement, reads
// the go-ahead or dispatches a command.
func TestNothingOfTheAnswerIsHandedOn(t *testing.T) {
	ty := reflect.TypeFor[scopeRequest]()
	var fields []string
	for i := range ty.NumField() {
		fields = append(fields, ty.Field(i).Name+" "+ty.Field(i).Type.String())
	}
	if got, want := strings.Join(fields, ", "), "Argv []string, Env []string, Rehearse bool"; got != want {
		t.Errorf("scopeRequest is {%s}; want {%s}: no verdict, cause or proof may travel", got, want)
	}
	src, err := os.ReadFile("runscope.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	i := strings.Index(body, "func scopedMain(")
	if i < 0 {
		t.Fatal("runscope.go has no scopedMain")
	}
	body = body[i:]
	if j := strings.Index(body, "\nfunc "); j > 0 {
		body = body[:j]
	}
	ask := strings.Index(body, "selfAnswer().Outside()")
	for _, later := range []string{"scopePlacement()", "wr.Write([]byte{1})", "io.ReadFull(rd, goAhead[:])", "mainWith("} {
		if at := strings.Index(body, later); ask < 0 || at < ask {
			t.Errorf("scopedMain reaches %s before it asks the rule itself (selfAnswer at %d, %s at %d)", later, ask, later, at)
		}
	}
	if runscope.ManagerSocket(1000) != filepath.Join(config.LogindRuntimeRoot, "1000", "systemd", "private") {
		t.Errorf("the rule's manager socket %q is not under config.LogindRuntimeRoot %q", runscope.ManagerSocket(1000), config.LogindRuntimeRoot)
	}
}
