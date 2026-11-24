// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/pathcheck"
	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func TestRulesPageSourceReadUnavailableDisablesChanges(t *testing.T) {
	f := newRulesFix(t)
	unreadable := testutil.EIOFile(t) // not /proc/self/mem: the undumpable helper cannot open its own
	if st, err := os.Lstat(unreadable); err != nil || !st.Mode().IsRegular() {
		t.Fatalf("metadata control: stat=%v err=%v", st, err)
	}
	for _, run := range []string{rulesRunA, rulesRunB} {
		file := filepath.Join(f.root, run, "events.jsonl")
		text, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(strings.ReplaceAll(string(text), f.source, unreadable)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Select the recorded run, as the page's chooser does for a run whose source reads fail.
	code, body := f.get(t, "/rules?run="+rulesRunB)
	if code != http.StatusOK || !strings.Contains(body, "Can run git") || !strings.Contains(body, pathcheck.Unavailable) {
		t.Fatalf("source read failure lost the copy or reason: status=%d body=%s", code, body)
	}
	if strings.Contains(body, `href="/rules/change?c=`) || !strings.Contains(body, `disabled aria-describedby="rules-soon"`) {
		t.Fatal("read-unavailable source still offers source edits")
	}
	if selected := sourceAvailabilityOption(body, ""); !strings.Contains(selected, pathcheck.Unavailable) {
		t.Fatalf("chooser lost source availability: %s", selected)
	}
}

type unavailableNewProfile struct{ cause error }

func (p unavailableNewProfile) Resolve(string) (string, []byte, error) {
	return "", nil, &os.PathError{Op: "read", Path: "/profiles/base.yaml", Err: p.cause}
}

func TestNotRunProfileReadUnavailableDisablesStart(t *testing.T) {
	for _, cause := range []error{syscall.EIO, syscall.ENOTCONN, context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			f := newRulesFix(t)
			dir := filepath.Join(f.home, "fresh-agent")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			svc := &rules.Service{Ledger: f.root, Home: f.home, Check: func(string, string, []byte) error { return nil }}
			req := rules.NewReq{Dir: dir, Presets: []string{"no-secrets"}, Command: "sh"}
			plan, err := svc.PlanNew(context.Background(), req)
			if err != nil || !plan.OK {
				t.Fatalf("healthy preview: plan=%+v err=%v", plan, err)
			}
			created, err := svc.CreateNew(context.Background(), req, plan.Base)
			if err != nil {
				t.Fatal(err)
			}
			svc.Check = func(file, _ string, _ []byte) error {
				_, _, err := agent.LoadBytes(file, []byte("version: 0\nname: fresh-agent\ncommand: [sh]\nextends: base\n"), unavailableNewProfile{cause})
				return err
			}
			f.s.cfg.Setup = svc
			code, body := f.get(t, "/rules?c="+created.Ref)
			if code != http.StatusOK || !strings.Contains(body, pathcheck.Unavailable) || !strings.Contains(body, "fresh-agent") {
				t.Fatalf("profile failure lost not-run contract or reason: status=%d body=%s", code, body)
			}
			if strings.Contains(body, "Start it") || strings.Contains(body, `href="/rules/change?c=`) {
				t.Error("unavailable profile offered start or edit")
			}
		})
	}
}

type unavailablePendingSource struct{ *rules.Service }

func (s unavailablePendingSource) PendingOn(context.Context, string, []string) map[string]rules.PendingNow {
	return map[string]rules.PendingNow{"change": {ID: "change", Options: []rules.NowOption{{OK: true, Block: "exec:git"}}}}
}

func TestRulesUnavailableSourceDisablesPendingTrust(t *testing.T) {
	f := newRulesFix(t)
	f.s.cfg.Rules = unavailablePendingSource{&rules.Service{Ledger: f.root, Home: f.home}}
	run, err := ledgerview.LoadRun(f.root, rulesRunB)
	if err != nil {
		t.Fatal(err)
	}
	d := rulesData{Run: run, Running: true, CannotChange: pathcheck.Unavailable,
		Pending: &pendingView{Changes: []pendingChange{{ID: "change"}}}}
	f.s.fillPendingLive(context.Background(), &d)
	if d.Pending.Restart != "" {
		t.Error("unavailable source offered a next-run command")
	}
	now := d.Pending.Changes[0].Now
	if now == nil || now.CanApply || !strings.Contains(now.Note, pathcheck.Unavailable) {
		t.Fatalf("unavailable source offered a pending source change: %+v", now)
	}
}

type recordedRefusalSetup struct {
	*rules.Service
	ref rules.ContractRef
}

func (s recordedRefusalSetup) Contracts() ([]rules.ContractRef, error) {
	return []rules.ContractRef{s.ref}, nil
}

func TestRulesChooserKeepsRecordedRefusal(t *testing.T) {
	for _, service := range []string{"setup", "rules"} {
		t.Run(service, func(t *testing.T) {
			f := newRulesFix(t)
			const reason = "the source was refused by its recorded ownership guard"
			ref := rules.RefLexical(f.source)
			svc := recordedRefusalSetup{
				Service: &rules.Service{Ledger: f.root, Home: f.home},
				ref:     rules.ContractRef{Ref: ref, Path: f.source, Agent: "rules-demo", Runs: 2, Why: reason},
			}
			if service == "setup" {
				f.s.cfg.Setup = svc
			} else {
				f.s.cfg.Rules = svc
			}
			code, body := f.get(t, "/rules?c="+ref)
			if code != http.StatusOK {
				t.Fatalf("GET: %d %s", code, body)
			}
			if selected := sourceAvailabilityOption(body, ref); !strings.Contains(selected, reason) {
				t.Errorf("chooser discarded the recorded source's refusal: %s", selected)
			}
			if strings.Contains(body, `href="/rules/change?c=`) || !strings.Contains(body, reason) {
				t.Error("recorded refusal left source edits enabled or lost its explanation")
			}
		})
	}
}

func sourceAvailabilityOption(body, ref string) string {
	if ref == "" {
		for _, chunk := range strings.Split(body, "<option ") {
			tag, text, ok := strings.Cut(chunk, ">")
			if ok && strings.Contains(tag, " selected") {
				text, _, _ = strings.Cut(text, "</option>")
				return text
			}
		}
		return ""
	}
	start := strings.Index(body, `<option value="`+ref+`"`)
	if start < 0 {
		return ""
	}
	end := strings.Index(body[start:], "</option>")
	if end < 0 {
		return body[start:]
	}
	return body[start : start+end]
}

type mixedPageProfiles struct{}

func (mixedPageProfiles) Resolve(name string) (string, []byte, error) {
	if name == "missing" {
		return "", nil, os.ErrNotExist
	}
	return unavailableNewProfile{syscall.ENOTCONN}.Resolve(name)
}
func TestRulesPageChecksEveryProfileDiagnostic(t *testing.T) {
	for _, order := range []string{"missing, offline", "offline, missing"} {
		t.Run(order, func(t *testing.T) {
			f := newRulesFix(t)
			if err := os.WriteFile(f.source, []byte(rulesSource+"\nextends: ["+order+"]\n"), 0600); err != nil {
				t.Fatal(err)
			}
			f.s.cfg.Profiles = mixedPageProfiles{}
			code, body := f.get(t, "/rules?run="+rulesRunB)
			if code != http.StatusOK || !strings.Contains(body, "Can run git") || !strings.Contains(body, pathcheck.Unavailable) {
				t.Fatalf("status=%d body=%s", code, body)
			}
			if strings.Contains(body, `href="/rules/change?c=`) || !strings.Contains(body, `disabled aria-describedby="rules-soon"`) {
				t.Fatal("source changes enabled")
			}
		})
	}
}

type blockedSourceCatalogue struct {
	*rules.Service
	ctx  context.Context
	path string
}

func (s blockedSourceCatalogue) Contracts() ([]rules.ContractRef, error) {
	var reply struct{}
	err := pathcheck.Call(s.ctx, "test.source-read", s.path, &reply)
	why := ""
	if err != nil {
		why = err.Error()
	}
	return []rules.ContractRef{{Ref: rules.RefLexical(s.path), Path: s.path, Agent: "rules-demo", Runs: 2, Why: why}}, nil
}
func TestRulesPageCatalogueReadTimeoutKeepsRecordedRules(t *testing.T) {
	f := newRulesFix(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(exe + ".catalogue-read") })
	f.s.cfg.Setup = blockedSourceCatalogue{Service: &rules.Service{Ledger: f.root, Home: f.home}, ctx: ctx, path: f.source}
	// Supply the same session to the injected catalogue and the HTTP request.
	ctx, closeSession := contracts.WithHelperSession(ctx)
	defer closeSession()
	svc := f.s.cfg.Setup.(blockedSourceCatalogue)
	svc.ctx = ctx
	f.s.cfg.Setup = svc
	count := pageHelperCount(t)
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+"/rules?run="+rulesRunB, nil).WithContext(ctx)
	req.AddCookie(f.c)
	response := httptest.NewRecorder()
	f.s.ServeHTTP(response, req)
	body := response.Body.String()
	if _, err := os.Stat(exe + ".catalogue-read"); err != nil {
		t.Fatalf("read never blocked: %v", err)
	}
	if response.Code != http.StatusOK || !strings.Contains(body, "Can run git") || strings.Contains(body, rulesCanary) || !strings.Contains(body, pathcheck.Unavailable) {
		t.Fatalf("status=%d body=%s", response.Code, body)
	}
	if strings.Contains(body, `href="/rules/change?c=`) || !strings.Contains(body, `disabled aria-describedby="rules-soon"`) {
		t.Fatal("source edits enabled")
	}
	if got := count(); got != (helperStarts{Launcher: 1, Worker: 1}) {
		t.Fatalf("helper starts: %+v", got)
	}
}
