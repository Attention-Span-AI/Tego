// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/control/pathcheck"
	"github.com/attention-span-ai/tego/internal/control/rules"
)

// The service boundary can refuse before dispatch (capacity) or lose a reply
// after a write was submitted (deadline). Neither outcome is an internal error,
// and the HTTP edge cannot promise that a timed-out write did not reach disk.
type unavailableSaveService struct {
	*rules.Service
	err   error
	phase string
}

func (s *unavailableSaveService) Contracts() ([]rules.ContractRef, error) {
	if s.phase == "raw-catalogue" {
		return nil, s.err
	}
	return s.Service.Contracts()
}
func (s *unavailableSaveService) Current(ref string) (*rules.Current, error) {
	if s.phase == "raw-current" {
		return nil, s.err
	}
	return s.Service.Current(ref)
}

func (s *unavailableSaveService) ApplyChange(context.Context, rules.ChangeReq) (*rules.Applied, error) {
	return nil, s.err
}
func (s *unavailableSaveService) ApplyRaw(context.Context, rules.RawReq) (*rules.Applied, error) {
	return nil, s.err
}
func (s *unavailableSaveService) CreateNew(context.Context, rules.NewReq, string) (*rules.Created, error) {
	return nil, s.err
}

func TestSaveUnavailableExplainsRecovery(t *testing.T) {
	for _, cause := range []struct {
		name  string
		err   error
		words string // the cause the 503 page names
	}{
		{"capacity", contracts.CheckUnavailable(errors.New("32 filesystem helpers are still alive in this uid and network namespace")), "the location does not answer"},
		{"deadline", contracts.CheckUnavailable(context.DeadlineExceeded), "the location does not answer"},
		{"remote-deadline", &pathcheck.RemoteError{Message: pathcheck.Unavailable + ": location-check context deadline"}, "the location does not answer"},
		// The checker did not start in time: the same 503, whatever the words.
		{"remote-busy", &pathcheck.RemoteError{Message: pathcheck.Busy + ": context deadline exceeded"}, "the machine is very busy: the checker did not start in time"},
		// The helper sat in this computer's own disk or journal: the 503 page names the disk, not a mount.
		{"remote-disk", &pathcheck.RemoteError{Message: pathcheck.Disk + ": context deadline exceeded"}, "the disk of this computer did not finish writing in time (it is very busy or nearly full)"},
		{"stuck", contracts.CheckUnavailable(fmt.Errorf("3 earlier checks hold every slot: %w", contracts.ErrHelpersStuck)), "earlier checks are stuck on a location"},
		{"cancelled", contracts.CompileNotFinished(context.Canceled), "the request was cancelled before the check finished"},
	} {
		for _, mode := range []string{"structured", "raw", "raw-catalogue", "raw-current", "new"} {
			t.Run(cause.name+"/"+mode, func(t *testing.T) {
				f := newChangeFix(t)
				// This test injects the service's availability result. Keep review
				// setup independent of reexec/race-runtime exit delays; the real
				// review store, source guards, publisher and journal still run.
				f.svc.Compile = func(context.Context, rules.CheckContext, []byte) error { return nil }
				c := f.ref(t, f.source)
				code, preview := f.get(t, "/rules/change/preview?"+url.Values{"c": {c.Ref}, "base": {c.Base}, "op": {"remove"}, "key": {"exec.allow"}, "v": {"git"}}.Encode())
				if code != http.StatusOK || !strings.Contains(preview, `name="ack"`) {
					t.Fatalf("review setup: %d %s", code, preview)
				}
				form := builderLostStructuredForm(t, preview)
				form.Del("now")
				target := "/rules/change"
				if strings.HasPrefix(mode, "raw") {
					form.Set("mode", "raw")
					form.Set("step", "save")
					form.Set("text", rulesSource+"\n# reviewed edit\n")
				}
				if mode == "new" {
					target = "/rules/new"
					form = url.Values{"csrf": {f.s.csrf}, "builder": {"1"}, "step": {"save"}, "mode": {"blank"}, "name": {"unavailable"}, "dir": {f.proj}, "cmd": {"/bin/echo"}}
				}
				boundary := &unavailableSaveService{Service: f.svc, err: cause.err, phase: mode}
				f.s.cfg.Rules, f.s.cfg.Setup = boundary, boundary
				before := readText(t, c.Path)
				w := post(f.s, target, form, own, "", f.c)
				body := w.Body.String()
				if w.Code != http.StatusServiceUnavailable {
					t.Fatalf("Save returned %d, want 503: %s", w.Code, body)
				}
				for _, want := range []string{"The contract check could not finish", "The check did not finish: " + cause.words, "Reload the contract and its History", "a submitted save may already have reached the file"} {
					if !strings.Contains(body, want) {
						t.Errorf("recovery page lacks %q: %s", want, body)
					}
				}
				if strings.Contains(body, "Nothing was saved") || strings.Contains(body, "Not saved") {
					t.Error("uncertain write was reported as definitely unwritten")
				}
				if readText(t, c.Path) != before || journalLen(t, f.root) != 0 {
					t.Fatal("the refused service call changed source or history")
				}
				if mode == "structured" {
					f.s.cfg.Rules = f.svc
					w = post(f.s, target, form, own, "", f.c)
					if w.Code != http.StatusSeeOther || journalLen(t, f.root) != 1 || readText(t, c.Path) == before {
						t.Fatalf("recovery consumed the review before a successful retry: %d location=%s journal=%d body=%s", w.Code, w.Header().Get("Location"), journalLen(t, f.root), w.Body.String())
					}
				}
			})
		}
	}
}
