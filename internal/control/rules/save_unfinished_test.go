// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/control/draftcompile"
	"github.com/attention-span-ai/tego/internal/control/pathcheck"
	"github.com/attention-span-ai/tego/internal/registry"
)

// A Save re-checks the folder it was reviewed for. "The contract changed since you looked" (ErrStale, 409) is for a
// real difference only; a check that did not finish says why, and the review stays held for the retry.
func reviewedNew(t *testing.T, f *fixture, name string) (NewReq, string, string) {
	t.Helper()
	dir := f.newProject(t, name)
	req := NewReq{Dir: dir, Presets: []string{"no-secrets"}, Command: "sh"}
	p, err := f.s.PlanNew(context.Background(), req)
	if err != nil || !p.OK {
		t.Fatalf("review: %+v, %v", p, err)
	}
	return req, p.Base, dir
}

func noContractWritten(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(dir, NewFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused Save wrote %s: %v", NewFile, err)
	}
}

func TestSaveSaysWhyTheFolderCheckDidNotFinish(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		words string // what the error says of itself
		page  string // the cause the dashboard's 503 page names
	}{
		{"busy compile step", contracts.CompileUnavailable(true, errors.New("compiler busy, try again")), contracts.CompileBusy, "the compiler is busy with other checks"},
		{"compile not finished", contracts.CompileNotFinished(context.DeadlineExceeded), contracts.CompileUnfinished, "the machine is very busy: the contract check did not finish in time"},
		{"compile could not run", contracts.CompileUnavailable(false, errors.New("no process")), contracts.CompileCouldNotRun, "Tego's compiler could not run"},
		{"location does not answer", contracts.CheckUnavailable(context.DeadlineExceeded), pathcheck.Unavailable, "the location does not answer (a disconnected or stuck mount?)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			req, base, dir := reviewedNew(t, f, "later")
			f.s.directory = func(context.Context, draftcompile.DirectoryRequest) (string, error) { return "", tc.err }
			_, err := f.s.CreateNew(context.Background(), req, base)
			if err == nil || errors.Is(err, ErrStale) || errors.Is(err, ErrRefused) || !pathcheck.IsNotFinished(err) || !strings.Contains(err.Error(), tc.words) {
				t.Fatalf("a folder check that did not finish = %v, want its own reason and not ErrStale or ErrRefused", err)
			}
			if got := pathcheck.Words(err); got != tc.page {
				t.Errorf("the page's cause = %q, want %q", got, tc.page)
			}
			noContractWritten(t, dir)
			// Nothing was consumed: the same review saves once the check answers.
			f.s.directory = nil
			if _, err := f.s.CreateNew(context.Background(), req, base); err != nil {
				t.Fatalf("the retry of the same review: %v", err)
			}
		})
	}
}

// The reason survives the helper pipe, as the dashboard's service runs in one: the kinds name the cause, the message
// carries the words.
func TestSaveFolderCheckReasonCrossesTheHelperPipe(t *testing.T) {
	f := newFixture(t)
	for _, cause := range []error{contracts.CompileUnavailable(true, errors.New("compiler busy, try again")), contracts.CompileNotFinished(context.DeadlineExceeded)} {
		reply, err := f.s.pack(nil, cause)
		if err != nil {
			t.Fatal(err)
		}
		var got serviceReply
		if err := pathcheck.Decode(reply, &got); err != nil {
			t.Fatal(err)
		}
		var causes []error
		for _, kind := range got.Kinds {
			causes = append(causes, serviceErrors[kind])
		}
		remote := &pathcheck.RemoteError{Message: got.Error, Causes: causes}
		if !pathcheck.IsNotFinished(remote) || errors.Is(remote, ErrStale) || pathcheck.Words(remote) != pathcheck.Words(cause) {
			t.Errorf("%v across the pipe: not finished %v, stale %v, words %q want %q", cause, pathcheck.IsNotFinished(remote), errors.Is(remote, ErrStale), pathcheck.Words(remote), pathcheck.Words(cause))
		}
	}
}

func TestSaveSaysWhyTheCompileDidNotFinish(t *testing.T) {
	f := newFixture(t)
	req, base, dir := reviewedNew(t, f, "compiling")
	busy := contracts.CompileUnavailable(true, errors.New("compiler busy, try again"))
	f.s.Compile = func(context.Context, CheckContext, []byte) error { return busy }
	_, err := f.s.CreateNew(context.Background(), req, base)
	if err == nil || errors.Is(err, ErrStale) || errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), contracts.CompileBusy) {
		t.Fatalf("a busy compile at Save = %v, want its own reason and neither ErrStale nor ErrRefused", err)
	}
	noContractWritten(t, dir)
	f.s.Compile = func(context.Context, CheckContext, []byte) error { return errors.New("does-not-compile") }
	if _, err = f.s.CreateNew(context.Background(), req, base); !errors.Is(err, ErrRefused) {
		t.Fatalf("a contract that does not compile at Save = %v, want ErrRefused", err)
	}
}

func TestSaveStaleIsARealDifference(t *testing.T) {
	cases := []struct {
		name  string
		after func(t *testing.T, f *fixture, req *NewReq, dir string)
	}{
		{"another folder", func(t *testing.T, f *fixture, req *NewReq, dir string) { req.Dir = f.newProject(t, "elsewhere") }},
		{"another name", func(t *testing.T, f *fixture, req *NewReq, dir string) { req.Name = "another-name" }},
		{"another registry entry", func(t *testing.T, f *fixture, req *NewReq, dir string) { req.Registry = true }},
		{"another draft", func(t *testing.T, f *fixture, req *NewReq, dir string) { req.Draft = "not-the-reviewed-draft" }},
		{"other content", func(t *testing.T, f *fixture, req *NewReq, dir string) { req.Command = "bash" }},
		{"the folder was replaced", func(t *testing.T, f *fixture, req *NewReq, dir string) {
			if err := os.Rename(dir, dir+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"the folder is refused now", func(t *testing.T, f *fixture, req *NewReq, dir string) {
			f.s.directory = func(context.Context, draftcompile.DirectoryRequest) (string, error) {
				return "", errors.New(dir + " is not a folder.")
			}
		}},
		{"the folder is gone when opened", func(t *testing.T, f *fixture, req *NewReq, dir string) {
			was := openDirectory
			t.Cleanup(func() { openDirectory = was })
			openDirectory = failingOpen(fmt.Errorf("open-directory: %w", unix.ENOENT))
		}},
		{"a link stands where the folder was", func(t *testing.T, f *fixture, req *NewReq, dir string) {
			was := openDirectory
			t.Cleanup(func() { openDirectory = was })
			openDirectory = failingOpen(fmt.Errorf("open-directory: %w", unix.ELOOP))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			req, base, dir := reviewedNew(t, f, "stale")
			tc.after(t, f, &req, dir)
			_, err := f.s.CreateNew(context.Background(), req, base)
			if !errors.Is(err, ErrStale) || pathcheck.IsNotFinished(err) {
				t.Fatalf("a real difference = %v, want ErrStale", err)
			}
			noContractWritten(t, dir)
		})
	}
}

func failingOpen(err error) func(context.Context, string, bool) (*registry.Directory, error) {
	return func(context.Context, string, bool) (*registry.Directory, error) { return nil, err }
}

func TestSaveSaysWhyTheFolderCouldNotBeOpened(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		finished bool // false: a check that did not finish
		words    string
	}{
		{"input/output error", fmt.Errorf("open-directory: %w", unix.EIO), false, pathcheck.Unavailable},
		{"deadline", context.DeadlineExceeded, false, pathcheck.Unavailable},
		{"cancelled", context.Canceled, false, ""},
		{"not permitted", fmt.Errorf("open-directory: %w", unix.EACCES), true, "permission denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			req, base, dir := reviewedNew(t, f, "opening")
			was := openDirectory
			t.Cleanup(func() { openDirectory = was })
			openDirectory = failingOpen(tc.err)
			_, err := f.s.CreateNew(context.Background(), req, base)
			switch {
			case err == nil, errors.Is(err, ErrStale):
				t.Fatalf("a folder that could not be opened = %v, want its own reason and not ErrStale", err)
			case tc.finished && !errors.Is(err, ErrRefused), !tc.finished && !pathcheck.IsNotFinished(err), !strings.Contains(err.Error(), tc.words):
				t.Fatalf("a folder that could not be opened = %v (not finished %v), want %q", err, pathcheck.IsNotFinished(err), tc.words)
			}
			noContractWritten(t, dir)
			openDirectory = was
			if _, err := f.s.CreateNew(context.Background(), req, base); err != nil {
				t.Fatalf("the retry of the same review: %v", err)
			}
		})
	}
}

// A Save of a change to an existing contract compiles the held bytes again: a busy or unfinished compile there is the
// same unfinished check, not a refusal of the contract (ErrRefused, "Nothing was written: ..."), and the review stays.
func TestSaveOfAChangeSaysWhyTheCompileDidNotFinish(t *testing.T) {
	f := newFixture(t)
	c := f.ref(t, f.contract)
	req := RawReq{Session: "person", Ref: c.Ref, Base: c.Base, Text: []byte(f.text(t) + "\n# reviewed\n")}
	plan, err := f.s.PlanRaw(t.Context(), req)
	if err != nil || plan.Err != "" {
		t.Fatalf("review: %+v %v", plan, err)
	}
	req.Ack = plan.Ack
	was := f.s.Compile
	f.s.Compile = func(context.Context, CheckContext, []byte) error {
		return contracts.CompileUnavailable(true, errors.New("compiler busy, try again"))
	}
	_, err = f.s.ApplyRaw(t.Context(), req)
	if err == nil || errors.Is(err, ErrRefused) || errors.Is(err, ErrStale) || !pathcheck.IsNotFinished(err) || !strings.Contains(err.Error(), contracts.CompileBusy) {
		t.Fatalf("a busy compile at Save of a change = %v, want its own reason, neither ErrRefused nor ErrStale", err)
	}
	f.s.Compile = func(context.Context, CheckContext, []byte) error { return errors.New("does-not-compile") }
	if _, err = f.s.ApplyRaw(t.Context(), req); !errors.Is(err, ErrRefused) {
		t.Fatalf("a contract that does not compile at Save of a change = %v, want ErrRefused", err)
	}
	f.s.Compile = was
	if _, err = f.s.ApplyRaw(t.Context(), req); err != nil {
		t.Fatalf("the retry of the same review: %v", err)
	}
}
