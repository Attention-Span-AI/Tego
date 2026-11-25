// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"crypto/sha256"
	"errors"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/testutil"
	htmlnode "golang.org/x/net/html"
)

func TestBuilderGovernedPreviewDoesNotPrepareDirectories(t *testing.T) {
	f := newRulesFix(t)
	reg := f.withRegistry(t)
	f.s.governed = func(*http.Request) error { return errors.New("governed run") }
	q := url.Values{"mode": {"blank"}, "dir": {f.proj}, "name": {"readonly"}, "to": {"registry"}, "preview": {"1"}}
	code, _ := f.get(t, "/rules/new?"+q.Encode())
	if code != http.StatusOK {
		t.Fatalf("preview: %d", code)
	}
	if _, err := os.Lstat(reg); !os.IsNotExist(err) {
		t.Fatalf("governed preview prepared registry: %v", err)
	}
}

type builderDiskEntry struct {
	Mode          fs.FileMode
	Size          int64
	Modified      time.Time
	Changed       time.Time
	Device, Inode uint64
	UID, GID      uint32
	Link          string
	Digest        [32]byte
}

func builderDiskSnapshot(t *testing.T, roots ...string) map[string]builderDiskEntry {
	t.Helper()
	out := map[string]builderDiskEntry{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			st, err := d.Info()
			if err != nil {
				return err
			}
			sys := st.Sys().(*syscall.Stat_t)
			// Access time can change from reading, including this snapshot. Bind
			// modification and status-change times, permissions, ownership and bytes.
			entry := builderDiskEntry{Mode: st.Mode(), Size: st.Size(), Modified: st.ModTime(), Changed: time.Unix(sys.Ctim.Sec, sys.Ctim.Nsec), Device: uint64(sys.Dev), Inode: sys.Ino, UID: sys.Uid, GID: sys.Gid}
			switch {
			case st.Mode().IsRegular():
				b, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				entry.Digest = sha256.Sum256(b)
			case st.Mode()&os.ModeSymlink != 0:
				entry.Link, err = os.Readlink(path)
				if err != nil {
					return err
				}
			}
			out[path] = entry
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// Registration and coverage share one table: a new builder read route is tested
// automatically, for GET and HEAD, canonical address and alias, with all sources.
// Both interfaces use one real service and compiler; preview requests must produce
// a valid reviewed plan before disk snapshots are compared. Aliases are followed.
// This covers the fixture home, project and ledger on the host filesystem. It does
// not cover concurrent governed peers, crash durability, other roots or browsers.
// The registry exists before the request; missing-directory preparation is tested
// separately by TestBuilderPreparationRequiresGuardedPost.
func TestBuilderEveryReadRouteLeavesDiskUnchanged(t *testing.T) {
	// Every case plans a draft through a compile helper, and a race build starts that helper race-instrumented (about a
	// second, and about 5 s a case here: 393 s for the test on a quiet box), so a race run takes every fourth case, from the
	// -shuffle seed's offset, and every other run takes all of them.
	subset, n := 0, 0
	if raceEnabled {
		subset = testutil.ShuffleOffset(t, 4)
	}
	for _, route := range builderGetRoutes {
		for _, alias := range []bool{false, true} {
			path := route.path
			if alias {
				path = "/contracts" + strings.TrimPrefix(path, "/rules")
			}
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				for _, mode := range []string{"blank", "presets", "run"} {
					if n++; raceEnabled && (n-1)%4 != subset {
						continue
					}
					t.Run(method+path+"/"+mode, func(t *testing.T) {
						f := newChangeFix(t)
						reg := filepath.Join(f.home, ".config", "tego")
						f.svc.Machine.Registry.Value = reg
						if err := os.MkdirAll(filepath.Join(reg, "agents"), 0700); err != nil {
							t.Fatal(err)
						}
						rs := &builderReadPlans{Service: f.svc}
						f.s.cfg.Rules, f.s.cfg.Setup = rs, rs
						if any(f.s.cfg.Rules) != any(f.s.cfg.Setup) || rs.Compile != nil || rs.Check != nil {
							t.Fatal("read routes must share one production compiler service")
						}
						dir := filepath.Join(f.proj, "new-project")
						if err := os.Mkdir(dir, 0700); err != nil {
							t.Fatal(err)
						}
						q := url.Values{"mode": {mode}, "dir": {dir}, "name": {"readonly"}, "to": {"registry"}, "preview": {"1"}, "cmd": {"/bin/sh"}, "preset": {"no-secrets"}, "from": {rulesRunA}, "c": {rules.Ref(f.source)}, "op": {"add"}, "key": {"exec.allow"}, "v": {"/bin/echo"}}
						current, err := rs.Current(rules.Ref(f.source))
						if err != nil {
							t.Fatal(err)
						}
						q.Set("base", current.Base)
						before := builderDiskSnapshot(t, f.home, f.proj, f.root)
						w := do(f.s, method, path+"?"+q.Encode(), "127.0.0.1:8484", f.c)
						if alias {
							want := route.path + "?" + q.Encode()
							if w.Code != http.StatusSeeOther || w.Header().Get("Location") != want {
								t.Fatalf("alias: %d %q", w.Code, w.Header().Get("Location"))
							}
							w = do(f.s, method, want, "127.0.0.1:8484", f.c)
						}
						if w.Code != http.StatusOK {
							t.Fatalf("route refused: %d", w.Code)
						}
						switch route.path {
						case "/rules/new":
							p := rs.newPlan
							if p == nil || !p.OK || p.Base == "" || len(p.Text) == 0 {
								t.Fatalf("preview did not reach a valid reviewed new plan: %+v", p)
							}
						case "/rules/change/preview":
							p := rs.changePlan
							if p == nil || p.Err != "" || p.Nothing || p.Stale || p.Ack == "" || p.Compiled == "" {
								t.Fatalf("preview did not reach a valid compiled reviewed change plan: %+v", p)
							}
						}
						after := builderDiskSnapshot(t, f.home, f.proj, f.root)
						if !reflect.DeepEqual(before, after) {
							t.Fatalf("read route changed disk (before %d entries, after %d)", len(before), len(after))
						}
					})
				}
			}
		}
	}
}

// Observe the actual handler path without replacing production compilation.
type builderReadPlans struct {
	*rules.Service
	newPlan    *rules.NewPlan
	changePlan *rules.ChangePlan
}

func (s *builderReadPlans) PlanNew(ctx context.Context, req rules.NewReq) (*rules.NewPlan, error) {
	p, err := s.Service.PlanNew(ctx, req)
	s.newPlan = p
	return p, err
}

func (s *builderReadPlans) PlanChange(ctx context.Context, req rules.ChangeReq) (*rules.ChangePlan, error) {
	p, err := s.Service.PlanChange(ctx, req)
	s.changePlan = p
	return p, err
}

func TestBuilderPreparationRequiresGuardedPost(t *testing.T) {
	for _, refusal := range []string{"governed", "origin", "csrf", "allowed"} {
		t.Run(refusal, func(t *testing.T) {
			f := newRulesFix(t)
			reg := f.withRegistry(t)
			form := url.Values{"mode": {"blank"}, "dir": {f.proj}, "name": {"prepared"}, "to": {"registry"}, "cmd": {"/bin/sh"}, "builder": {"1"}, "step": {"source"}, "csrf": {f.s.csrf}}
			if refusal == "governed" {
				f.s.governed = func(*http.Request) error { return errors.New("governed run") }
			}
			origin := own
			if refusal == "origin" {
				origin = "https://foreign.example"
			}
			if refusal == "csrf" {
				form.Set("csrf", "foreign")
			}
			if refusal == "allowed" {
				code, body := f.get(t, "/rules/new?"+form.Encode())
				if code != http.StatusOK || newBase.MatchString(body) {
					t.Fatal("unprepared read preview offered Save")
				}
				form = builderRenderedSourceForm(t, body)
			}
			w := post(f.s, "/rules/new", form, origin, "", f.c)
			if refusal != "allowed" {
				if w.Code != http.StatusForbidden {
					t.Fatalf("preparation: %d", w.Code)
				}
				if _, err := os.Lstat(reg); !os.IsNotExist(err) {
					t.Fatalf("refused preparation changed disk: %v", err)
				}
				return
			}
			if w.Code != http.StatusOK {
				t.Fatalf("preview: %d %s", w.Code, w.Body.String())
			}
			if st, err := os.Stat(filepath.Join(reg, "agents")); err != nil || !st.IsDir() {
				t.Fatalf("guarded Preview did not prepare registry: %v", err)
			}
			save := builderRenderedSaveForm(t, w.Body.String())
			w = post(f.s, "/rules/new", save, own, "", f.c)
			if w.Code != http.StatusSeeOther {
				t.Fatalf("prepared Save: %d %s", w.Code, w.Body.String())
			}
			if _, err := os.Stat(filepath.Join(reg, "agents", "prepared.yaml")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Read the actual native source form, including the selected run, checked source
// options and the POST/CSRF fields. Do not reconstruct an intended request.
func builderRenderedSourceForm(t *testing.T, body string) url.Values {
	t.Helper()
	var form *htmlnode.Node
	walk(parseHTML(t, "source form", body), func(n *htmlnode.Node) {
		if id, _ := attr(n, "id"); n.Data == "form" && id == "builder-source" {
			form = n
		}
	})
	if form == nil {
		t.Fatal("no source form")
	}
	if method, _ := attr(form, "method"); method != "post" {
		t.Fatalf("source preparation uses %q", method)
	}
	out := url.Values{}
	walk(form, func(n *htmlnode.Node) {
		name, _ := attr(n, "name")
		if name == "" {
			return
		}
		switch n.Data {
		case "input":
			kind, _ := attr(n, "type")
			if kind == "radio" || kind == "checkbox" {
				if _, checked := attr(n, "checked"); !checked {
					return
				}
			}
			value, _ := attr(n, "value")
			out.Add(name, value)
		case "textarea":
			if n.FirstChild != nil {
				out.Add(name, n.FirstChild.Data)
			} else {
				out.Add(name, "")
			}
		case "select":
			var selected *htmlnode.Node
			walk(n, func(option *htmlnode.Node) {
				if option.Data != "option" {
					return
				}
				_, checked := attr(option, "selected")
				if selected == nil || checked {
					selected = option
				}
			})
			if selected != nil {
				value, _ := attr(selected, "value")
				out.Add(name, value)
			}
		}
	})
	if out.Get("csrf") == "" || out.Get("step") != "source" {
		t.Fatal("source preparation lost its guarded form fields")
	}
	return out
}

// The review must compile after preparation: adding registry directories changes
// the compiler's protected-path metadata, even when the YAML grants no writes.
func TestBuilderPreparedPreviewUsesFinalDirectoryState(t *testing.T) {
	f := newChangeFix(t)
	f.s.cfg.Setup = f.svc
	f.svc.Machine.Registry.Value = filepath.Join(f.home, ".config", "tego")
	q := url.Values{"mode": {"blank"}, "dir": {f.proj}, "name": {"prepared-once"}, "to": {"registry"}, "cmd": {"/bin/sh"}, "preview": {"1"}}
	_, body := f.get(t, "/rules/new?"+q.Encode())
	w := post(f.s, "/rules/new", builderRenderedSourceForm(t, body), own, "", f.c)
	if w.Code != http.StatusOK {
		t.Fatalf("source Preview: %d", w.Code)
	}
	w = post(f.s, "/rules/new", builderRenderedSaveForm(t, w.Body.String()), own, "", f.c)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("unchanged prepared preview Save: %d", w.Code)
	}
	if _, err := os.Stat(filepath.Join(f.svc.Machine.Registry.Value, "agents", "prepared-once.yaml")); err != nil {
		t.Fatal(err)
	}
}
