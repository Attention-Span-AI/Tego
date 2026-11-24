// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/contractsrc"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

const generalSourceText = "version: 0\nname: shared\ncommand: [true]\nenv: {set: {TOKEN: secret-canary-general}}\n"

func generalServer(t *testing.T) (*Server, *http.Cookie, string) {
	t.Helper()
	s := newServer(t, fixture(t))
	home := filepath.Join(t.TempDir(), "home-<script>alert(1)")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".tego")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "general.yaml")
	if err := os.WriteFile(path, []byte(generalSourceText), 0600); err != nil {
		t.Fatal(err)
	}
	s.cfg.Machine = config.Builtin()
	s.cfg.Machine.Home = home
	// Model system absence and placement only. The user source is opened and read
	// on each request; parsing and canonicalisation use the production reader.
	// Real placement checks are tested in config, not against installed /etc or HOME.
	s.readGeneral = func(ctx context.Context, m *config.Machine, uid int) contractsrc.General {
		return contractsrc.ReadGeneralWithSource(ctx, m, uid, func(p string, system bool, _ int, max int64) (config.PolicySource, bool, error) {
			if system {
				if p != contractsrc.SystemPath {
					t.Fatalf("unexpected system source %s", p)
				}
				return config.PolicySource{}, true, nil
			}
			if p != path {
				t.Fatalf("unexpected user source %s", p)
			}
			f, err := os.Open(p)
			if err != nil {
				return config.PolicySource{}, false, err
			}
			defer func() { _ = f.Close() }()
			st, err := f.Stat()
			if err != nil {
				return config.PolicySource{}, false, err
			}
			if err := config.CheckTrusted(f, p, os.Getuid()); err != nil {
				return config.PolicySource{}, false, err
			}
			if st.Mode().Perm()&0077 != 0 {
				return config.PolicySource{}, false, fmt.Errorf("fixture source is not private")
			}
			data, err := io.ReadAll(io.LimitReader(f, max+1))
			if err != nil {
				return config.PolicySource{}, false, err
			}
			if int64(len(data)) > max {
				return config.PolicySource{}, false, fmt.Errorf("fixture source exceeds bound")
			}
			return config.PolicySource{Data: data, Resolved: p, Owner: os.Getuid(), Mode: st.Mode().Perm(), Walk: []string{dir, p}}, false, nil
		})
	}
	return s, login(t, s), path
}

func TestGeneralContractsSourceAndLockedBaseline(t *testing.T) {
	s, c, path := generalServer(t)
	// The independently specified canonical bytes include the secret canary.
	// Matching this digest proves that the real parser saw it before projection.
	const canonical = "version: 0\nname: shared\ncommand:\n  - \"true\"\nenv:\n  set:\n    TOKEN: secret-canary-general\n"
	const canonicalHash = "2a34b742833a2e507d26f0c8a998508fc94edfbf088922f5e12c294a7ef01edb"
	const sourceHash = "b2d4b3ad9bba7c8db877511c26d094d011c9b45bb741489b7ea4cef3db6f6235"
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(canonical))); got != canonicalHash {
		t.Fatalf("independent canonical fixture digest = %s, want %s", got, canonicalHash)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(generalSourceText))); got != sourceHash {
		t.Fatalf("independent source fixture digest = %s, want %s", got, sourceHash)
	}
	read := s.readGeneral
	var parsed contractsrc.General
	s.readGeneral = func(ctx context.Context, m *config.Machine, uid int) contractsrc.General {
		parsed = read(ctx, m, uid)
		return parsed
	}
	w := do(s, "GET", "/rules", "127.0.0.1:8484", c)
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, body)
	}
	if parsed.State != "loaded" || parsed.Hash != canonicalHash || len(parsed.Sources) != 2 || parsed.Sources[1].SHA256 != sourceHash {
		t.Fatalf("handler did not parse fixture source: %+v", parsed)
	}
	for _, word := range []string{"Source loaded; general launch not built yet", "Canonical general hash:", canonicalHash, "Source SHA-256:", sourceHash, "Machine baseline · Locked", "Existing own contracts keep their rules", "Your agents on this machine", "home-&lt;script&gt;alert(1)"} {
		if !strings.Contains(body, word) {
			t.Errorf("missing %q", word)
		}
	}
	if strings.Index(body, "id=\"h-general\"") > strings.Index(body, "id=\"h-general-baseline\"") {
		t.Fatal("baseline precedes general")
	}
	if strings.Contains(body, "<script>alert(1)") || strings.Contains(body, "secret-canary-general") {
		t.Fatal("source escaped incorrectly or env value leaked")
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	w = do(s, "GET", "/rules", "127.0.0.1:8484", c)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "General contract UNKNOWN") {
		t.Fatalf("unknown source hid page: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "Source loaded;") {
		t.Fatal("unsafe source shown loaded")
	}
}

func TestGeneralCardDoesNotChangeRunDetails(t *testing.T) {
	s, c, _ := generalServer(t)
	w := do(s, "GET", "/rules?run="+harmRun, "127.0.0.1:8484", c)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "id=\"h-general\"") {
		t.Fatalf("run detail changed: %d", w.Code)
	}
}
