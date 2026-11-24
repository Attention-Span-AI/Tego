// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"github.com/attention-span-ai/tego/internal/setup"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDashboardIdentityChallenge(t *testing.T) {
	const token = "private-sign-in-token"
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := dashboardIdentity(next, "http://127.0.0.1:8484/?t="+token, "test-scope")
	nonce := strings.Repeat("a", 64)
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8484/_tego/identity?challenge="+nonce, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write([]byte("tego-dashboard-v1\n" + nonce + "\ntest-scope"))
	if w.Code != http.StatusOK || w.Body.String() != hex.EncodeToString(mac.Sum(nil)) || strings.Contains(w.Body.String(), token) {
		t.Fatalf("invalid proof: %d %s", w.Code, w.Body)
	}
	for _, path := range []string{"/_tego/identity?challenge=bad", "/ordinary"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8484"+path, nil))
		if w.Code == http.StatusOK {
			t.Fatalf("unexpected success for %s", path)
		}
	}
}

// startupWriter changes the on-disk config only after the server has been built.
type startupWriter func([]byte) (int, error)

func (w startupWriter) Write(p []byte) (int, error) { return w(p) }

func TestServeIdentityUsesLoadedSnapshot(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "machine.yaml")
	root := filepath.Join(dir, "ledger")
	before := []byte("version: 0\nledger_root: " + root + "\nlimits: {tokens: 100}\n")
	if err := os.WriteFile(file, before, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.EnvConfigVar, file)
	mr := loadMachineReport(config.TrustWarn)
	if mr.err != nil {
		t.Fatal(mr.err)
	}
	_, scope, err := setup.DashboardScope(mr.m, root)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	emitted := make(chan string, 1)
	writer := startupWriter(func(p []byte) (int, error) {
		if err := os.WriteFile(file, []byte("version: 0\nledger_root: "+root+"\nlimits: {tokens: 20}\n"), 0600); err != nil {
			return 0, err
		}
		emitted <- strings.TrimSpace(strings.TrimPrefix(string(p), "Tego dashboard: "))
		return len(p), nil
	})
	var se syncBuffer
	done := make(chan int, 1)
	go func() { done <- cmdServe().Run(ctx, []string{"--addr", "127.0.0.1:0"}, writer, &se) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("serve did not stop")
		}
	}()
	var link string
	select {
	case link = <-emitted:
	case code := <-done:
		done <- code
		t.Fatalf("serve %d: %s", code, se.String())
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not start")
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	token := u.Query().Get("t")
	nonce := strings.Repeat("b", 64)
	u.Path, u.RawQuery = "/_tego/identity", "challenge="+nonce
	client := http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	proof, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write([]byte("tego-dashboard-v1\n" + nonce + "\n" + scope))
	if string(proof) != hex.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("proof describes a different snapshot: %q", proof)
	}
}
