// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDashboardRejectsUnrelatedListener(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0700); err != nil {
		t.Fatal(err)
	}
	var received string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.URL.RawQuery
		_, _ = w.Write([]byte("ordinary local server"))
	}))
	defer s.Close()
	if err := os.Mkdir(filepath.Join(home, ".tego"), 0700); err != nil {
		t.Fatal(err)
	}
	link := s.URL + "/?t=0123abcd"
	if err := os.WriteFile(dashboardLog(home), []byte(link), 0600); err != nil {
		t.Fatal(err)
	}
	if got, current := dashboardAt(home); got != "" || current {
		t.Fatalf("unrelated listener trusted: %q %v", got, current)
	}
	if received == "t=0123abcd" {
		t.Fatal("probe sent the sign-in secret")
	}
}

func dashboardStandIn(t *testing.T) *httptest.Server {
	t.Helper()
	_, _, scope, err := dashboardConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mac := hmac.New(sha256.New, []byte("0123abcd"))
		_, _ = mac.Write([]byte("tego-dashboard-v1\n" + r.URL.Query().Get("challenge") + "\n" + scope))
		_, _ = io.WriteString(w, hex.EncodeToString(mac.Sum(nil)))
	}))
	t.Cleanup(s.Close)
	return s
}
