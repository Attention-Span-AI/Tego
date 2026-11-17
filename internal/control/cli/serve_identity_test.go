// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
