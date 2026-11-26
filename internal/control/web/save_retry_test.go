// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// maxSaveTries is how many times postSave sends a Save the dashboard answered "The contract check could not finish".
const maxSaveTries = 8

// postSave posts a Save as a person's page does when the dashboard says the contract check could not finish (a busy
// compile step, a location that did not answer): the review is still held, so the same form is sent again. Any other
// answer is returned as it came, and the review's own refusals (409, 422) are never retried.
func postSave(t *testing.T, s *Server, target string, form url.Values, origin, referer string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	w := post(s, target, form, origin, referer, cookie)
	for try := 1; w.Code == http.StatusServiceUnavailable && try < maxSaveTries; try++ {
		t.Logf("Save answered 503 (try %d), sending the same review again", try)
		w = post(s, target, form, origin, referer, cookie)
	}
	return w
}
