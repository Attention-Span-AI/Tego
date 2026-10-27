// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeOpener is a script that writes its arguments to a file beside it, standing in for a browser.
func fakeOpener(t *testing.T) (script, out string) {
	t.Helper()
	dir := t.TempDir()
	script, out = filepath.Join(dir, "opener"), filepath.Join(dir, "args")
	body := "#!/bin/sh\nprintf '%s\\n' \"$*\" > '" + out + ".tmp' && mv '" + out + ".tmp' '" + out + "'\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return script, out
}

func waitFile(t *testing.T, path string) string {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if b, err := os.ReadFile(path); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	t.Fatalf("%s never appeared: the opener did not run", path)
	return ""
}

// TestOpenURLStartsTheOpenerWithTheURL: $BROWSER's command gets the URL appended, or in place of %s, and a first
// entry that does not exist falls through to the next.
func TestOpenURLStartsTheOpenerWithTheURL(t *testing.T) {
	script, out := fakeOpener(t)
	if err := openURL("http://127.0.0.1:1/?t=abc", "/nonexistent/browser:"+script+" --new-window"); err != nil {
		t.Fatal(err)
	}
	if got := waitFile(t, out); got != "--new-window http://127.0.0.1:1/?t=abc" {
		t.Errorf("opener args %q", got)
	}
	script, out = fakeOpener(t)
	if err := openURL("http://127.0.0.1:2/?t=x", script+" --app=%s"); err != nil {
		t.Fatal(err)
	}
	if got := waitFile(t, out); got != "--app=http://127.0.0.1:2/?t=x" {
		t.Errorf("opener args %q", got)
	}
}

// TestOpenURLWithNoOpenerIsAnError: no $BROWSER and no xdg-open on PATH is an error for the caller to print, not a panic.
func TestOpenURLWithNoOpenerIsAnError(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if err := openURL("http://127.0.0.1:1/", ""); err == nil {
		t.Fatal("no opener exists, want an error")
	}
}

// TestServeOpenPrintsTheURLAndOpensIt: serve --open prints the URL, starts the opener with it, and with no opener at
// all still serves, printing the URL and one stderr line saying so.
func TestServeOpenPrintsTheURLAndOpensIt(t *testing.T) {
	ledger := t.TempDir()
	run := func(t *testing.T, until func() bool) (stdout, stderr string, code int) {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var so, se bytes.Buffer
		done := make(chan int, 1)
		go func() {
			done <- cmdServe().Run(ctx, []string{"--addr", "127.0.0.1:0", "--ledger", ledger, "--open"}, &so, &se)
		}()
		for end := time.Now().Add(5 * time.Second); !until() && time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		}
		cancel()
		select {
		case code = <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("serve did not stop")
		}
		return so.String(), se.String(), code
	}

	script, out := fakeOpener(t)
	t.Setenv("BROWSER", script)
	// The opener's address signs in once (303 with the session cookie), and a second use of it is refused: it is a
	// one-time code, never the printed token (web/opencode.go).
	var first, second *http.Response
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout: 5 * time.Second}
	so, _, code := run(t, func() bool {
		b, err := os.ReadFile(out)
		if err != nil {
			return false
		}
		opened := strings.TrimSpace(string(b))
		if first, err = noFollow.Get(opened); err == nil {
			_ = first.Body.Close()
			if second, err = noFollow.Get(opened); err == nil {
				_ = second.Body.Close()
			}
		}
		return true
	})
	url := strings.TrimSpace(strings.TrimPrefix(so, "Tego dashboard: "))
	if code != 0 || !strings.HasPrefix(url, "http://127.0.0.1:") || !strings.Contains(url, "/?t=") {
		t.Fatalf("exit %d, stdout %q", code, so)
	}
	host, token, _ := strings.Cut(url, "/?t=")
	got := waitFile(t, out)
	if !strings.HasPrefix(got, host+"/?o=") || strings.Contains(got, token) {
		t.Errorf("the opener got %q, want %s/?o=<code> without the printed token", got, host)
	}
	if first == nil || first.StatusCode != http.StatusSeeOther || len(first.Cookies()) != 1 {
		t.Errorf("the opener's address: %+v, want a 303 with the session cookie", first)
	}
	if second == nil || second.StatusCode != http.StatusUnauthorized {
		t.Errorf("the opener's address used again: %+v, want 401", second)
	}

	t.Setenv("BROWSER", "")
	t.Setenv("PATH", t.TempDir())
	t0 := time.Now()
	so, se, code := run(t, func() bool { return time.Since(t0) > 300*time.Millisecond }) // the note is printed before Serve runs
	if code != 0 || !strings.HasPrefix(so, "Tego dashboard: http://127.0.0.1:") || !strings.Contains(se, "--open") {
		t.Errorf("no opener: exit %d, stdout %q, stderr %q; want a normal serve and a note", code, so, se)
	}
}
