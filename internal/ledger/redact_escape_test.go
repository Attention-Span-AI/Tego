// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Redact rewrites the payload it changes without HTML escaping: '&', '<', '>' and U+2028 in the fields it
// never meant to touch stay as the producer wrote them.
func TestRedactKeepsUnescapedText(t *testing.T) {
	e := record.Event{
		Kind:    record.KindSSLRequest,
		Payload: []byte("{\"headers\":{\"content-type\":\"a&b<c\"},\"note\":\"a<b && c>d\",\"path\":\"/v1/m?x=1&y=2\"}"),
	}
	if err := Redact(&e); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"\"note\":\"a<b && c>d\"", "\"content-type\":\"a&b<c\"", "/redacted?redacted"} {
		if !strings.Contains(string(e.Payload), want) {
			t.Errorf("payload %q lost %q", e.Payload, want)
		}
	}
}

// TestRedactEscapedKeys: a top-level key spelled with JSON escapes is still that key. MarshalLine writes it to
// disk as a plain "headers" or "path", so Redact must not skip the payload just because the plain spelling
// is absent from its bytes (R9).
func TestRedactEscapedKeys(t *testing.T) {
	const secret = "SECRETSECRETSECRETSECRET"
	w, dir := startedWriter(t)
	e := &record.Event{Kind: record.KindSSLRequest, Source: record.SourceForwarder, PID: 48212, TID: 48212}
	e.Payload = []byte(`{"\u0068eaders":{"authorization":"Bearer ` + secret + `","content-type":"a"},` +
		`"\u0070ath":"/v1?key=` + secret + `","method":"POST"}`)
	if err := RedactStage(w.Append)(e); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"content-type":"a"`) || !strings.Contains(string(data), `/redacted?redacted`) {
		t.Fatalf("the event did not reach disk as expected:\n%s", data)
	}
	for _, leak := range []string{secret, "authorization"} {
		if strings.Contains(string(data), leak) {
			t.Errorf("%q reached disk:\n%s", leak, data)
		}
	}
}

// TestRedactFoldedKeys: encoding/json matches a field name case-insensitively (Unicode simple folding), so a
// top-level "Headers", "HEADERS", "headerſ" or "Path" is the headers or path every reader decodes. Redact
// must treat each as that field; before it did, such a payload reached disk byte-identical (R9, R9a).
func TestRedactFoldedKeys(t *testing.T) {
	const secret = "SECRETSECRETSECRETSECRET"
	cases := map[string]string{
		"Headers": `{"Headers":{"Authorization":"Bearer ` + secret + `"},"Path":"/v1?key=` + secret + `","method":"POST"}`,
		"HEADERS": `{"HEADERS":{"x-api-key":"` + secret + `","content-type":"a"},"PATH":"/v1?key=` + secret + `"}`,
		"both":    `{"headers":{"content-type":"a"},"Headers":{"cookie":"` + secret + `"},"path":"/v1","pAtH":"/v1?k=` + secret + `"}`,
		"long s":  `{"headerſ":{"authorization":"` + secret + `"},"method":"POST"}`,
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			e := record.Event{Kind: record.KindSSLRequest, Payload: []byte(payload)}
			if err := Redact(&e); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(e.Payload), secret) {
				t.Fatalf("secret survived: %s", e.Payload)
			}
			var p record.SSLRequestPayload
			if err := json.Unmarshal(e.Payload, &p); err != nil {
				t.Fatal(err)
			}
			if p.Headers["content-type"] == "" && strings.Contains(payload, "content-type") {
				t.Errorf("allowed header lost: %s", e.Payload)
			}
		})
	}
	// An exec or fs path is a filesystem path, kept exactly whatever its key's case.
	e := record.Event{Kind: record.KindExec, Payload: []byte(`{"Path":"/bin/x?key=1"}`)}
	if err := Redact(&e); err != nil {
		t.Fatal(err)
	}
	if string(e.Payload) != `{"Path":"/bin/x?key=1"}` {
		t.Errorf("exec payload changed: %s", e.Payload)
	}
}
