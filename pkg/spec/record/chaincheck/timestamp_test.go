// SPDX-License-Identifier: Apache-2.0

package chaincheck

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// A complete record must never disappear as a torn tail when a stricter field parser refuses it.
func TestRefusedTimestampIsNeverATornTail(t *testing.T) {
	raw, err := os.ReadFile("../../../../spec/record/v1/fixtures/profiles.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'})
	for _, stamp := range []string{"2026-09-22T09:00:00,002Z", "2026-09-22T9:00:00Z", "2026-09-22T09:00:00+24:00", "2026-09-22T09:00:00+00:60"} {
		for _, terminated := range []bool{true, false} {
			t.Run(stamp+map[bool]string{true: "/terminated", false: "/unterminated"}[terminated], func(t *testing.T) {
				last := bytes.Clone(lines[len(lines)-1])
				begin := bytes.Index(last, []byte(`"ts":"`)) + 6
				end := begin + bytes.IndexByte(last[begin:], '"')
				last = append(append(bytes.Clone(last[:begin]), stamp...), last[end:]...)
				data := bytes.Join(append(append([][]byte(nil), lines[:len(lines)-1]...), last), []byte{'\n'})
				if terminated {
					data = append(data, '\n')
				}
				rep, err := Check(Input{Dir: "copy", Events: data})
				v, r := Reason(rep, err, nil)
				if v != "mismatch" || r != "line-malformed" || rep.TornBytes != 0 || !rep.AtLine {
					t.Fatalf("%s %s %+v %v", v, r, rep, err)
				}
			})
		}
	}
}

func TestWholeLineUsesJSONCompleteness(t *testing.T) {
	for _, s := range []string{`{}`, `{"v":1,"ts":"bad"}`, `{"v":1,"v":1}`, `null`, `[]`, `nullx`, `truex`, `falsex`, `1x`, `"scalar"x`, `01`, `-01`, `00.1`, `-00e1`} {
		if !WholeLine([]byte(s)) {
			t.Errorf("complete JSON hidden: %s", s)
		}
	}
	for _, s := range []string{`{"v":1`, `{"v":`, `garbage`} {
		if WholeLine([]byte(s)) {
			t.Errorf("torn bytes read: %s", s)
		}
	}
}

func TestWholeLineDoesNotInterpretJSONGrammarOrDepth(t *testing.T) {
	for _, s := range []string{strings.Repeat("[", 10001) + "0" + strings.Repeat("]", 10001), `{"a":}`, `{"a":1,}`, `{}x`, `{}{"v":`, "{} \t\r"} {
		if !WholeLine([]byte(s)) {
			t.Fatalf("closed JSON container hidden (len %d)", len(s))
		}
	}
	for _, s := range []string{`{"a":"}`, `{"a":[]`, `[{]}`} {
		if WholeLine([]byte(s)) {
			t.Fatalf("unclosed bytes framed: %s", s)
		}
	}
}
