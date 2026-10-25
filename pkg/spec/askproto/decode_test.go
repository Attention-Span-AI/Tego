// SPDX-License-Identifier: Apache-2.0

package askproto

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

type corpusCase struct {
	In    string `json:"in"`
	Err   string `json:"err,omitempty"`
	Value string `json:"value,omitempty"`
}

func readCorpus(t testing.TB) (commands, responses []corpusCase) {
	t.Helper()
	b, err := os.ReadFile("testdata/corpus-e47e1ba4.json")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Commands  []corpusCase `json:"commands"`
		Responses []corpusCase `json:"responses"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c.Commands, c.Responses
}

// TestDecodeCommandCorpusAsBefore: every command of the corpus recorded from the decoder before it
// moved here, is accepted or refused as it was then, and an accepted one decodes to the same value.
func TestDecodeCommandCorpusAsBefore(t *testing.T) {
	commands, _ := readCorpus(t)
	if len(commands) < 50 {
		t.Fatalf("the corpus holds %d commands", len(commands))
	}
	accepted := 0
	for _, want := range commands {
		c, err := DecodeCommand([]byte(want.In))
		got := corpusCase{In: want.In}
		if err != nil {
			got.Err = err.Error()
		} else {
			accepted++
			b, _ := json.Marshal(c)
			got.Value = string(b)
		}
		if got != want {
			t.Errorf("%q: %q / %s, before the move %q / %s", want.In, got.Err, got.Value, want.Err, want.Value)
		}
	}
	if accepted == 0 || accepted == len(commands) {
		t.Fatalf("%d of %d commands accepted: the corpus must hold both", accepted, len(commands))
	}
}

// TestEveryCodeRoundTrips: each sentinel's code, sent with the sentinel's text, reads back as that sentinel, and an
// error the broker wraps keeps its code.
func TestEveryCodeRoundTrips(t *testing.T) {
	for _, c := range []struct {
		err  error
		code string
	}{
		{ErrNotPending, CodeNotPending}, {ErrNotRememberable, CodeNotRememberable}, {ErrStandingFull, CodeStandingFull},
		{ErrStandingBusy, CodeStandingBusy}, {ErrNoAlternate, CodeNoAlternate}, {ErrBadAlternate, CodeBadAlternate},
		{ErrProtocol, CodeProtocol}, {ErrUnavailable, CodeUnavailable}, {errors.New("context deadline exceeded"), CodeUnavailable},
	} {
		if got := Code(c.err); got != c.code {
			t.Errorf("Code(%v) = %q, want %q", c.err, got, c.code)
		}
		if got := Code(errors.Join(errors.New("wrapped"), c.err)); got != c.code {
			t.Errorf("Code(wrapped %v) = %q, want %q", c.err, got, c.code)
		}
		data, _ := json.Marshal(Response{Error: c.err.Error(), Code: c.code})
		if _, err := DecodeResponse(data); err == nil || (strings.HasPrefix(c.err.Error(), "ask:") && !errors.Is(err, c.err)) {
			t.Errorf("%s: read back as %v", data, err)
		}
	}
	data, _ := json.Marshal(Response{Error: ErrUnauthorized.Error(), Code: CodeUnauthorized})
	if _, err := DecodeResponse(data); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("unauthorized read back as %v", err)
	}
	if _, err := DecodeResponse([]byte(ResponseTooLarge)); !errors.Is(err, ErrUnavailable) {
		t.Errorf("the too-large reply read back as %v", err)
	}
}

// FuzzAskprotoDecode: neither decoder panics on any packet. An accepted command keeps the rules DecodeCommand
// states (a nonce of NonceLen, a known action with only its own fields, a valid ask id, an alternate only on a
// refusal and only a valid path) and encodes to bytes that decode to the same command. A response read without
// error carries no error text, and one read with an error of a code this side knows returns that code's sentinel.
func FuzzAskprotoDecode(f *testing.F) {
	commands, responses := readCorpus(f)
	for _, c := range commands {
		f.Add([]byte(c.In))
	}
	for _, c := range responses {
		f.Add([]byte(c.In))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if c, err := DecodeCommand(data); err == nil {
			if len(c.Nonce) != NonceLen {
				t.Fatalf("accepted nonce %q", c.Nonce)
			}
			switch c.Action {
			case ActionList:
				if c.AskID != "" || c.Approve != nil || c.Remember != nil || c.Alternate != nil {
					t.Fatalf("a list with fields: %+v", c)
				}
			case ActionDetail:
				if !ValidID(c.AskID) || c.Approve != nil || c.Remember != nil || c.Alternate != nil {
					t.Fatalf("a detail with fields: %+v", c)
				}
			case ActionAnswer:
				if !ValidID(c.AskID) || c.Approve == nil || (c.Alternate != nil && (*c.Approve || !ValidAlternate(*c.Alternate))) {
					t.Fatalf("an answer out of rule: %+v", c)
				}
			default:
				t.Fatalf("accepted action %q", c.Action)
			}
			b, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			again, err := DecodeCommand(b)
			if err != nil || !reflect.DeepEqual(again, c) {
				t.Fatalf("%s re-encoded as %s decodes to %+v, %v", data, b, again, err)
			}
		} else if !errors.Is(err, ErrProtocol) {
			t.Fatalf("a refused command is ErrProtocol, not %v", err)
		}
		r, err := DecodeResponse(data)
		switch {
		case err == nil && r.Error != "":
			t.Fatalf("an error response %q read without error", r.Error)
		case err != nil && r.Error == "" && !errors.Is(err, ErrProtocol):
			t.Fatalf("an undecodable response is ErrProtocol, not %v", err)
		case err != nil && r.Code == CodeNotPending && !errors.Is(err, ErrNotPending),
			err != nil && r.Code == CodeBadAlternate && !errors.Is(err, ErrBadAlternate),
			err != nil && r.Code == CodeUnauthorized && !errors.Is(err, ErrUnauthorized):
			t.Fatalf("code %q read as %v", r.Code, err)
		}
	})
}
