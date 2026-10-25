// SPDX-License-Identifier: Apache-2.0

package askproto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// DecodeCommand reads a client's packet strictly: one flat JSON object, every key known and given once, no null
// value, nothing after it, a nonce of NonceLen characters, and only the fields its action takes. Anything else is
// ErrProtocol. It does not compare the nonce with the hello's; the broker does.
func DecodeCommand(data []byte) (Command, error) {
	// A flat command lets us reject duplicate keys as well as unknown keys.
	d := json.NewDecoder(bytes.NewReader(data))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return Command{}, ErrProtocol
	}
	seen := make(map[string]bool)
	var c Command
	for d.More() {
		t, err = d.Token()
		key, ok := t.(string)
		if err != nil || !ok || seen[key] {
			return Command{}, ErrProtocol
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return Command{}, ErrProtocol
		}
		switch key {
		case "action":
			err = json.Unmarshal(value, &c.Action)
		case "nonce":
			err = json.Unmarshal(value, &c.Nonce)
		case "ask_id":
			err = json.Unmarshal(value, &c.AskID)
		case "approve":
			err = json.Unmarshal(value, &c.Approve)
		case "remember":
			err = json.Unmarshal(value, &c.Remember)
		case "alternate":
			err = json.Unmarshal(value, &c.Alternate)
		default:
			return Command{}, ErrProtocol
		}
		if err != nil {
			return Command{}, ErrProtocol
		}
	}
	t, err = d.Token()
	if err != nil || t != json.Delim('}') {
		return Command{}, ErrProtocol
	}
	if _, err = d.Token(); !errors.Is(err, io.EOF) {
		return Command{}, ErrProtocol
	}
	if len(c.Nonce) != NonceLen {
		return Command{}, ErrProtocol
	}
	switch c.Action {
	case ActionList:
		if seen["ask_id"] || seen["approve"] || seen["remember"] || seen["alternate"] {
			return Command{}, ErrProtocol
		}
	case ActionDetail:
		if !ValidID(c.AskID) || c.Approve != nil || c.Remember != nil || c.Alternate != nil {
			return Command{}, ErrProtocol
		}
	case ActionAnswer:
		if !ValidID(c.AskID) || c.Approve == nil {
			return Command{}, ErrProtocol
		}
		// An alternate is never an approval of the target, and is a path that can be one at all.
		if c.Alternate != nil && (*c.Approve || !ValidAlternate(*c.Alternate)) {
			return Command{}, ErrProtocol
		}
	default:
		return Command{}, ErrProtocol
	}
	return c, nil
}

// DecodeResponse reads a broker's packet: one JSON object of Response's fields and nothing after it, else
// ErrProtocol. A response that carries an error returns it with the sentinel its code names, the broker's own
// text kept where the code says the text is the reason (bad-alternate, and any code this client does not know,
// which is ErrUnavailable). The text came over the socket, so a caller prints it made printable.
func DecodeResponse(data []byte) (Response, error) {
	var r Response
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return Response{}, ErrProtocol
	}
	if d.Decode(new(any)) != io.EOF {
		return Response{}, ErrProtocol
	}
	if r.Error != "" {
		switch r.Code {
		case CodeNotPending:
			return r, ErrNotPending
		case CodeNotRememberable:
			return r, ErrNotRememberable
		case CodeStandingFull:
			return r, ErrStandingFull
		case CodeStandingBusy:
			return r, ErrStandingBusy
		case CodeNoAlternate:
			return r, ErrNoAlternate
		case CodeBadAlternate:
			// The broker's text after the sentinel's says why.
			return r, fmt.Errorf("%w%s", ErrBadAlternate, strings.TrimPrefix(r.Error, ErrBadAlternate.Error()))
		case CodeUnauthorized:
			return r, ErrUnauthorized
		case CodeProtocol:
			return r, ErrProtocol
		default:
			return r, fmt.Errorf("%w: %s", ErrUnavailable, r.Error)
		}
	}
	return r, nil
}

// Code is the response code for the error an exchange ended in: the code of the first sentinel err wraps, and
// CodeUnavailable for every other error.
func Code(err error) string {
	switch {
	case errors.Is(err, ErrNotPending):
		return CodeNotPending
	case errors.Is(err, ErrNotRememberable):
		return CodeNotRememberable
	case errors.Is(err, ErrStandingFull):
		return CodeStandingFull
	case errors.Is(err, ErrStandingBusy):
		return CodeStandingBusy
	case errors.Is(err, ErrNoAlternate):
		return CodeNoAlternate
	case errors.Is(err, ErrBadAlternate):
		return CodeBadAlternate
	case errors.Is(err, ErrProtocol):
		return CodeProtocol
	default:
		return CodeUnavailable
	}
}
