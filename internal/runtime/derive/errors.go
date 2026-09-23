// SPDX-License-Identifier: Apache-2.0

package derive

import "errors"

// ErrNoRequest is returned by Dispatcher.Handle when it is given no request message. It signals a caller
// bug, never a runtime condition: an unparseable body is a decision event, not an error (§4, R29).
var ErrNoRequest = errors.New("derive: no request message")

// ErrSchema is the sentinel a Parser wraps when a body's structure is not the one it knows: a JSON syntax
// error, a missing required field, an unknown stream event, a delta for an unopened block, or a body the
// capture truncated. Mapped to decision: unparsed why=schema (R29).
var ErrSchema = errors.New("derive: schema")

// ErrEncoding is the sentinel a Parser wraps when the bytes it was handed are not decoded text: a
// Content-Encoding capture could not undo, or bytes that are not valid UTF-8/JSON after decoding.
// Mapped to decision: unparsed why=encoding (R29).
var ErrEncoding = errors.New("derive: encoding")

// ErrH2 is the sentinel for bytes that turned out to be HTTP/2. Capture aborts h2 reassembly before derive
// ever sees it (R17), so this exists as the defensive third value of the closed why set (R29).
var ErrH2 = errors.New("derive: http/2")
