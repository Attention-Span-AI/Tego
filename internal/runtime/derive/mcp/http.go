// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
	"net/http"
)

// ErrUnreadable is a POST body that holds no message this package can read: not JSON-RPC, cut short by a capture
// cap, or longer than MaxMessage.
var ErrUnreadable = errors.New("mcp: request body unreadable")

// ReadHTTPRequest reads one request a client sent its server over HTTP. Both HTTP transports carry the client's
// messages in POST bodies — the streamable transport (2025-03-26 on) at the server's one endpoint, the HTTP+SSE
// transport (2024-11-05) at the endpoint its event stream named — one message or a batch per body. A GET opens the
// server's event stream and a DELETE ends a session: neither carries a client message, and an empty body names
// nothing.
//
// A body that names some items and has unreadable batch members returns both: the items and a Result.Malformed
// count. A body that cannot be read at all returns ErrUnreadable; truncated says a capture cap cut it, which no
// reading can repair.
func ReadHTTPRequest(method string, body []byte, truncated bool) (Result, error) {
	if method != http.MethodPost || len(trimSpace(body)) == 0 && !truncated {
		return Result{}, nil
	}
	if truncated || len(body) > MaxMessage {
		return Result{}, ErrUnreadable
	}
	items, bad := Read(body)
	if len(items) == 0 && bad > 0 {
		return Result{}, ErrUnreadable
	}
	return Result{Items: items, Malformed: bad}, nil
}
