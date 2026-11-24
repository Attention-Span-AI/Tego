// SPDX-License-Identifier: Apache-2.0

package record

import (
	"regexp"
	"strconv"
)

// The why of a gap what=record the MCP relay writes for a message it dropped because it was past the size the relay
// reads (GAPS C201, C202). The relay never passes on what it cannot read whole, so the message did not reach its
// reader: the line says which side, how big the message was and what the limit was, in binary (OversizeNote). No
// field is added to the payload and no revision is needed: a reader that does not know either why reads the line as
// any gap what=record it does not know, a loss it cannot size, which is the conservative reading (gaps.Missed).
//
//	GapMCPResponseOversize is an answer of a stdio server (one JSON-RPC line) or a url server's JSON answer to a
//	tools/list, dropped (the client got none; an HTTP client got a 502).
//	GapMCPStreamOversize is one message of a url server's event stream, dropped from the stream: the client read the
//	rest of the stream without it.
//
// A run writes at most OversizeLines lines of each why for one server; the messages past that are counted in one line
// of the same why with count and no binary, written when the relay stops.
const (
	GapMCPResponseOversize = "mcp-response-oversize"
	GapMCPStreamOversize   = "mcp-stream-oversize"
)

// OversizeLines is how many oversize lines of one why a run writes for one server before it only counts them.
const OversizeLines = 16

// OversizeNote is the binary of an oversize gap line: the server's name, then ": ", the message's size in bytes and
// the limit. size 0 says the relay stopped reading at the limit and did not learn the size, which the note writes as
// "more than <limit> bytes".
func OversizeNote(server string, size, limit int64) string {
	s := server + ": "
	if size > limit {
		s += strconv.FormatInt(size, 10) + " bytes"
	} else {
		s += "more than " + strconv.FormatInt(limit, 10) + " bytes"
	}
	return s + ", limit " + strconv.FormatInt(limit, 10) + " bytes"
}

var oversizeRE = regexp.MustCompile(`^(.*): (more than )?([0-9]+) bytes?(?:, limit ([0-9]+) bytes)$`)

// ParseOversizeNote reads an OversizeNote back: the server, the size (0 when the note says "more than"), the limit
// and whether the note was one. A reader that gets false shows the binary as it is.
func ParseOversizeNote(binary string) (server string, size, limit int64, ok bool) {
	m := oversizeRE.FindStringSubmatch(binary)
	if m == nil {
		return "", 0, 0, false
	}
	n, err1 := strconv.ParseInt(m[3], 10, 64)
	l, err2 := strconv.ParseInt(m[4], 10, 64)
	if err1 != nil || err2 != nil {
		return "", 0, 0, false
	}
	if m[2] != "" {
		return m[1], 0, l, true
	}
	return m[1], n, l, true
}

// GapModelRouteUnreadable is the why of a gap what=enforce the forwarder writes once per state of a run's model route
// overlay it could not read (GAPS C220): the routes it read last stay in force, so no request goes by a route no
// line put in force, and a person's change made in that state is not applied. It has no count and no binary.
const GapModelRouteUnreadable = "model-route-unreadable"
