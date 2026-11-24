// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"math"
	"strconv"

	"github.com/attention-span-ai/tego/pkg/policy/mcptool"
)

// MaxBatch bounds the messages one JSON-RPC batch may carry. A batch past it is refused whole and unread, with one
// error and one line of the record, since each member of a larger one would be a line and an answer of its own, and a
// body of 4 MiB holds a million members (ADR 0126 §4, amended 2026-11-21).
const MaxBatch = 128

// tooManyAnswer is the JSON-RPC invalid-request error a client gets for a batch of more than MaxBatch members.
var tooManyAnswer = []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Tego's MCP relay passes batches of at most ` +
	strconv.Itoa(MaxBatch) + ` messages, so no message of this batch was passed to the server"}}`)

// What the relay does with one member of a batch.
type itemKind int

const (
	// itemPass goes to the server.
	itemPass itemKind = iota
	// itemRefuse is answered with an error of its own, and never reaches the server.
	itemRefuse
	// itemAsk is held for a person, as a single call is.
	itemAsk
)

// batchItem is one member of a batch and what the relay decided for it, on its own.
type batchItem struct {
	cl   call
	kind itemKind
	// res is a tools/call's decision (itemPass and itemAsk).
	res mcptool.Result
	// rule, reason and because are an itemRefuse's: the rule and reason of its line of the record and the words after
	// the colon of its error. because is empty for a tool the rules deny, whose error is the usual one.
	rule, reason, because string
}

// answer is the JSON-RPC error of a refused member.
func (it batchItem) answer(server string) []byte {
	if it.because != "" {
		return mcptool.RefusalBecause(it.cl.id, server, it.cl.tool, it.rule, it.reason, it.because)
	}
	return mcptool.Refusal(it.cl.id, server, it.cl.tool, it.rule, it.reason)
}

// refused is a refusal of cl by the relay's own rule, not by a tool's decision.
func refused(server string, cl call, because string) batchItem {
	return batchItem{cl: cl, kind: itemRefuse, rule: "mcp[" + server + "].relay", reason: mcptool.ReasonDenied, because: because}
}

// idKey is a request id as one value: a number is one id whatever it is spelt (1, 1.0, 1e0), a string is another (1 and "1"
// differ), null is its own. It is hashed, so a table of ids holds a fixed size for each, whatever the ids are.
func idKey(id json.RawMessage) string {
	t := bytes.TrimSpace(id)
	var canon string
	switch {
	case len(t) == 0:
		return ""
	case t[0] == '"':
		var v string
		if json.Unmarshal(t, &v) != nil {
			canon = "r:" + string(t)
		} else {
			canon = "s:" + v
		}
	case string(t) == "null":
		canon = "z"
	default:
		if f, err := strconv.ParseFloat(string(t), 64); err == nil && !math.IsInf(f, 0) {
			canon = "n:" + strconv.FormatFloat(f, 'g', -1, 64)
		} else {
			canon = "r:" + string(t)
		}
	}
	sum := sha256.Sum256([]byte(canon))
	return string(sum[:16])
}

// planBatch decides every member of a batch on its own (ADR 0126 §4, amended 2026-11-21):
//   - a request whose id another request of the batch also has is refused with every request of that id, and the server
//     never sees either: two answers under one id could be told apart by no client, so the refused one's error could be
//     read as the allowed one's result, or the reverse. Ids compare as values (idKey: 1, 1.0 and 1e0 are one, "1" another);
//     a notification has none and a response is the client's answer to the server, so neither counts;
//   - a tools/call is decided by the rules as a single one is: allow passes, deny is refused, ask is held, and a call
//     whose tool the relay cannot name is refused;
//   - every other message passes.
//
// A member's decision never depends on another's, and the plan makes no record line and holds nothing: the caller does
// both, in the order of the members.
func (s *Service) planBatch(server string, calls []call) []batchItem {
	ids := map[string]int{}
	for _, cl := range calls {
		if cl.method != "" && len(cl.id) > 0 {
			ids[idKey(cl.id)]++
		}
	}
	out := make([]batchItem, len(calls))
	for i, cl := range calls {
		it := batchItem{cl: cl}
		switch {
		case cl.method != "" && len(cl.id) > 0 && ids[idKey(cl.id)] > 1:
			it = refused(server, cl, "another message of this batch has the same id, so no answer could be told apart")
		case !cl.isCall:
		case cl.tool == "":
			it = refused(server, cl, "")
		default:
			it.res = s.decide(server, cl.tool)
			switch it.res.Decision {
			case mcptool.Allow:
			case mcptool.Ask:
				it.kind = itemAsk
			default:
				it.kind, it.rule, it.reason = itemRefuse, it.res.Rule, mcptool.ReasonDenied
			}
		}
		out[i] = it
	}
	return out
}

// joinJSON is the members as one JSON array, each as it is: json.Marshal would rewrite a RawMessage's bytes (HTML escapes),
// and a member passed to the server is the wire form the relay decided.
func joinJSON(members []json.RawMessage) []byte {
	var b bytes.Buffer
	b.WriteByte('[')
	for i, m := range members {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(m)
	}
	b.WriteByte(']')
	return b.Bytes()
}
