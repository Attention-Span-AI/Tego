// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// eventAction is the phone timeline's action. The linked Event retains the
// exact target, process, deciding rule and raw record.
func eventAction(e ledgerview.Event) string {
	if e.Malformed != "" {
		return capFirst(e.Malformed)
	}
	switch e.Kind {
	case "run_start":
		return "Run started"
	case "run_end":
		return "Run ended"
	case "exec":
		return "Run a program"
	case "net":
		return "Connect to a destination"
	case "fs":
		switch e.Op {
		case "write", "unlink", "rename", "mkdir":
			return "Change a file"
		}
		return "Open a file"
	case "refused":
		switch e.Op {
		case "connect", "net":
			return "Connect to a destination"
		case "exec":
			return "Run a program"
		case "open", "read":
			return "Open a file"
		case "write", "unlink", "rename", "mkdir":
			return "Change a file"
		}
		return "Action refused"
	case "ask":
		return "Request to " + askVerb(e.Op, e.Rule, "")
	case "answer":
		return "Request answered"
	}
	return shownOp(e)
}

// protectedReadChip gives every page the same meaning for a protected read.
// An allowed read of the agent's own login stays routine; observation alone
// supplies no such exception.
func protectedReadChip(verdict string, own, unread bool) verdictChip {
	c := verdictChip{Class: "b-through", Icon: "i-triangle-alert", Text: "Read allowed"}
	if verdict == "allow" && own {
		return verdictChip{Class: "b-neutral", Icon: "i-check", Text: "Allowed"}
	}
	if verdict == "observed" {
		c.Text = "Read, not refused"
	}
	if unread {
		c.Text = "Protected file touched"
		if verdict == "observed" {
			c.Text = "Touch, not refused"
		}
	}
	return c
}

// readContext carries the run and its contract-aware signal classification.
// The path index is built once per rendered page, rather than scanned per row.
type readContext struct {
	agent string
	paths map[string]bool
}

func readContextOf(r *ledgerview.Run, sig *ledgerview.RunSignal) *readContext {
	c := &readContext{paths: map[string]bool{}}
	if r != nil {
		c.agent = r.CommandAgent()
	}
	if sig != nil {
		for _, touch := range sig.Secrets {
			c.paths[touch.Path] = true
		}
	}
	return c
}

// secretChips formats the signal's protected touches with the same read chips
// as the receipt and individual events. Write-only touches stay named as touches.
func secretChips(s ledgerview.SecretTouch, r *ledgerview.Run) []verdictChip {
	var out []verdictChip
	if s.Refused > 0 {
		out = append(out, verdictChip{Class: "b-refused", Icon: "i-ban", Text: "Refused", N: s.Refused})
	}
	if s.Asked > 0 {
		out = append(out, verdictChip{Class: "b-asked", Icon: "i-hand", Text: "Asked", N: s.Asked})
	}
	own := r != nil && ledgerview.AgentOwn(r.CommandAgent(), s.Path)
	for _, v := range []struct {
		verdict string
		n       int
	}{{"allow", s.Allowed}, {"observed", s.Observed}} {
		if v.n > 0 {
			c := protectedReadChip(v.verdict, own, s.Unread > 0)
			c.N = v.n
			out = append(out, c)
		}
	}
	return out
}

// pageVerdict classifies an actual read against the run's contract-aware signal.
// Missing context leaves the recorded verdict; it cannot infer a protected read.
func pageVerdict(e ledgerview.Event, context ...*readContext) (class, icon, word string) {
	if len(context) > 0 && context[0] != nil && context[0].paths[e.Target] && e.Kind == "fs" && (e.Verdict == "allow" || e.Verdict == "observed") {
		var p struct {
			Op         string `json:"op"`
			Flags      int    `json:"flags"`
			Errno      int    `json:"errno"`
			SyscallRet int64  `json:"syscall_ret"`
			Created    bool   `json:"created"`
		}
		if json.Unmarshal([]byte(e.Raw), &p) == nil && p.SyscallRet >= 0 && ledgerview.ReadOpen(p.Op, p.Flags, p.Errno, p.Created) {
			c := protectedReadChip(e.Verdict, ledgerview.AgentOwn(context[0].agent, e.Target), false)
			return c.Class[2:], c.Icon, c.Text
		}
	}
	return lineVerdict(e)
}

// sensitiveReadRecorded uses the event chips' own-login exception. Aggregate
// counts settle ordinary paths; mixed own-login reads and write-only touches
// need the actual events because Unread is not split by verdict.
func sensitiveReadRecorded(r *ledgerview.Run, sig *ledgerview.RunSignal) bool {
	if r == nil || sig == nil {
		return false
	}
	agent := r.CommandAgent()
	ambiguous := &readContext{agent: agent, paths: map[string]bool{}}
	for _, touch := range sig.Secrets {
		if touch.Allowed+touch.Observed <= touch.Unread {
			continue
		}
		if !ledgerview.AgentOwn(agent, touch.Path) {
			return true
		}
		if touch.Observed == 0 {
			continue
		}
		if touch.Allowed == 0 || touch.Unread == 0 {
			return true
		}
		ambiguous.paths[touch.Path] = true
	}
	if len(ambiguous.paths) == 0 {
		return false
	}
	for _, e := range r.AllEvents() {
		if class, _, _ := pageVerdict(e, ambiguous); class == "through" {
			return true
		}
	}
	return false
}
