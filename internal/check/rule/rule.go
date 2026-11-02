// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"errors"
	"fmt"
	"net/netip"
	"path"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Action is what the next run does with the action the event shows.
type Action string

// The three actions.
const (
	Block Action = "block"
	Ask   Action = "ask"
	Allow Action = "allow"
)

// Kind is what the event did, as a rule sees it.
type Kind string

// The kinds of event a rule can be made from.
const (
	KindRead  Kind = "read"
	KindWrite Kind = "write" // a write, create, delete, rename, mkdir, chmod and the like
	KindExec  Kind = "exec"
	KindNet   Kind = "net"
)

// Target is what an event names: the one path, program or destination a rule from it may name.
type Target struct {
	Kind Kind
	// Path is the absolute file path (read, write) or the program's image path (exec).
	Path string
	// Dest is the destination as net.allow spells it (host:port, ip:port or unix:<path>).
	Dest string
	// Op is the event's operation (open, unlink, connect, exec, ...).
	Op string
	// Refused is whether the run was refused the action (or held it and did not do it).
	Refused bool
	// Rule is the rule that decided, as the event spells it ("fs.deny_read[../secrets/]", "exec[sh]", "net[h:443]").
	Rule string
	// Argv is an exec's argument vector, when the event carries it.
	Argv []string
}

// What is the target as a person reads it: the path, the program or the destination.
func (t Target) What() string {
	if t.Kind == KindNet {
		return t.Dest
	}
	return t.Path
}

// Verb is the action the event shows, in words ("read", "write to", "run", "connect to").
func (t Target) Verb() string {
	switch t.Kind {
	case KindRead:
		return "read"
	case KindWrite:
		return "write to"
	case KindExec:
		return "run"
	}
	return "connect to"
}

// ErrUnsupported is TargetOf's error for an event no rule can be made from (a run_start, a model call, a gap).
var ErrUnsupported = errors.New("no rule can be made from this event")

const (
	oAccmode = 0o3
	oCreat   = 0o100
	oTrunc   = 0o1000
)

// TargetOf reads the target of e: an fs, exec or net event, or a refusal of one of those.
func TargetOf(e *record.Event) (Target, error) {
	t := Target{Rule: e.Rule, Refused: e.Verdict == record.VerdictRefused || e.Verdict == record.VerdictAsk}
	switch e.Kind {
	case record.KindFS:
		var p record.FSPayload
		if err := e.DecodePayload(&p); err != nil {
			return t, fmt.Errorf("fs event at seq %d: %w", e.Seq, err)
		}
		t.Op, t.Path = p.Op, p.Path
		t.Kind = KindWrite
		if p.Op == "open" && p.Flags&oAccmode == 0 && p.Flags&(oCreat|oTrunc) == 0 {
			t.Kind = KindRead
		}
	case record.KindExec:
		var p record.ExecPayload
		if err := e.DecodePayload(&p); err != nil {
			return t, fmt.Errorf("exec event at seq %d: %w", e.Seq, err)
		}
		t.Kind, t.Op, t.Path, t.Argv = KindExec, "exec", p.Path, p.Argv
	case record.KindNet:
		var p record.NetPayload
		if err := e.DecodePayload(&p); err != nil {
			return t, fmt.Errorf("net event at seq %d: %w", e.Seq, err)
		}
		if p.Op == "http_request" {
			return t, fmt.Errorf("%w: an HTTP request rule (net.http) is not made from an event yet", ErrUnsupported)
		}
		t.Kind, t.Op, t.Dest = KindNet, "connect", netDest(p)
	case record.KindRefused:
		var p record.RefusedPayload
		if err := e.DecodePayload(&p); err != nil {
			return t, fmt.Errorf("refused event at seq %d: %w", e.Seq, err)
		}
		t.Refused, t.Op = true, p.Op
		if t.Rule == "" {
			t.Rule = p.Rule
		}
		switch e.Reason {
		case record.ReasonReadDenied:
			t.Kind, t.Path = KindRead, p.Target
		case record.ReasonWriteOutsideContract, record.ReasonDeleteOutsideContract, record.ReasonRenameOutsideContract,
			record.ReasonMkdirOutsideContract:
			t.Kind, t.Path = KindWrite, p.Target
		case record.ReasonExecNotAllowed:
			t.Kind, t.Path = KindExec, p.Target
		case record.ReasonNetNotAllowed:
			t.Kind, t.Dest = KindNet, p.Target
		case record.ReasonAskDenied, record.ReasonAskTimeout, record.ReasonAskUnavailable, record.ReasonAskUnreadable:
			if err := askedTarget(&t, p); err != nil {
				return t, fmt.Errorf("%w: %s %s refusal: %v", ErrUnsupported, article(string(e.Reason)), e.Reason, err)
			}
		default:
			return t, fmt.Errorf("%w: %s %s refusal", ErrUnsupported, article(string(e.Reason)), e.Reason)
		}
	default:
		return t, fmt.Errorf("%w: %s %s line", ErrUnsupported, article(string(e.Kind)), e.Kind)
	}
	if t.Kind != KindNet && (t.Path == "" || !path.IsAbs(t.Path)) {
		return t, fmt.Errorf("%w: the event names no absolute path", ErrUnsupported)
	}
	if t.Kind == KindNet {
		if t.Dest == "" {
			return t, fmt.Errorf("%w: the event names no destination", ErrUnsupported)
		}
		t.Dest = unzoned(t.Dest)
	}
	return t, nil
}

// askedTarget reads the target of a refusal an ask ended in (a person said no, no answer came in time, or the ask
// could not be made): the rule's family says what was asked about (fs.ask_read a read, fs.ask a write, net.ask a
// connection), and a network operation says so where the rule is not an ask entry's (a gate's).
func askedTarget(t *Target, p record.RefusedPayload) error {
	key, entry, _ := ruleEntry(t.Rule)
	switch {
	case key == "fs.ask_read":
		t.Kind, t.Path = KindRead, p.Target
	case key == "fs.ask":
		t.Kind, t.Path = KindWrite, p.Target
	case p.Op == "http_request":
		return errors.New("an HTTP request rule (net.http) is not made from an event yet")
	case key == "net.ask":
		t.Kind, t.Dest = KindNet, p.Target
		if t.Dest == "" {
			t.Dest = entry
		}
	case p.Op == "connect" || p.Op == "first_write" || p.Op == "send":
		t.Kind, t.Dest = KindNet, p.Target
	default:
		return fmt.Errorf("its rule %q names no ask list a rule can change", t.Rule)
	}
	return nil
}

// article is "a" or "an" for the word w.
func article(w string) string {
	if w != "" && strings.ContainsRune("aeiouAEIOU", rune(w[0])) {
		return "an"
	}
	return "a"
}

// netDest is the destination as a net.allow entry spells it: the host name the run asked for when the record has
// one, with the port, else the address it connected to. A literal IPv6 entry's host is its address, and the port pasted
// after that gives 2001:db8::1:443, another address and no port, so its dst, bracketed, is the spelling.
func netDest(p record.NetPayload) string {
	if strings.HasPrefix(p.Dst, "unix:") || p.Host == "" || strings.Contains(p.Host, ":") {
		return p.Dst
	}
	i := strings.LastIndexByte(p.Dst, ':')
	if i < 0 {
		return p.Dst
	}
	return p.Host + p.Dst[i:]
}

// unzoned is dest without the scope id a line keeps from its connect, which every connect to a link-local address has
// to pass: a net entry cannot hold one, since no tier matches on it (agent.ParseEndpoint), and a live block never does.
func unzoned(dest string) string {
	ap, err := netip.ParseAddrPort(dest)
	if err != nil || ap.Addr().Zone() == "" {
		return dest
	}
	return netip.AddrPortFrom(ap.Addr().WithZone(""), ap.Port()).String()
}

// Actions are the actions the contract grammar has for k, in the order a page offers them. exec.ask is reserved and
// refuses every match (ADR 0048 (5)), so an exec offers block and allow only.
func Actions(k Kind) []Action {
	if k == KindExec {
		return []Action{Block, Allow}
	}
	return []Action{Block, Ask, Allow}
}

// ruleEntry splits an event's rule into its contract key and the entry it names: "fs.deny_read[../s/]" is
// ("fs.deny_read", "../s/"), "exec[sh]" ("exec.allow", "sh"), "net[h:443]" ("net.allow", "h:443").
func ruleEntry(rule string) (key, entry string, ok bool) {
	i := strings.IndexByte(rule, '[')
	if i < 0 || !strings.HasSuffix(rule, "]") {
		return "", "", false
	}
	key, entry = rule[:i], rule[i+1:len(rule)-1]
	switch key {
	case "exec":
		key = "exec.allow"
	case "net":
		key = "net.allow"
	}
	return key, entry, true
}
