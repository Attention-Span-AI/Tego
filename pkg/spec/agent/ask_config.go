// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"gopkg.in/yaml.v3"
)

type AskHold string

const (
	AskHoldConnect    AskHold = "connect"
	AskHoldFirstWrite AskHold = "first_write"
	AskHoldRequest    AskHold = "request"
)

// AskOnTimeout is what an ask that times out leaves behind (ask.on_timeout, SEMANTICS §6).
type AskOnTimeout string

const (
	// AskOnTimeoutRefuse refuses the timed-out operation once: a retry is held again for the whole timeout. The default.
	AskOnTimeoutRefuse AskOnTimeout = "refuse"
	// AskOnTimeoutRefuseAlways refuses it and leaves a standing refusal for the same operation, rule and exact target
	// for the rest of the run, as `tego deny --always` would: a retry is refused at once, citing the timed-out ask.
	AskOnTimeoutRefuseAlways AskOnTimeout = "refuse_always"
)

// AskConfig is the compiled approval configuration. Administrative replies must
// come from an authenticated process outside the governed run.
type AskConfig struct {
	Hold       AskHold  `yaml:"hold,omitempty"`
	Timeout    Duration `yaml:"timeout,omitempty"`
	MaxPending int      `yaml:"max_pending,omitempty"`
	// OnTimeout is ask.on_timeout; CompileAskConfig always sets it (AskOnTimeoutRefuse when the key is absent).
	OnTimeout AskOnTimeout `yaml:"on_timeout,omitempty"`
}

func CompileAskConfig(c *Contract) (*AskConfig, error) {
	if c == nil {
		return nil, nil
	}
	hasScopes := c.FS != nil && (len(c.FS.Ask) > 0 || len(c.FS.AskRead) > 0) || c.Net != nil && len(c.Net.Ask) > 0 || gateRequiresBroker(c)
	if c.Ask.Kind == 0 && !hasScopes {
		return nil, nil
	}
	p := &AskConfig{Hold: AskHoldConnect, MaxPending: 64, OnTimeout: AskOnTimeoutRefuse}
	n := &c.Ask
	for depth := 0; n.Kind == yaml.DocumentNode || n.Kind == yaml.AliasNode; depth++ {
		if depth >= 16 {
			return nil, fmt.Errorf("ask: alias nesting exceeds 16")
		}
		switch {
		case n.Kind == yaml.AliasNode:
			n = n.Alias
		case len(n.Content) == 1:
			n = n.Content[0]
		default:
			return nil, fmt.Errorf("ask must be a mapping")
		}
		if n == nil {
			return nil, fmt.Errorf("ask must be a mapping")
		}
	}
	if n.Kind != 0 && n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("ask must be a mapping")
	}
	if len(n.Content)%2 != 0 {
		return nil, fmt.Errorf("ask has malformed mapping")
	}
	if n.Kind == yaml.MappingNode && len(n.Content) == 0 && !hasScopes {
		return nil, nil
	}
	seen := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, value := n.Content[i], n.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || seen[key.Value] {
			return nil, fmt.Errorf("ask: unknown or duplicate field %q", key.Value)
		}
		seen[key.Value] = true
		for depth := 0; value.Kind == yaml.AliasNode; depth++ {
			if depth >= 16 || value.Alias == nil {
				return nil, fmt.Errorf("ask.%s has invalid alias", key.Value)
			}
			value = value.Alias
		}
		if value.Kind != yaml.ScalarNode || value.ShortTag() == "!!null" {
			return nil, fmt.Errorf("ask.%s requires a scalar value", key.Value)
		}
		switch key.Value {
		case "hold":
			if value.ShortTag() != "!!str" {
				return nil, fmt.Errorf("ask.hold requires a string")
			}
			p.Hold = AskHold(value.Value)
		case "timeout":
			if value.ShortTag() != "!!str" {
				return nil, fmt.Errorf("ask.timeout requires a duration string")
			}
			d, e := ParseDuration(value.Value)
			if e != nil || d <= 0 || time.Duration(d) > time.Hour {
				return nil, fmt.Errorf("ask.timeout must be positive and at most 1h")
			}
			p.Timeout = d
		case "max_pending":
			if value.ShortTag() != "!!int" || !intRE.MatchString(value.Value) {
				return nil, fmt.Errorf("ask.max_pending requires an integer")
			}
			v, e := strconv.Atoi(value.Value)
			if e != nil || v < 1 || v > 64 {
				return nil, fmt.Errorf("ask.max_pending must be 1..64")
			}
			p.MaxPending = v
		case "on_timeout":
			if value.ShortTag() != "!!str" {
				return nil, fmt.Errorf("ask.on_timeout requires a string")
			}
			p.OnTimeout = AskOnTimeout(value.Value)
		default:
			return nil, fmt.Errorf("ask: unknown field %q", key.Value)
		}
	}
	switch p.Hold {
	case AskHoldConnect, AskHoldFirstWrite, AskHoldRequest:
	default:
		return nil, fmt.Errorf("ask.hold must be connect, first_write or request")
	}
	switch p.OnTimeout {
	case AskOnTimeoutRefuse, AskOnTimeoutRefuseAlways:
	default:
		return nil, fmt.Errorf("ask.on_timeout must be refuse or refuse_always")
	}
	if p.Timeout == 0 {
		p.Timeout = Duration(5 * time.Minute)
		if p.Hold == AskHoldRequest {
			p.Timeout = Duration(4 * time.Minute)
		}
	}
	if p.Timeout < 0 || time.Duration(p.Timeout) > time.Hour || p.MaxPending < 1 || p.MaxPending > 64 {
		return nil, fmt.Errorf("ask timeout must be positive and at most 1h; max_pending must be 1..64")
	}
	return p, nil
}

func checkAskTimeout(v string) (string, string) {
	d, e := ParseDuration(v)
	if e != nil || d <= 0 || time.Duration(d) > time.Hour {
		return "ask.timeout must be positive and at most 1h", "write a duration such as 5m"
	}
	return "", ""
}

func checkAskPath(v string) (string, string) {
	if len(v) > 4096 || strings.ContainsAny(v, "*?[") {
		return "fs.ask requires literal paths of at most 4096 bytes", "list a literal file or directory"
	}
	return checkPath(v)
}

// checkAskReadPath is fs.ask_read's entry: a literal path of at most 4096 bytes, as fs.ask's. A glob is refused
// rather than expanded as deny_read's is: a held read names one file a person decides on, and the files a glob
// would match later are not in the ruleset Landlock was given (SEMANTICS §2).
func checkAskReadPath(v string) (string, string) {
	if len(v) > 4096 || strings.ContainsAny(v, "*?[") {
		return "fs.ask_read requires literal paths of at most 4096 bytes", "list a literal file or directory"
	}
	return checkPath(v)
}

// checkDenyWritePath is fs.deny_write's entry (ADR 0071): a literal path. A glob character is refused rather than
// expanded: the tiers key the entry on the inode it names, and a file a glob would match later has none at compile.
func checkDenyWritePath(v string) (string, string) {
	if strings.ContainsAny(v, "*?[") {
		return "fs.deny_write takes literal paths: a glob character (*, ?, [) is not a pattern here",
			"name the file, or the directory that holds the files (an entry covers everything beneath it)"
	}
	return checkPath(v)
}

func checkAskEndpoint(v string) (string, string) {
	e, eErr := ParseEndpoint(v)
	if eErr != nil {
		return eErr.Error(), "write tcp://host:port"
	}
	if e.Kind == EndpointUnix {
		return "", "" // a socket path or abstract name, held at the connect (askSyscallHeld)
	}
	// tcp://, udp:// and a bare host:port, which names both (SEMANTICS §5), each with the one port an
	// approval names: port 0 is an ICMP destination, which no ask holds.
	if e.Port <= 0 {
		return "net.ask destinations need a port in 1..65535", "write host:port, tcp://host:port, udp://host:port or unix:/path/to.sock"
	}
	return "", ""
}

// askSyscallHeld names the first net.ask scope that is held at the syscall alone, "" when none is: a unix: scope, whose
// connect is relayed as the task once approved (supervisor R11), and a udp:// or bare host:port scope, whose datagram
// or UDP connect is held and relayed (supervisor R13d). Neither carries a TCP byte stream for first_write to hold nor
// an HTTP request for request to inspect, so those holds refuse a contract that lists one.
func askSyscallHeld(c *Contract) string {
	if c.Net == nil {
		return ""
	}
	for _, raw := range c.Net.Ask {
		e, err := ParseEndpoint(raw)
		if err != nil {
			continue
		}
		switch {
		case e.Kind == EndpointUnix:
			return "unix: scopes are"
		case e.Proto == ProtoUDP:
			return "udp:// scopes are"
		case e.Proto == ProtoInet:
			return "bare host:port scopes name UDP too, which is"
		}
	}
	return ""
}

func validateAsk(ds *diags, c *Contract, at func(string) Pos) {
	if c.FS != nil {
		if len(c.FS.Ask) > 256 {
			ds.errorf(at("fs.ask"), CodeSchema, "fs.ask exceeds 256 scopes")
		}
		for i, p := range c.FS.Ask {
			if msg, _ := checkAskPath(p); msg != "" {
				ds.errorf(at("fs.ask."+strconv.Itoa(i)), CodeSchema, "%s", msg)
			}
		}
		if len(c.FS.AskRead) > 256 {
			ds.errorf(at("fs.ask_read"), CodeSchema, "fs.ask_read exceeds 256 entries")
		}
		for i, p := range c.FS.AskRead {
			if msg, _ := checkAskReadPath(p); msg != "" {
				ds.errorf(at("fs.ask_read."+strconv.Itoa(i)), CodeSchema, "%s", msg)
			}
		}
	}
	if c.Net != nil {
		if len(c.Net.Ask) > 256 {
			ds.errorf(at("net.ask"), CodeSchema, "net.ask exceeds 256 scopes")
		}
		for i, p := range c.Net.Ask {
			if msg, _ := checkAskEndpoint(p); msg != "" {
				ds.errorf(at("net.ask."+strconv.Itoa(i)), CodeSchema, "%s", msg)
			}
		}
	}
	p, e := CompileAskConfig(c)
	if e != nil {
		ds.errorf(at("ask"), CodeSchema, "%v", e)
		return
	}
	if p == nil {
		return
	}
	if c.IOUring || c.Setuid {
		ds.errorf(at("ask"), CodeSchema, "ask requires io_uring and setuid disabled")
	}
	if backend.Tier(c.Tier) == backend.TierObserve {
		ds.errorf(at("ask"), CodeSchema, "ask requires an enforcing tier")
	}
	if held := askSyscallHeld(c); p.Hold != AskHoldConnect && held != "" {
		ds.errorf(at("ask.hold"), CodeSchema, "net.ask %s held at the syscall (ask.hold: connect); ask.hold %s holds TCP bytes or HTTP requests", held, p.Hold).
			fix("write tcp://host:port for a TCP scope, or use ask.hold: connect")
	}
	if p.Hold == AskHoldRequest && c.Net != nil && len(c.Net.Ask) > 0 {
		if c.Capture != CaptureForwarder || len(c.Models) == 0 || len(c.Net.HTTP) == 0 {
			ds.errorf(at("ask.hold"), CodeSchema, "ask request holds require explicit capture: forwarder, fixed models and net.http policy")
		}
		if c.Net.Proxy != nil && (len(c.Net.Proxy.Connect) > 0 || len(c.Net.Proxy.WebSocket) > 0) {
			ds.errorf(at("ask.hold"), CodeSchema, "ask request holds do not inspect CONNECT tunnels or WebSocket frames")
		}
		for _, raw := range c.Net.Ask {
			e, err := ParseEndpoint(raw)
			if err != nil {
				continue
			}
			found := false
			for _, m := range c.Models {
				port := m.Port
				if port == 0 {
					port = 443
				}
				if e.Kind == EndpointHost && CanonicalHost(e.Host) == CanonicalHost(m.Host) && e.Port == port {
					found = true
					break
				}
			}
			if !found {
				ds.errorf(at("net.ask"), CodeSchema, "ask request destination %q must exactly name a declared model authority", raw)
			}
		}
	}
}

func (k *compiler) askConfig() {
	validateAsk(&k.ds, k.c, k.pos)
	p, e := CompileAskConfig(k.c)
	if e != nil || p == nil {
		return
	}
	if k.rt.Tier == backend.TierObserve {
		k.ds.errorf(k.pos("ask"), CodeUnenforced, "ask requires an enforcing tier")
		return
	}
	if p.Hold == AskHoldRequest && k.c.Net != nil && len(k.c.Net.Ask) > 0 && k.rt.Capture != CaptureForwarder {
		k.ds.errorf(k.pos("ask"), CodeUnenforced, "ask request holds require forwarder capture after machine ceilings")
		return
	}
	k.rt.AskConfig = p
}
