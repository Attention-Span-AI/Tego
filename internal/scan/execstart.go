// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/scan/catalog"
	"github.com/attention-span-ai/tego/internal/watch/sig"
)

type unitExec struct {
	words      int
	Program    string
	Arguments  int
	Specifiers bool
	Path       string
}
type unitDocument struct {
	Exec        []unitExec
	Reset       bool
	Trigger     string
	ServiceType *string
}

// parseExecStart implements a bounded subset of systemd's ExecStart word parser,
// without a shell or any expansion. At most one word is held transiently for
// catalog matching; values after secret-like flags are not materialized.
func parseExecStart(raw []byte) (unitExec, error) {
	return parseConfiguredCommand(raw, false)
}

// parseConfiguredCommand shares catalog matching and value dropping between unit
// and cron commands. Cron uses shell lexical rules without evaluating a shell.
func parseConfiguredCommand(raw []byte, cron bool) (unitExec, error) {
	out := unitExec{}
	if len(raw) > unitLineBytes {
		return out, errLimit
	}
	if !utf8.Valid(raw) {
		return out, errSyntax
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return out, nil
	}
	prefixes := map[byte]int{}
	at := false
	words := 0
	var nodeRows []catalog.Row
	secretNext := false
	bestRule := 1000
	for len(raw) > 0 {
		raw = bytes.TrimLeft(raw, " \t\r")
		if len(raw) == 0 {
			break
		}
		if cron && raw[0] == '#' {
			break
		}
		words++
		maxWords := unitArgumentLimit + 1
		if at {
			maxWords++
		}
		if words > maxWords {
			return unitExec{}, errLimit
		}
		quote := byte(0)
		keep := words == 1 || len(nodeRows) > 0 && !secretNext && !(at && words == 2)
		var program strings.Builder
		dollar, specifiers := false, false
		for len(raw) > 0 {
			b := raw[0]
			raw = raw[1:]
			if quote != 0 && b == quote {
				quote = 0
				continue
			}
			if quote == 0 && (b == '\'' || b == '"') {
				// config_parse_exec uses EXTRACT_UNQUOTE, including midword quotes.
				quote = b
				continue
			}
			if quote == 0 && (b == ' ' || b == '\t' || b == '\r') {
				break
			}
			if cron && (quote != '\'' && (b == '$' || b == '`') || quote == 0 && strings.ContainsRune(";&|<>(){}~*?[", rune(b))) {
				return unitExec{}, errUnresolved
			}
			if b < 0x20 || b == 0x7f || !cron && quote == 0 && b == ';' {
				return unitExec{}, errUnsupported
			}
			r := rune(b)
			if b >= utf8.RuneSelf {
				var rawRune [utf8.UTFMax]byte
				rawRune[0] = b
				n := copy(rawRune[1:], raw)
				var size int
				r, size = utf8.DecodeRune(rawRune[:n+1])
				raw = raw[size-1:]
			}
			if b == '\\' && (!cron || quote != '\'') {
				if len(raw) == 0 {
					return unitExec{}, errSyntax
				}
				b = raw[0]
				if cron {
					// In double quotes shell backslash only quotes these bytes.
					if quote == '"' && !strings.ContainsRune("$`\"\\", rune(b)) {
						if keep {
							program.WriteByte('\\')
						}
						continue
					}
					r, n := utf8.DecodeRune(raw)
					raw = raw[n:]
					if keep {
						program.WriteRune(r)
					}
					continue
				}
				raw = raw[1:]
				r = rune(b)
				switch b {
				case 'a':
					r = '\a'
				case 'b':
					r = '\b'
				case 'f':
					r = '\f'
				case 'n':
					r = '\n'
				case 'r':
					r = '\r'
				case 't':
					r = '\t'
				case 'v':
					r = '\v'
				case 's':
					r = ' '
				case '\\', '"', '\'', ';':
				case 'x', 'u', 'U':
					n := 2
					if b == 'u' {
						n = 4
					}
					if b == 'U' {
						n = 8
					}
					if len(raw) < n {
						return unitExec{}, errSyntax
					}
					v, e := strconv.ParseUint(string(raw[:n]), 16, 32)
					if e != nil || v == 0 || v > utf8.MaxRune || v >= 0xd800 && v <= 0xdfff {
						return unitExec{}, errSyntax
					}
					r = rune(v)
					raw = raw[n:]
				default:
					if b < '0' || b > '7' || len(raw) < 2 {
						return unitExec{}, errUnsupported
					}
					v, e := strconv.ParseUint(string(append([]byte{b}, raw[:2]...)), 8, 8)
					if e != nil || v == 0 {
						return unitExec{}, errSyntax
					}
					r = rune(v)
					raw = raw[2:]
				}
			}
			if !cron && r == '%' {
				out.Specifiers = true
				specifiers = true
			}
			// Inspect expansions even in words whose values are discarded. Holding
			// the value is unnecessary, including after secret-like flags and @ argv0.
			if !cron && dollar && (r == '{' || r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') && (words == 1 || prefixes[':'] == 0) {
				return unitExec{}, errUnresolved
			}
			if !cron && dollar && r == '$' {
				dollar = false
			} else {
				dollar = !cron && r == '$'
			}
			if keep {
				program.WriteRune(r)
			}
		}
		if quote != 0 {
			return unitExec{}, errSyntax
		}
		if words == 1 {
			v := program.String()
			for !cron && len(v) > 0 && bytes.ContainsRune([]byte("-@:+!|"), rune(v[0])) {
				b := v[0]
				if b == '|' {
					return unitExec{}, errUnresolved
				}
				prefixes[b]++
				if prefixes[b] > 1 && !(b == '!' && prefixes[b] == 2) {
					return unitExec{}, errSyntax
				}
				if b == '@' {
					at = true
				}
				v = v[1:]
			}
			if prefixes['+'] > 0 && prefixes['!'] > 0 {
				return unitExec{}, errSyntax
			}
			if !serverName(v) {
				return unitExec{}, errSyntax
			}
			if strings.Contains(v, "%") {
				return unitExec{}, errUnresolved
			}
			if cron && (strings.ContainsAny(v, "=*?[") || v == "!") {
				return unitExec{}, errUnresolved
			}
			out.Program = mcpProgram(v)
			base := v
			if i := strings.LastIndexByte(base, '/'); i >= 0 {
				base = base[i+1:]
			}
			if base == "node" {
				nodeRows = catalog.Rows()
			}
			if cron {
				switch base {
				case "cd", "if", "for", "while", "until", "case", "exec", "command", "eval", ".", "source", "time", "then", "do", "select", "function", "ash", "csh", "tcsh", "ksh", "fish", "busybox", "ion", "nu", "xonsh", "pwsh", "powershell":
					return unitExec{}, errUnresolved
				}
			}
			switch base {
			case "sh", "bash", "dash", "zsh", "env", "tego", "nohup", "timeout", "nice", "setsid", "stdbuf", "npx", "bunx", "uvx", "tmux", "screen":
				return unitExec{}, errUnresolved
			}
			if out.Program == "" && strings.Contains(v, "/") && !strings.HasPrefix(v, "/") {
				return unitExec{}, errUnsupported
			}
		} else if len(nodeRows) > 0 && !(at && words == 2) {
			if secretNext {
				if specifiers && out.Program == "" {
					return unitExec{}, errUnresolved
				}
				secretNext = false
				continue
			}
			token := program.String()
			secretNext = secretArgumentNext(token)
			if strings.HasPrefix(token, "-") {
				if specifiers && out.Program == "" {
					return unitExec{}, errUnresolved
				}
				continue
			}
			// Catalog wrapper patterns have exactly one argument token. Match it
			// while scanning and retain only the winning id, never a token sequence.
			matched := false
			for n, row := range nodeRows {
				if len(row.Rule.Argv) == 2 && row.Rule.Match(sig.Facts{Exe: "node", Argv: []string{"node", token}}) {
					matched = true
					if n < bestRule {
						out.Program = row.ID
						bestRule = n
					}
				}
			}
			if specifiers && !matched && out.Program == "" {
				return unitExec{}, errUnresolved
			}
		}
	}
	if words == 0 || at && words < 2 {
		return unitExec{}, errSyntax
	}
	out.words = words
	out.Arguments = words - 1
	if at {
		out.Arguments--
	}
	return out, nil
}

func secretArgumentNext(token string) bool {
	name, _, attached := strings.Cut(token, "=")
	if attached || !strings.HasPrefix(name, "-") {
		return false
	}
	name = strings.ToLower(name)
	for _, word := range []string{"token", "secret", "password", "passwd", "credential", "authorization", "header", "key"} {
		if strings.Contains(name, word) {
			return true
		}
	}
	return false
}

func parseUnit(ctx context.Context, r io.Reader) (unitDocument, error) {
	out := unitDocument{Exec: []unitExec{}}
	s := bufio.NewScanner(io.LimitReader(r, manifestBytes+1))
	s.Buffer(make([]byte, unitLineBytes), unitLineBytes+1)
	section := ""
	total, lines, tokens := 0, 0, 0
	var logical []byte
	applyLine := func() error {
		v := bytes.TrimSpace(logical)
		if len(v) == 0 {
			return nil
		}
		if v[0] == '[' {
			if v[len(v)-1] != ']' {
				return errSyntax
			}
			section = string(v[1 : len(v)-1])
		} else {
			k, value, ok := bytes.Cut(v, []byte{'='})
			if !ok {
				return errSyntax
			}
			k = bytes.TrimSpace(k)
			value = bytes.TrimSpace(value)
			if section == "Service" && bytes.Equal(k, []byte("ExecStart")) {
				if len(value) == 0 {
					out.Exec = []unitExec{}
					out.Reset = true
				} else {
					x, e := parseExecStart(value)
					if e != nil {
						return e
					}
					tokens += x.words
					if tokens+lines > unitTokenLimit {
						return errLimit
					}
					out.Exec = append(out.Exec, x)
					if len(out.Exec) > unitExecLimit {
						return errLimit
					}
				}
			}
			if section == "Service" && bytes.Equal(k, []byte("Type")) {
				v := string(value)
				switch v {
				case "", "simple", "exec", "forking", "oneshot", "dbus", "notify", "notify-reload", "idle":
					out.ServiceType = &v
				default:
					return errUnsupported
				}
			}

			if section == "Timer" && bytes.Equal(k, []byte("Unit")) {
				if !configuredUnitName(string(value)) || !bytes.HasSuffix(value, []byte(".service")) {
					return errUnsupported
				}
				out.Trigger = string(value)
			}
		}
		return nil
	}
	for s.Scan() {
		if e := ctx.Err(); e != nil {
			return unitDocument{}, e
		}
		line := s.Bytes()
		total += len(line) + 1
		line = bytes.TrimSuffix(line, []byte{'\r'})
		lines++
		if total > manifestBytes {
			return unitDocument{}, errSize
		}
		if lines+tokens > unitTokenLimit {
			return unitDocument{}, errLimit
		}
		for _, b := range line {
			if b < 0x20 && b != '\t' && b != '\r' {
				return unitDocument{}, errSyntax
			}
		}
		if !utf8.Valid(line) {
			return unitDocument{}, errSyntax
		}
		trim := bytes.TrimSpace(line)
		if len(trim) > 0 && (trim[0] == '#' || trim[0] == ';') {
			continue
		}
		if len(logical)+len(line) > unitLineBytes {
			return unitDocument{}, errLimit
		}
		logical = append(logical, line...)
		backslashes := 0
		for i := len(line) - 1; i >= 0 && line[i] == '\\'; i-- {
			backslashes++
		}
		if backslashes%2 != 0 {
			// conf-parser.c replaces only the final unescaped backslash with space.
			logical[len(logical)-1] = ' '
			continue
		}
		if e := applyLine(); e != nil {
			return unitDocument{}, e
		}
		// The input buffer and this one logical line are the only places argument
		// and Environment= bytes live; they never enter a returned structure.
		clear(logical)
		logical = logical[:0]
	}
	if e := s.Err(); e != nil {
		return unitDocument{}, errSize
	}
	if len(logical) > 0 {
		if e := applyLine(); e != nil {
			return unitDocument{}, e
		}
		clear(logical)
	}
	return out, nil
}
