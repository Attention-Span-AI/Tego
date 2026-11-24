// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bufio"
	"context"
	"crypto/sha256"
	"io"
	"path/filepath"

	"github.com/attention-span-ai/tego/internal/scan/catalog"
	"github.com/attention-span-ai/tego/internal/scan/result"
)

type mcpServer struct {
	Name, Program, Transport string
	Scope                    string
	Arguments                int
}
type mcpObservation struct {
	RuleID, Path, Client, Scope string
	Server                      mcpServer
}
type mcpSnapshot struct {
	Items   []mcpObservation
	Sources []processSource
}

// Only the command's closed catalog id survives its scalar. Every argument,
// URL, header, environment and unknown value is validated and discarded.
func mcpProgram(s string) string {
	for _, r := range catalog.Rows() {
		for _, p := range r.Programs {
			if s == p || filepath.IsAbs(s) && filepath.Base(s) == p {
				return r.ID
			}
		}
	}
	return ""
}
func serverName(s string) bool { return len(s) > 0 && len(s) <= 256 && plainPath("/"+s) }

func parseMCPJSON(ctx context.Context, r io.Reader) ([]mcpServer, error) {
	return parseMCPJSONForProject(ctx, r, "")
}
func parseMCPJSONForProject(ctx context.Context, r io.Reader, cwd string) ([]mcpServer, error) {
	s := manifestStream{ctx: ctx, r: bufio.NewReaderSize(io.LimitReader(r, manifestBytes+1), 4096)}
	out := []mcpServer{}
	// Modes: root, projects, selected local project, servers, server. Ignored
	// keys and subtrees consume only bounded bytes, depth and parsing time.
	var object func(int, int, *mcpServer) error
	object = func(depth, mode int, server *mcpServer) error {
		if depth > 32 {
			return errLimit
		}
		if e := s.token(); e != nil {
			return e
		}
		if e := s.want('{'); e != nil {
			return errSyntax
		}
		seen := map[[32]byte]bool{}
		commandSeen, urlSeen := false, false
		entries := 0
		if e := s.space(); e != nil {
			return e
		}
		b, e := s.peek()
		if e != nil {
			return e
		}
		if b == '}' {
			return s.want('}')
		}
		for {
			var key string
			switch mode {
			case 1:
				if cwd == "" {
					key, e = s.quotedMatch("mcpServers")
				} else {
					key, e = s.quotedMatch("mcpServers", "projects")
				}
			case 2:
				key, e = s.quotedMatch(cwd)
			case 3:
				key, e = s.quotedMatch("mcpServers")
			case 4:
				key, e = s.quoted(true)
			case 5:
				key, e = s.quotedMatch("command", "url", "httpUrl", "type", "args")
			}
			if e != nil {
				return e
			}
			if key != "" || mode == 4 {
				if e = s.token(); e != nil {
					return e
				}
				h := sha256.Sum256([]byte(key))
				if seen[h] {
					return errSyntax
				}
				seen[h] = true
				entries++
				if entries > 128 {
					return errLimit
				}
			}
			if e = s.space(); e != nil {
				return e
			}
			if e = s.want(':'); e != nil {
				return e
			}
			if e = s.space(); e != nil {
				return e
			}
			if mode == 5 && (key == "command" || key == "url" || key == "httpUrl" || key == "type" || key == "args") {
				if e = s.token(); e != nil {
					return e
				}
			}
			next := 0
			switch {
			case (mode == 1 || mode == 3) && key == "mcpServers":
				next = 4
			case cwd != "" && mode == 1 && key == "projects":
				next = 2
			case mode == 2 && key == cwd:
				next = 3
			case mode == 4:
				next = 5
			}
			switch {
			case next != 0:
				b, e = s.peek()
				if e != nil {
					return e
				}
				if b != '{' {
					return errSyntax
				}
				child := mcpServer{Name: key, Transport: "unknown"}
				if next == 5 && (!serverName(key) || len(out) >= 128) {
					return errLimit
				}
				start := len(out)
				if e = object(depth+1, next, &child); e != nil {
					return e
				}
				if next == 3 {
					for i := start; i < len(out); i++ {
						out[i].Scope = "local"
					}
				}
				if next == 5 {
					if child.Transport == "unknown" && child.Program != "" {
						child.Transport = "stdio"
					}
					if child.Transport != "stdio" {
						child.Program = ""
					}
					out = append(out, child)
				}
			case mode == 5 && key == "command":
				v, e := s.quoted(true)
				if e != nil {
					return e
				}
				commandSeen = true
				server.Program = mcpProgram(v)
				if server.Transport == "unknown" {
					server.Transport = "stdio"
				}
			case mode == 5 && (key == "url" || key == "httpUrl"):
				b, e = s.peek()
				if e != nil || b != '"' {
					return errSyntax
				}
				if _, e = s.quoted(false); e != nil {
					return e
				}
				urlSeen = true
				if server.Transport == "unknown" {
					server.Transport = "http"
				}
			case mode == 5 && key == "type":
				v, e := s.quoted(true)
				if e != nil {
					return e
				}
				switch v {
				case "stdio", "http", "sse":
					server.Transport = v
				default:
					return errUnsupported
				}
			case mode == 5 && key == "args":
				if e = s.want('['); e != nil {
					return errSyntax
				}
				if e = s.space(); e != nil {
					return e
				}
				b, e = s.peek()
				if e != nil {
					return e
				}
				if b == ']' {
					e = s.want(']')
				} else {
					for {
						if e = s.token(); e != nil {
							return e
						}
						if _, e = s.quoted(false); e != nil {
							return e
						}
						server.Arguments++
						if server.Arguments > 128 {
							return errLimit
						}
						if e = s.space(); e != nil {
							return e
						}
						b, e = s.byte()
						if e != nil {
							return e
						}
						if b == ']' {
							break
						}
						if b != ',' {
							return errSyntax
						}
						if e = s.space(); e != nil {
							return e
						}
					}
				}
				if e != nil {
					return e
				}
			default:
				if e = s.skipJSON(depth + 1); e != nil {
					return e
				}
			}
			if e = s.space(); e != nil {
				return e
			}
			b, e = s.byte()
			if e != nil {
				return e
			}
			if b == '}' {
				if mode == 5 && (commandSeen && urlSeen || commandSeen && server.Transport != "stdio" || urlSeen && server.Transport == "stdio") {
					return errUnsupported
				}
				return nil
			}
			if b != ',' {
				return errSyntax
			}
			if e = s.space(); e != nil {
				return e
			}
		}
	}
	if e := s.space(); e != nil {
		return nil, e
	}
	if e := object(0, 1, nil); e != nil {
		return nil, e
	}
	if e := s.space(); e != nil {
		return nil, e
	}
	if _, e := s.peek(); e != io.EOF {
		return nil, errSyntax
	}
	return out, nil
}
func collectMCP(ctx context.Context, home, cwd string, uid uint32, budget *contentBudget) mcpSnapshot {
	out := mcpSnapshot{}
	seenPaths := map[string]bool{}
	for _, src := range catalog.SettingsFiles() {
		base := home
		if src.Scope == "project" {
			base = cwd
		}
		path := filepath.Join(base, src.Path)
		if seenPaths[path] {
			continue
		}
		seenPaths[path] = true
		root, _, e := metadataPath(ctx, base, false)
		var servers []mcpServer
		if e == nil {
			e = readContent(ctx, root, src.Path, uid, budget, func(r io.Reader) error {
				var x error
				if src.Format == "json" {
					if src.Client == "claude" && src.Path == ".claude.json" {
						servers, x = parseMCPJSONForProject(ctx, r, cwd)
					} else {
						servers, x = parseMCPJSON(ctx, r)
					}
				} else {
					servers, x = parseMCPTOML(ctx, r)
				}
				return x
			})
			_ = root.Close()
		}
		out.Sources = append(out.Sources, projectSource(path, e))
		if e == nil {
			for _, s := range servers {
				out.Items = append(out.Items, mcpObservation{src.ID, path, src.Client, src.Scope, s})
			}
		}
	}
	return out
}

func mcpDetail(p mcpObservation) result.Config {
	program := result.Path(p.Server.Program)
	if p.Server.Scope != "" {
		p.Scope = p.Server.Scope
	}
	return result.Config{Path: result.Path(p.Path), Client: p.Client, Scope: p.Scope, Transport: p.Server.Transport, Program: program, Server: p.Server.Name, Arguments: p.Server.Arguments}
}
