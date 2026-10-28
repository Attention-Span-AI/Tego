// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// SeenName is the tools-seen file: <ledger_root>/<run>/mcp-seen.json, {server: [tool names]}.
const SeenName = "mcp-seen.json"

// Bounds of the seen file.
const (
	// MaxSeenPerServer bounds the names kept for one server: a server that lists more is cut, never grown past it.
	MaxSeenPerServer = 512
	// MaxSeenServers bounds the servers kept.
	MaxSeenServers = 64
	maxSeenBytes   = 4 << 20
)

// Seen is the tools each server offered, by server name, each list sorted and unique.
type Seen map[string][]string

// Merge adds tools to server's list, keeping only valid names, at most MaxSeenPerServer; it reports whether the list
// grew. An invalid server name, or a new server past MaxSeenServers, adds nothing.
func (s Seen) Merge(server string, tools []string) bool {
	if !ValidName(server) {
		return false
	}
	have, ok := s[server]
	if !ok && len(s) >= MaxSeenServers {
		return false
	}
	set := make(map[string]bool, len(have)+len(tools))
	for _, t := range have {
		set[t] = true
	}
	grew := false
	for _, t := range tools {
		if len(set) >= MaxSeenPerServer {
			break
		}
		if ValidName(t) && !set[t] {
			set[t] = true
			grew = true
		}
	}
	if !grew {
		return false
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	s[server] = out
	return true
}

// WriteSeen writes s as dir's SeenName (0600, atomic rename).
func WriteSeen(dir string, s Seen) error {
	clean := Seen{}
	for server, tools := range s {
		clean.Merge(server, tools)
	}
	b, err := json.MarshalIndent(clean, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(dir, SeenName, append(b, '\n'), 0o600)
}

// ReadSeen is dir's seen file; no file is an empty Seen. Invalid names and lists past the bounds are dropped.
func ReadSeen(dir string) (Seen, error) {
	b, err := readTrusted(filepath.Join(dir, SeenName), maxSeenBytes)
	if errors.Is(err, os.ErrNotExist) {
		return Seen{}, nil
	}
	if err != nil {
		return nil, err
	}
	var raw map[string][]string
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalid, SeenName, err)
	}
	out := Seen{}
	names := make([]string, 0, len(raw))
	for k := range raw {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		out.Merge(k, raw[k])
	}
	return out, nil
}
