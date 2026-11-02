// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// clientServer is one entry of the client config's mcpServers (Claude Code's shape).
type clientServer struct {
	Type    string   `json:"type,omitempty"`
	Command string   `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
	URL     string   `json:"url,omitempty"`
}

// ClientConfig is the run's MCP client config: each relayed server as the agent's client must start or reach it,
// the shim for a stdio server and the relay URL for an HTTP one. Claude Code reads it with --mcp-config.
func ClientConfig(exe string, servers []Server, urls map[string]string) ([]byte, error) {
	out := struct {
		MCPServers map[string]clientServer `json:"mcpServers"`
	}{MCPServers: map[string]clientServer{}}
	for _, s := range servers {
		if s.URL != "" {
			u, ok := urls[s.Name]
			if !ok {
				continue
			}
			out.MCPServers[s.Name] = clientServer{Type: "http", URL: u}
			continue
		}
		args := append([]string{"mcp", "relay", "--server", s.Name, "--"}, s.Command...)
		out.MCPServers[s.Name] = clientServer{Command: exe, Args: args}
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// writeClientConfig writes the client config as dir/ConfigName, 0444, made exclusively (the run's runtime directory
// is new and its own), and returns its path.
func writeClientConfig(dir, exe string, servers []Server, urls map[string]string) (string, error) {
	b, err := ClientConfig(exe, servers, urls)
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, ConfigName)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o444)
	if err != nil {
		return "", fmt.Errorf("mcprelay: write %s: %w", ConfigName, err)
	}
	_, werr := f.Write(b)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(p)
		return "", fmt.Errorf("mcprelay: write %s: %w", ConfigName, werr)
	}
	return p, nil
}
