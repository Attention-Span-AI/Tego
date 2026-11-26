// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
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
		if s.BusinessRules {
			return nil, ErrBusinessUnavailable
		}
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

// writeClientConfig writes the client config as ConfigName in the directory, made exclusively and never through a
// link, and returns its path. With dfd nil the directory is the run's own runtime directory (private to the user who
// runs the agent, 0700) at dir, and the file is 0444. With a descriptor it is a directory a root launcher made and only
// root can write, held open as dfd (dir is its name, for the agent): the file is made through dfd, never through dir,
// 0400, and handed to uid and gid by its own descriptor, so the agent's user reads it, no other user can, and no one but
// root can add, rename or remove an entry beside it.
func writeClientConfig(dir string, dfd *sys.FD, exe string, servers []Server, urls map[string]string, uid, gid int) (string, error) {
	b, err := ClientConfig(exe, servers, urls)
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, ConfigName)
	if dfd == nil {
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
	fd, err := dfd.Openat(ConfigName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o400)
	if err != nil {
		return "", fmt.Errorf("mcprelay: write %s: %w", ConfigName, err)
	}
	f, err := fd.Release(p)
	if err != nil {
		_ = fd.Close()
		return "", fmt.Errorf("mcprelay: write %s: %w", ConfigName, err)
	}
	_, werr := f.Write(b)
	if werr == nil {
		werr = f.Chown(uid, gid)
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = dfd.Borrow(func(n int) error { return unix.Unlinkat(n, ConfigName, 0) })
		return "", fmt.Errorf("mcprelay: write %s: %w", ConfigName, werr)
	}
	return p, nil
}
