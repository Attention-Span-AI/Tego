// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// The agent's git identity: every commit Claude Code makes under Maze carries this name and email and is
// signed with a key Maze made for it, so the person's own commits and the agent's are told apart at a glance
// (git log) and by signature (git log --show-signature), and a pre-push check can find the agent's commits.
const (
	AgentName  = "Claude Code (via Maze)"
	AgentEmail = "claude-code@maze.local"
	agentDir   = ".maze/agent"
	agentKey   = "id_ed25519"
	// allowedSigners lets git verify the agent's signatures without the person's own git config changing.
	allowedSigners = "allowed_signers"
)

// AgentKey is where the agent's signing key and its allowed-signers file are.
type AgentKey struct {
	Private        string
	Public         string
	AllowedSigners string
}

// AgentKeyPaths returns the paths of the agent's key under home, made or not.
func AgentKeyPaths(home string) AgentKey {
	dir := filepath.Join(home, agentDir)
	return AgentKey{
		Private:        filepath.Join(dir, agentKey),
		Public:         filepath.Join(dir, agentKey+".pub"),
		AllowedSigners: filepath.Join(dir, allowedSigners),
	}
}

// EnsureAgentKey makes the agent's signing key the first time and returns its paths. The key never leaves this
// computer and is used for nothing but the agent's commits; it is not the person's key and GitHub doesn't know it
// (GitHub shows such commits as Unverified unless the person uploads the public key). An existing key is kept.
func EnsureAgentKey(home string) (AgentKey, error) {
	k := AgentKeyPaths(home)
	if _, ok, err := readFile(k.Private); err != nil || ok {
		return k, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return AgentKey{}, fmt.Errorf("make the agent's signing key: %w", err)
	}
	private, err := opensshPrivateKey(pub, priv, AgentEmail)
	if err != nil {
		return AgentKey{}, err
	}
	line := authorizedKey(pub)
	for _, f := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{k.Private, private, 0o600},
		{k.Public, []byte(line + " " + AgentEmail + "\n"), 0o644},
		{k.AllowedSigners, []byte(AgentEmail + ` namespaces="git" ` + line + "\n"), 0o644},
	} {
		if err := writeFile(f.path, f.data, f.mode, 0o700); err != nil {
			return AgentKey{}, err
		}
	}
	return k, nil
}

// sshString is the SSH wire encoding of b: a 4-byte big-endian length, then b (RFC 4251 §5).
func sshString(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	return append(out, b...)
}

// publicBlob is an ed25519 public key in SSH wire form (RFC 8709 §4).
func publicBlob(pub ed25519.PublicKey) []byte {
	return append(sshString([]byte("ssh-ed25519")), sshString(pub)...)
}

// authorizedKey is the public key as one line: "ssh-ed25519 AAAA…".
func authorizedKey(pub ed25519.PublicKey) string {
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(publicBlob(pub))
}

// opensshPrivateKey encodes an unencrypted ed25519 key in OpenSSH's own format (PROTOCOL.key in OpenSSH's
// sources), the one ssh-keygen writes and git's SSH signing reads.
func opensshPrivateKey(pub ed25519.PublicKey, priv ed25519.PrivateKey, comment string) ([]byte, error) {
	var check [4]byte
	if _, err := rand.Read(check[:]); err != nil {
		return nil, err
	}
	var p bytes.Buffer
	p.Write(check[:])
	p.Write(check[:])
	p.Write(sshString([]byte("ssh-ed25519")))
	p.Write(sshString(pub))
	p.Write(sshString(priv)) // 64 bytes: the seed, then the public key
	p.Write(sshString([]byte(comment)))
	for i := byte(1); p.Len()%8 != 0; i++ {
		p.WriteByte(i)
	}
	var b bytes.Buffer
	b.WriteString("openssh-key-v1\x00")
	b.Write(sshString([]byte("none"))) // cipher
	b.Write(sshString([]byte("none"))) // kdf
	b.Write(sshString(nil))            // kdf options
	b.Write(binary.BigEndian.AppendUint32(nil, 1))
	b.Write(sshString(publicBlob(pub)))
	b.Write(sshString(p.Bytes()))
	return pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: b.Bytes()}), nil
}

// GitIdentityEnv is the environment a run gives the agent so git commits as the agent and signs with its key,
// without touching the person's git config: GIT_CONFIG_COUNT settings apply to that process tree only.
func GitIdentityEnv(k AgentKey) [][2]string {
	return [][2]string{
		{"GIT_AUTHOR_NAME", AgentName},
		{"GIT_AUTHOR_EMAIL", AgentEmail},
		{"GIT_COMMITTER_NAME", AgentName},
		{"GIT_COMMITTER_EMAIL", AgentEmail},
		{"GIT_CONFIG_COUNT", "4"},
		{"GIT_CONFIG_KEY_0", "gpg.format"},
		{"GIT_CONFIG_VALUE_0", "ssh"},
		{"GIT_CONFIG_KEY_1", "user.signingkey"},
		{"GIT_CONFIG_VALUE_1", k.Private},
		{"GIT_CONFIG_KEY_2", "commit.gpgsign"},
		{"GIT_CONFIG_VALUE_2", "true"},
		{"GIT_CONFIG_KEY_3", "gpg.ssh.allowedSignersFile"},
		{"GIT_CONFIG_VALUE_3", k.AllowedSigners},
	}
}
