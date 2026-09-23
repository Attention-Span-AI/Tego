// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"bytes"
	"fmt"
	"strings"
)

// CodexConfig renders the config.toml a run's CODEX_HOME holds when capture is forwarder
// (spec/identity/RUN-IDENTITY.md, the CODEX_HOME row): openai_base_url names the run's openai
// listener, so Codex's built-in openai provider sends its requests through the forwarder. Codex has no
// variable for this: it ignores OPENAI_BASE_URL (checked against codex-cli 0.155.1, which called
// api.openai.com with the variable set and a local listener's URL with this file), and its configuration
// reference says it reads openai_base_url only from the user-level file, never from a project's
// .codex/config.toml.
//
// user is the user's own config.toml, or nil. It follows the tego key unchanged, so the run keeps the
// user's settings; a top-level key has to precede every table, which is why the key goes first. A user
// file that sets openai_base_url itself is left as it is, and the duplicate key makes the file invalid
// TOML, which Codex refuses to start on (codex-cli 0.155.1 exits 1 with "Error loading config.toml:
// duplicate key"): a run that would otherwise have sent its traffic around the forwarder fails where the
// user can see it. A leading byte-order mark is dropped, since it would no
// longer be at the start of the file.
func CodexConfig(openaiBaseURL string, user []byte) []byte {
	var b bytes.Buffer
	b.WriteString("# Written by tego for one run: the built-in openai provider goes through the run's\n")
	b.WriteString("# loopback forwarder, which records every model call (docs/p0/capture-derive.md R19).\n")
	fmt.Fprintf(&b, "openai_base_url = %s\n", tomlString(openaiBaseURL))
	user = bytes.TrimPrefix(user, []byte("\xef\xbb\xbf"))
	if len(user) > 0 {
		b.WriteString("\n")
		b.Write(user)
		if user[len(user)-1] != '\n' {
			b.WriteString("\n")
		}
	}
	return b.Bytes()
}

// tomlString quotes s as a TOML basic string: backslash and quote escaped, and every control character
// written as \uXXXX, which is the one escape TOML 1.0 defines for all of them.
func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, "\\u%04X", r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
