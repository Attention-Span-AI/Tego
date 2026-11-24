// SPDX-License-Identifier: Apache-2.0

package web

// bandVerb keeps a phone request's action and short target readable at 320 px.
// The accessible sentence and Details retain askVerb's complete wording.
func bandVerb(op, rule, hold string) string {
	switch op {
	case "":
		return "continue"
	case "mkdir":
		return "create folder"
	case "symlink":
		return "symlink"
	case "link":
		return "hard link"
	case "request":
		return "request"
	case "mcp_tool":
		return "call tool"
	}
	return askVerb(op, rule, hold)
}
