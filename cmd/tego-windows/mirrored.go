// SPDX-License-Identifier: Apache-2.0

package main

import "strings"

// The mirrored-networking verdict, as pure functions over what was read (the Windows-only files read it), so it is
// tested on Linux. It is made before the dashboard is started, from WSL's own answer, so how long Tego's Linux takes to
// start does not change it (relay.go's portReservedWords is the same verdict reached by measurement, after).

// mirroredWords is the message of a mirrored-networking WSL, said before the dashboard is started (the port is then
// not known to be reserved; the networking mode says it will be). The tail is portReservedWords's.
func mirroredWords() string {
	return "tego: WSL is using mirrored networking, which reserves the dashboard's own port on this computer for Tego's Linux, so the dashboard cannot open in your browser; " + mirroredAdvice
}

// mirroredAdvice is what to do about it, the same whether the port was measured reserved or the mode said so.
const mirroredAdvice = `it needs WSL's default networking (networkingMode=nat in %USERPROFILE%\.wslconfig, then wsl --shutdown), and meanwhile the terminal shows your sessions: run: tego session list`

// networkingMirrored reads `wslinfo --networking-mode` (one word) and, when that gave none, the .wslconfig text. The
// running WSL decides when it answers: a .wslconfig edited since the last wsl --shutdown says nothing about it.
func networkingMirrored(wslinfo string, wslconfig string) bool {
	if mode := strings.ToLower(strings.TrimSpace(wslinfo)); mode != "" && !strings.ContainsAny(mode, " \t\r\n:/\\") {
		return mode == "mirrored"
	}
	return wslconfigMirrored(wslconfig)
}

// wslconfigMirrored reports whether a .wslconfig sets networkingMode=mirrored in its [wsl2] section. Section, key and
// value are not case-sensitive, whitespace around them and a CRLF are ignored, and a comment (# or ;, at the start of a
// line or after the value) is dropped. Microsoft's documentation of .wslconfig states neither what WSL does with a
// key given twice nor what it does with a comment after a value, so the first is not guessed (a key given twice
// with different values answers "no") and the second is read as the usual ini convention (the comment is dropped).
// Claiming mirrored wrongly would stop a dashboard that can start; answering "no" leaves the verdict to the relay's own
// measurement, which does not read this file.
func wslconfigMirrored(text string) bool {
	section := ""
	values := map[string]bool{}
	for _, line := range strings.Split(strings.TrimPrefix(text, "\ufeff"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			section = strings.ToLower(strings.Trim(line, "[] \t\r"))
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if section != "wsl2" || !ok || !strings.EqualFold(strings.TrimSpace(key), "networkingMode") {
			continue
		}
		if c := strings.IndexAny(val, "#;"); c >= 0 {
			val = val[:c]
		}
		values[strings.ToLower(strings.TrimSpace(val))] = true
	}
	return len(values) == 1 && values["mirrored"]
}
