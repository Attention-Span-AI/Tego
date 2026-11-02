// SPDX-License-Identifier: Apache-2.0

package shellword

import "strings"

// Quote is s as one word of a shell command line, the same word to sh, bash, zsh and fish. s stands as it is when it
// is not empty, holds only ASCII letters, digits and / . _ - : @ , + =, and does not start with = (zsh, by default,
// reads =name as the path of the program name). Any other s is put in single quotes, and each ' and each \ in it
// closes them, is written with a \ before it, and opens them again. The quoted text then holds neither, and no shell
// reads anything else in single quotes specially (fish reads \' and \\ there as escapes, so a \ left inside could
// close the quotes early), so no space, $, `, *, ~, ;, !, # or newline in s splits the word, expands or ends the
// command.
//
// Every byte is kept: a control or an invisible character (a bidi override) stays in the word as it is, so a caller
// that shows the line to a person writes those as it writes any other agent text (the dashboard as ⟦U+202E⟧).
func Quote(s string) string {
	if bare(s) {
		return s
	}
	return "'" + outside.Replace(s) + "'"
}

// outside writes a ' or a \ outside the single quotes, each after a \.
var outside = strings.NewReplacer(`'`, `'\''`, `\`, `'\\'`)

// bare reports whether s may stand unquoted.
func bare(s string) bool {
	if s == "" || s[0] == '=' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("/._-:@,+=", c) >= 0) {
			return false
		}
	}
	return true
}
