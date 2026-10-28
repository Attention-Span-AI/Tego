// SPDX-License-Identifier: Apache-2.0

package linewords

import (
	"regexp"
	"strings"
	"sync"
)

// secretArgs are the credential shapes Mask hides; each keeps its first group and masks the second.
var secretArgs = []*regexp.Regexp{
	// An HTTP auth scheme: "Authorization: Basic abc", a quoted "Token abc", or "Bearer abc" anywhere. Basic and
	// token are ordinary words ("pip install basic requests", "echo token generated"), so they count only after an
	// Authorization header name or a quote; bearer is not, so it counts after any space.
	regexp.MustCompile(`(?i)((?:(?:authorization\s*:\s*|^|["'])(?:bearer|basic|token)|(?:^|[\s:"'])bearer)\s+)([A-Za-z0-9._~+/=:-]{6,})`),
	// A flag that takes a secret: --token X, --password=X, -p=X is too short to tell and is left.
	regexp.MustCompile(`(?i)((?:^|\s)--?(?:api[-_]?key|access[-_]?token|auth[-_]?token|token|secret|client[-_]?secret|password|passwd|pass)(?:=|\s+))([^\s"']+)`),
	// key=value or key: value where the key names a secret (in a query string, an env assignment, a header).
	regexp.MustCompile(`(?i)((?:^|[\s&?;,"'])[a-z0-9_.-]*(?:api[-_]?key|token|secret|password|passwd)\s*[=:]\s*)([^\s&"',;]+)`),
	// A password in a URL: scheme://user:password@host.
	regexp.MustCompile(`(://[^/\s:@]+:)([^@\s/]+)(@)`),
}

// tokenShapes are well-known credential formats, masked after their first four characters.
var tokenShapes = regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[abpr]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,})`)

// Mask is s with credential-looking values replaced by "••••". A long text (a command line read from its blob, up to
// 8 KiB in a row and 256 KiB on the line page) costs milliseconds in the regexp engine, and every Logs request
// would pay it again for each such row, so its result is remembered (the mask memo).
func Mask(s string) string {
	if len(s) < MaskMemoMin {
		return MaskNow(s)
	}
	maskMu.Lock()
	m, ok := maskMemo[s]
	maskMu.Unlock()
	if ok {
		return m
	}
	m = MaskNow(s)
	maskMu.Lock()
	if maskBytes+len(s) > MaskMemoMax {
		maskMemo, maskBytes = map[string]string{}, 0 // full: start again rather than track an order
	}
	if len(s) <= MaskMemoMax {
		maskMemo[s] = m
		maskBytes += len(s) + len(m)
	}
	maskMu.Unlock()
	return m
}

// The mask memo: texts of at least MaskMemoMin bytes, up to MaskMemoMax bytes of keys and values in all.
const (
	MaskMemoMin = 1 << 10
	MaskMemoMax = 8 << 20
)

var (
	maskMu    sync.Mutex
	maskMemo  = map[string]string{}
	maskBytes int
)

// MaskNow is Mask without the memo.
func MaskNow(s string) string {
	for _, re := range secretArgs {
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			sub := re.FindStringSubmatch(m)
			if len(sub) < 3 || strings.Trim(sub[2], "•") == "" {
				return m
			}
			out := sub[1] + "••••"
			if len(sub) > 3 {
				out += sub[3]
			}
			return out
		})
	}
	return tokenShapes.ReplaceAllStringFunc(s, func(m string) string { return m[:4] + "••••" })
}
