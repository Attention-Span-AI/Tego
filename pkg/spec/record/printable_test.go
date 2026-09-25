// SPDX-License-Identifier: Apache-2.0

package record

import (
	"strings"
	"testing"
)

func TestPrintable(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/home/u/proj/out/report.md", "/home/u/proj/out/report.md"},
		{"naïve résumé 日本", "naïve résumé 日本"},
		{"x\x1b[1A\x1b[2K\rforged", `x\x1b[1A\x1b[2K\rforged`},
		{"a\nFAKE 99 refused", `a\nFAKE 99 refused`},
		{"\x1b]0;title\a", `\x1b]0;title\a`},
		{"del\x7f", `del\x7f`},
		{"c1\u0085x", `c1\u0085x`},
		{"bidi\u202egnp.exe", "bidi\\u202egnp.exe"},
		{"iso\u2066x\u2069", "iso\\u2066x\\u2069"},
		{"zw\U0000200bx\U0000200d\U00002060\U0000feff", "zw\x5cu200bx\x5cu200d\x5cu2060\x5cufeff"},
		{"marks\U0000200e\U0000200f\U0000061c", "marks\x5cu200e\x5cu200f\x5cu061c"},
		{"sep\U00002028\U00002029", "sep\x5cu2028\x5cu2029"},
		{"tag\U000e0041\U000e007f", `tag\U000e0041\U000e007f`},
		{"bad\xffutf8", `bad\xffutf8`},
		{"tab\tx", `tab\tx`},
	} {
		got := Printable(tc.in)
		if got != tc.want {
			t.Errorf("Printable(%q) = %q, want %q", tc.in, got, tc.want)
		}
		for _, c := range got {
			if unsafeRune(c) {
				t.Errorf("Printable(%q) still holds %U", tc.in, c)
			}
		}
		if strings.ContainsAny(got, "\n\r\x1b") {
			t.Errorf("Printable(%q) = %q holds a control byte", tc.in, got)
		}
	}
}

func TestInvisible(t *testing.T) {
	for _, r := range []rune{0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069, 0x200e, 0x200f,
		0x061c, 0x200b, 0x200c, 0x200d, 0x2060, 0xfeff, 0x00ad, 0x2028, 0x2029, 0xe0001, 0xe0041, 0xe007f} {
		if !Invisible(r) {
			t.Errorf("Invisible(%U) = false", r)
		}
	}
	for _, r := range []rune{'a', ' ', '\n', 0x7f, 0x85, 'é', '日', 0x00a0, 0x2011, 0xfe0f, 0x1f600, 0x27e6} {
		// Controls are Printable's own business (unsafeRune), not Invisible's; a variation selector is a mark (Mn).
		if Invisible(r) {
			t.Errorf("Invisible(%U) = true", r)
		}
	}
}

func FuzzPrintable(f *testing.F) {
	f.Add("x\x1b[2Kforged\n")
	f.Add("\u202e\xff")
	f.Fuzz(func(t *testing.T, s string) {
		got := Printable(s)
		for i := 0; i < len(got); i++ {
			if c := got[i]; c < 0x20 || c == 0x7f {
				t.Fatalf("Printable(%q) = %q holds byte %#x", s, got, c)
			}
		}
		for _, r := range got {
			if unsafeRune(r) {
				t.Fatalf("Printable(%q) = %q holds %U", s, got, r)
			}
		}
		if Printable(got) != got && !strings.Contains(got, `\`) {
			t.Fatalf("Printable is not stable on its own output: %q", got)
		}
	})
}
