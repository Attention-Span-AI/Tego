// SPDX-License-Identifier: Apache-2.0

package reason

import (
	"strconv"
	"strings"
)

// MaxRenderBytes bounds Render's text (a harness's context field takes about this many characters; a byte is at
// most one of them).
const MaxRenderBytes = 4000

// Render is the plain text an agent is shown for entries (oldest first, as Since returns them) and notListed more
// refusals that are not listed: a line saying how many refusals there were, then one line per distinct refusal in
// the order each first came, with "xN " before one that came N times, then "N more not listed." when the cap of
// MaxRenderBytes or the file's own list left some out. Each sentence is made again from the entry's fields (Text),
// never taken from the file's text, so every string an agent chose is quoted whatever wrote the file. A field the
// file holds cut (Cut) is quoted as the file holds it, so a sentence's "… (N bytes)" is the length of the field in
// the file: the real length is in the field's own "…(N bytes)" and the file's text, words of the file that Render
// does not take (an agent's own string can end the same way). Nothing to tell is "".
func Render(entries []Entry, notListed uint64) string {
	total := notListed + uint64(len(entries))
	if total == 0 {
		return ""
	}
	type line struct {
		text string
		n    uint64
	}
	var lines []line
	at := map[string]int{}
	for _, e := range entries {
		t := Text(e.Reason, e.Op, e.Target, e.Rule)
		if i, ok := at[t]; ok {
			lines[i].n++
			continue
		}
		at[t] = len(lines)
		lines = append(lines, line{t, 1})
	}
	var b strings.Builder
	b.WriteString("Tego, this run's access control, refused " + count(total, "action", "actions") + ":\n")
	// Room is kept for the closing line whenever anything after a line would be left out; its count is at most
	// total, so total's length is room enough.
	left, remaining, reserve := notListed, uint64(len(entries)), len(moreLine(total))
	for _, l := range lines {
		s := "- " + l.text + "\n"
		if l.n > 1 {
			s = "- x" + strconv.FormatUint(l.n, 10) + " " + l.text + "\n"
		}
		remaining -= l.n
		room := MaxRenderBytes - b.Len() - len(s)
		if remaining+left > 0 {
			room -= reserve
		}
		if room < 0 {
			left += remaining + l.n
			break
		}
		b.WriteString(s)
	}
	if left > 0 {
		b.WriteString(moreLine(left))
	}
	return b.String()
}

func moreLine(n uint64) string { return strconv.FormatUint(n, 10) + " more not listed.\n" }

func count(n uint64, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.FormatUint(n, 10) + " " + many
}
