// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"fmt"
	"strings"
)

// maxDiffCells bounds the line diff's table; past it the diff is the whole old file removed and the new one added.
const maxDiffCells = 4 << 20

// Diff is a unified line diff of a and b, labelled with name, with up to two lines of context around each change.
func Diff(name string, a, b []byte) string {
	x, y := splitLines(string(a)), splitLines(string(b))
	ops := lineOps(x, y)
	var out strings.Builder
	fmt.Fprintf(&out, "--- %s\n+++ %s (new)\n", name, name)
	const ctx = 2
	for i := 0; i < len(ops); {
		if ops[i].k == ' ' {
			i++
			continue
		}
		start := max(i-ctx, 0)
		end := i
		for end < len(ops) {
			if ops[end].k != ' ' {
				end++
				continue
			}
			j := end
			for j < len(ops) && ops[j].k == ' ' && j-end < 2*ctx+1 {
				j++
			}
			if j < len(ops) && ops[j].k != ' ' && j-end <= 2*ctx {
				end = j
				continue
			}
			break
		}
		stop := min(end+ctx, len(ops))
		fmt.Fprintf(&out, "@@ line %d @@\n", ops[start].line)
		for _, o := range ops[start:stop] {
			out.WriteByte(o.k)
			out.WriteString(o.s)
			out.WriteByte('\n')
		}
		i = stop
	}
	return out.String()
}

type lineOp struct {
	k    byte // ' ', '-' or '+'
	s    string
	line int // the line's number in the old file (for '+', the old line it comes before)
}

func splitLines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// lineOps is the longest-common-subsequence edit script of x into y. Where removing and adding are equally good the
// removal comes first, so a changed line reads old above new ("-  allow: [bash, cat, ls]" then "+  allow: [bash,
// cat]"), as every unified diff reads.
func lineOps(x, y []string) []lineOp {
	n, m := len(x), len(y)
	if (n+1)*(m+1) > maxDiffCells {
		ops := make([]lineOp, 0, n+m)
		for i, s := range x {
			ops = append(ops, lineOp{'-', s, i + 1})
		}
		for _, s := range y {
			ops = append(ops, lineOp{'+', s, n + 1})
		}
		return ops
	}
	t := make([][]int32, n+1)
	for i := range t {
		t[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if x[i] == y[j] {
				t[i][j] = t[i+1][j+1] + 1
			} else {
				t[i][j] = max(t[i+1][j], t[i][j+1])
			}
		}
	}
	var ops []lineOp
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && x[i] == y[j]:
			ops = append(ops, lineOp{' ', x[i], i + 1})
			i++
			j++
		case i < n && (j == m || t[i+1][j] >= t[i][j+1]):
			ops = append(ops, lineOp{'-', x[i], i + 1})
			i++
		default:
			ops = append(ops, lineOp{'+', y[j], i + 1})
			j++
		}
	}
	return ops
}
