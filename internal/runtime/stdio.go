// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// StdioStream is one standard descriptor as the agent gets it: its kind, and whether it grants more than its
// direction needs.
type StdioStream struct {
	// Name is stdin, stdout or stderr.
	Name string
	// Kind is one of the record.Stdio* kinds.
	Kind string
	// Path is where a regular file's descriptor points, "" for any other kind.
	Path string
	// Readable and Writable are the descriptor's access mode.
	Readable, Writable bool
}

// DescribeStdio examines the three streams a run hands its agent (invariant 4a). A nil member is
// /dev/null, which launch gives a stream the caller did not pass.
func DescribeStdio(s Stdio) [3]StdioStream {
	out := [3]StdioStream{{Name: "stdin"}, {Name: "stdout"}, {Name: "stderr"}}
	for i, f := range []*os.File{s.In, s.Out, s.Err} {
		if f == nil {
			out[i].Kind = record.StdioNull
			continue
		}
		if err := sys.FileDo(f, func(fd int) error { describeFD(fd, &out[i]); return nil }); err != nil {
			out[i].Kind = record.StdioUnknown // a closed File lends no number
		}
	}
	return out
}

// describeFD fills st from fstat and the access mode of fd.
func describeFD(fd int, st *StdioStream) {
	var s unix.Stat_t
	if err := unix.Fstat(fd, &s); err != nil {
		st.Kind = record.StdioUnknown
		return
	}
	if fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0); err == nil {
		switch fl & unix.O_ACCMODE {
		case unix.O_RDONLY:
			st.Readable = true
		case unix.O_WRONLY:
			st.Writable = true
		case unix.O_RDWR:
			st.Readable, st.Writable = true, true
		}
	}
	switch s.Mode & unix.S_IFMT {
	case unix.S_IFCHR:
		switch {
		case unix.Major(s.Rdev) == 1 && unix.Minor(s.Rdev) == 3:
			st.Kind = record.StdioNull
		case isTerminal(fd):
			st.Kind = record.StdioTTY
		default:
			st.Kind = record.StdioChar
		}
	case unix.S_IFIFO:
		st.Kind = record.StdioPipe
	case unix.S_IFSOCK:
		st.Kind = record.StdioSocket
	case unix.S_IFREG:
		st.Kind = record.StdioFile
		if p, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd)); err == nil {
			st.Path = p
		}
	case unix.S_IFDIR:
		st.Kind = record.StdioDir
	default:
		st.Kind = record.StdioOther
	}
}

// isTerminal reports whether fd is a terminal.
func isTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	return err == nil
}

// stdioRecord is DescribeStdio as run_start records it.
func stdioRecord(s Stdio) *record.Stdio {
	d := DescribeStdio(s)
	return &record.Stdio{Stdin: d[0].Kind, Stdout: d[1].Kind, Stderr: d[2].Kind}
}

// StdioBeyondContract is the streams that give the agent access no rule of rt would: a socket, a live
// channel whatever net: says; and a regular file outside every write entry that the stream grants more than
// its direction needs, stdin open for writing or stdout or stderr open for reading, since Landlock checks
// access only at open and cannot take back what the caller's open granted. A stream that goes only its own
// way, output redirected into a file, is what the caller asked for and is not reported (invariant 4a).
func StdioBeyondContract(rt *agent.RuleTable, streams [3]StdioStream) []StdioStream {
	var out []StdioStream
	for i, st := range streams {
		switch st.Kind {
		case record.StdioSocket:
			out = append(out, st)
		case record.StdioFile:
			beyond := (i == 0 && st.Writable) || (i > 0 && st.Readable)
			if !beyond {
				continue
			}
			if rt != nil && st.Path != "" && st.Writable &&
				decide.Evaluate(rt, agent.Action{Kind: agent.ActionFSWrite, Path: st.Path}, rt.Tier).Verdict == agent.VerdictAllow {
				continue // the contract grants the write anyway
			}
			out = append(out, st)
		}
	}
	return out
}
