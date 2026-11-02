// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/attention-span-ai/tego/internal/runtime/derive/mcp"
)

// The shim's control protocol (ADR 0126 §4 "Stdio shim"): newline-delimited JSON frames over one TCP connection to
// the service's control listener. The shim says hello, waits for ok, starts the server and says started; from then
// on every client line goes to the service as C and every server line as S, and the shim writes to the server only
// what a ToServer frame carries and to the client only what a ToClient frame carries. A line travels as bytes
// (base64 in JSON), so a line that is not UTF-8 reaches the service unchanged. The service answers it: a server line
// passes as it came, a client line goes to the server only in its wire form (wireLine).

// ProtocolVersion is the hello's v.
const ProtocolVersion = 1

// EnvRelay is the variable naming the control listener (127.0.0.1:<port>) in the run's environment.
const EnvRelay = "TEGO_MCP_RELAY"

// EnvConfig is the variable naming the run's MCP client config file (Claude Code's mcpServers shape).
const EnvConfig = "TEGO_MCP_CONFIG"

// ConfigName is the client config file's name in the run's runtime directory.
const ConfigName = "tego-mcp.json"

// MaxLine bounds one JSON-RPC line the shim forwards: derive/mcp's MaxMessage. A longer line is dropped and
// reported (Frame.Oversize), never forwarded unread.
const MaxLine = mcp.MaxMessage

// maxFrame bounds one control frame: a line in base64 and its frame.
const maxFrame = MaxLine/3*4 + 4096

// Frame is one control message, either way.
type Frame struct {
	// Hello (shim -> service).
	V      int      `json:"v,omitempty"`
	Server string   `json:"server,omitempty"`
	Argv   []string `json:"argv,omitempty"`
	PID    int      `json:"pid,omitempty"`
	// Answer to the hello (service -> shim).
	OK    bool   `json:"ok,omitempty"`
	Error string `json:"error,omitempty"`
	// Started is the server's pid, once the shim started it (shim -> service).
	Started int `json:"started,omitempty"`
	// C is a client line and S a server line (shim -> service).
	C []byte `json:"c,omitempty"`
	S []byte `json:"s,omitempty"`
	// Oversize says a line of "c" or "s" over MaxLine was dropped (shim -> service).
	Oversize string `json:"oversize,omitempty"`
	// Exit is the server's exit status once it ended (shim -> service).
	Exit *int `json:"exit,omitempty"`
	// ToServer and ToClient are lines the shim writes, with a newline (service -> shim).
	ToServer []byte `json:"to_server,omitempty"`
	ToClient []byte `json:"to_client,omitempty"`
}

// ErrFrame is a control frame that cannot be read.
var ErrFrame = errors.New("mcprelay: bad control frame")

// FrameReader reads frames of at most limit bytes.
type FrameReader struct {
	r     *bufio.Reader
	limit int
}

// NewFrameReader reads frames from r.
func NewFrameReader(r io.Reader, limit int) *FrameReader {
	if limit <= 0 {
		limit = maxFrame
	}
	return &FrameReader{r: bufio.NewReaderSize(r, 64<<10), limit: limit}
}

// Read is the next frame.
func (f *FrameReader) Read() (Frame, error) {
	line, oversize, err := ReadLine(f.r, f.limit)
	if err != nil {
		return Frame{}, err
	}
	if oversize {
		return Frame{}, fmt.Errorf("%w: longer than %d bytes", ErrFrame, f.limit)
	}
	var fr Frame
	if err := json.Unmarshal(line, &fr); err != nil {
		return Frame{}, fmt.Errorf("%w: %w", ErrFrame, err)
	}
	return fr, nil
}

// FrameWriter writes frames; it is safe for concurrent use.
type FrameWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// NewFrameWriter writes frames to w.
func NewFrameWriter(w io.Writer) *FrameWriter { return &FrameWriter{w: w} }

// Write sends one frame.
func (f *FrameWriter) Write(fr Frame) error {
	b, err := json.Marshal(fr)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_, err = f.w.Write(append(b, '\n'))
	return err
}

// ReadLine reads one newline-terminated line without its newline (and a trailing \r). A line longer than limit is
// read to its end and dropped: oversize is true and line nil. io.EOF with no bytes is the end; a last line with no
// newline is returned as a line.
func ReadLine(r *bufio.Reader, limit int) (line []byte, oversize bool, err error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if !oversize {
			if len(buf)+len(chunk) > limit+2 {
				oversize, buf = true, nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		switch {
		case err == nil:
			if oversize {
				return nil, true, nil
			}
			return trimEOL(buf), false, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && (len(buf) > 0 || oversize):
			if oversize {
				return nil, true, nil
			}
			return trimEOL(buf), false, nil
		default:
			return nil, false, err
		}
	}
}

func trimEOL(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
	}
	if n := len(b); n > 0 && b[n-1] == '\r' {
		b = b[:n-1]
	}
	if len(b) == 0 {
		return []byte{}
	}
	return b
}
