// SPDX-License-Identifier: Apache-2.0

package relaymux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Frame types.
const (
	TypeHello      byte = 1
	TypeOpen       byte = 2
	TypeData       byte = 3
	TypeWindow     byte = 4
	TypeCloseWrite byte = 5
	TypeClose      byte = 6
	TypeGoAway     byte = 7
)

// Limits on what a frame may carry.
const (
	headerSize = 9
	// MaxData is the most payload one DATA frame carries.
	MaxData = 32 << 10
	// maxReason bounds a CLOSE or GOAWAY reason.
	maxReason = 512
	// Window is each stream's send window in each direction.
	Window = 256 << 10
)

// Magic opens every HELLO payload: the protocol and its version.
const Magic = "tego-relay/1"

// Frame is one decoded frame. Payload aliases the buffer ReadFrame was given until the next call.
type Frame struct {
	Type    byte
	Stream  uint32
	Payload []byte
}

// ErrProtocol marks a frame no correct peer sends; the session ends on it.
var ErrProtocol = errors.New("relay protocol error")

func protocolf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrProtocol}, args...)...)
}

// maxPayload is the largest payload a frame of type t may carry, or -1 for an unknown type.
func maxPayload(t byte) int {
	switch t {
	case TypeHello:
		return len(Magic) + 2
	case TypeOpen, TypeCloseWrite:
		return 0
	case TypeData:
		return MaxData
	case TypeWindow:
		return 4
	case TypeClose, TypeGoAway:
		return maxReason
	}
	return -1
}

// ReadFrame reads one frame from r into buf (grown as needed, at most MaxData) and checks its shape: a known type,
// a payload within that type's limit, stream 0 exactly for HELLO and GOAWAY, and a nonzero WINDOW of 4 bytes.
func ReadFrame(r io.Reader, buf []byte) (Frame, []byte, error) {
	var h [headerSize]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return Frame{}, buf, err
	}
	f := Frame{Type: h[0], Stream: binary.BigEndian.Uint32(h[1:5])}
	n := binary.BigEndian.Uint32(h[5:9])
	limit := maxPayload(f.Type)
	if limit < 0 {
		return Frame{}, buf, protocolf("unknown frame type %d", f.Type)
	}
	if uint64(n) > uint64(limit) {
		return Frame{}, buf, protocolf("frame type %d carries %d bytes, more than %d", f.Type, n, limit)
	}
	control := f.Type == TypeHello || f.Type == TypeGoAway
	if control != (f.Stream == 0) {
		return Frame{}, buf, protocolf("frame type %d on stream %d", f.Type, f.Stream)
	}
	if cap(buf) < int(n) {
		buf = make([]byte, n, MaxData)
	}
	f.Payload = buf[:n]
	if _, err := io.ReadFull(r, f.Payload); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return Frame{}, buf, err
	}
	if f.Type == TypeWindow && (n != 4 || binary.BigEndian.Uint32(f.Payload) == 0) {
		return Frame{}, buf, protocolf("an empty window update on stream %d", f.Stream)
	}
	return f, buf, nil
}

// AppendFrame appends the encoding of one frame to b. It does not check limits: Session only builds frames within
// them.
func AppendFrame(b []byte, t byte, stream uint32, payload []byte) []byte {
	b = append(b, t)
	b = binary.BigEndian.AppendUint32(b, stream)
	b = binary.BigEndian.AppendUint32(b, uint32(len(payload)))
	return append(b, payload...)
}

// helloPayload is the HELLO payload: Magic, then the port the Linux end serves (0 from the Windows end).
func helloPayload(port uint16) []byte {
	return binary.BigEndian.AppendUint16([]byte(Magic), port)
}

// parseHello reads a HELLO payload's port, refusing another protocol or version.
func parseHello(p []byte) (uint16, error) {
	if len(p) != len(Magic)+2 || string(p[:len(Magic)]) != Magic {
		return 0, protocolf("the other end does not speak %s", Magic)
	}
	return binary.BigEndian.Uint16(p[len(Magic):]), nil
}
