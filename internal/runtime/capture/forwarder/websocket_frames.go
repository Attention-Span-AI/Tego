// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"encoding/binary"
	"errors"
	"io"
	"unicode/utf8"
)

var errWebSocketFrame = errors.New("forwarder: invalid WebSocket frame")
var errWebSocketClosed = errors.New("forwarder: WebSocket close frame delivered")

// Validate wire framing and bounded fragmented message lengths without
// recording payloads or changing masks, frame boundaries or application data.
func websocketFrames(dst io.Writer, src io.Reader, masked bool, maxFrame int64, budget *tunnelBudget) error {
	buffer := make([]byte, 32<<10)
	var header [14]byte
	fragmented, messageBytes := false, int64(0)
	for {
		if _, err := io.ReadFull(src, header[:2]); err != nil {
			return err
		}
		fin, opcode := header[0]&0x80 != 0, header[0]&15
		if header[0]&0x70 != 0 || (header[1]&0x80 != 0) != masked {
			return errWebSocketFrame
		}
		size, headerLen := uint64(header[1]&127), 2
		switch size {
		case 126:
			if _, err := io.ReadFull(src, header[2:4]); err != nil {
				return err
			}
			size, headerLen = uint64(binary.BigEndian.Uint16(header[2:4])), 4
			if size < 126 {
				return errWebSocketFrame
			}
		case 127:
			if _, err := io.ReadFull(src, header[2:10]); err != nil {
				return err
			}
			size, headerLen = binary.BigEndian.Uint64(header[2:10]), 10
			if size < 65536 || size>>63 != 0 {
				return errWebSocketFrame
			}
		}
		if size > uint64(maxFrame) {
			return errTunnelLimit
		}
		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(src, header[headerLen:headerLen+4]); err != nil {
				return err
			}
			copy(mask[:], header[headerLen:headerLen+4])
			headerLen += 4
		}
		switch opcode {
		case 0:
			if !fragmented {
				return errWebSocketFrame
			}
			if int64(size) > maxFrame-messageBytes {
				return errTunnelLimit
			}
			messageBytes += int64(size)
			if fin {
				fragmented, messageBytes = false, 0
			}
		case 1, 2:
			if fragmented {
				return errWebSocketFrame
			}
			if !fin {
				fragmented, messageBytes = true, int64(size)
			}
		case 8, 9, 10:
			if !fin || size > 125 || opcode == 8 && size == 1 {
				return errWebSocketFrame
			}
		default:
			return errWebSocketFrame
		}
		if !budget.reserve(int64(headerLen) + int64(size)) {
			return errTunnelLimit
		}
		if opcode >= 8 {
			payload := buffer[:int(size)]
			if _, err := io.ReadFull(src, payload); err != nil {
				return err
			}
			if opcode == 8 && size >= 2 {
				var decoded [125]byte
				for i, b := range payload {
					if masked {
						b ^= mask[i%4]
					}
					decoded[i] = b
				}
				code := binary.BigEndian.Uint16(decoded[:2])
				if code < 1000 || code >= 5000 || code == 1004 || code == 1005 || code == 1006 || code == 1015 || !utf8.Valid(decoded[2:size]) {
					return errWebSocketFrame
				}
			}
			if err := writeTunnelFrame(dst, header[:headerLen], payload, budget); err != nil {
				return err
			}
			if opcode == 8 {
				return errWebSocketClosed
			}
			continue
		}
		if err := writeTunnelFrame(dst, header[:headerLen], nil, budget); err != nil {
			return err
		}
		for remaining := int64(size); remaining > 0; {
			n := min(remaining, int64(len(buffer)))
			if _, err := io.ReadFull(src, buffer[:n]); err != nil {
				return err
			}
			if err := writeTunnelFrame(dst, nil, buffer[:n], budget); err != nil {
				return err
			}
			remaining -= n
		}
	}
}

func writeTunnelFrame(dst io.Writer, header, body []byte, budget *tunnelBudget) error {
	for _, data := range [][]byte{header, body} {
		if len(data) == 0 {
			continue
		}
		n, err := dst.Write(data)
		if n > 0 {
			budget.touch()
		}
		if err != nil {
			return err
		}
		if n != len(data) {
			return io.ErrShortWrite
		}
	}
	return nil
}
