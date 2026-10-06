// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

const (
	// metadataLen is sizeof(struct fanotify_event_metadata): event_len, vers, reserved, metadata_len, mask,
	// fd, pid. A group that asks for no FAN_REPORT_* flag, as this one, gets nothing after it.
	metadataLen = 24
	// permMask is the permission events a record can be one of. A record with none of these bits is an
	// overflow or a notification: it wants no response.
	permMask = unix.FAN_OPEN_PERM | unix.FAN_OPEN_EXEC_PERM
)

// event is one decoded record, the fields the listener uses.
type event struct {
	Len  uint32 // event_len: the record's size, any info records after the metadata included
	Mask uint64
	Fd   int32 // the opened file, open in this process until the response is written; FAN_NOFD for none
	Pid  int32 // the opener's thread group id, in this process's pid namespace
}

// isPermission reports whether the record demands a response. Every one that does gets exactly one.
func (e event) isPermission() bool { return e.Mask&permMask != 0 }

// isExec reports whether the open is an execve's.
func (e event) isExec() bool { return e.Mask&unix.FAN_OPEN_EXEC_PERM != 0 }

// errVersion is a record whose metadata version is not FANOTIFY_METADATA_VERSION. Nothing after its first
// bytes can be trusted, so it ends the listener, where a damaged record only ends the walk of its read.
var errVersion = errors.New("fanotify metadata version is not the one this tool speaks")

// parseEvents decodes a read(2) buffer into records. It returns everything it decoded before the first byte it
// could not, with an error naming that byte: the records before it carry descriptors somebody is blocked
// behind, so the caller answers them whatever the tail looks like. The bytes come from the kernel, but a length
// that does not advance, one past the buffer, or a version this code does not speak stops the walk instead of
// indexing out of range.
func parseEvents(buf []byte) ([]event, error) {
	var out []event
	for off := 0; off < len(buf); {
		rest := buf[off:]
		if len(rest) < metadataLen {
			return out, fmt.Errorf("record at %d is %d bytes, need %d", off, len(rest), metadataLen)
		}
		if v := rest[4]; v != unix.FANOTIFY_METADATA_VERSION {
			return out, fmt.Errorf("record at %d has version %d, this tool speaks %d: %w",
				off, v, unix.FANOTIFY_METADATA_VERSION, errVersion)
		}
		eventLen := binary.NativeEndian.Uint32(rest[0:4])
		metaLen := binary.NativeEndian.Uint16(rest[6:8])
		switch {
		case metaLen < metadataLen:
			return out, fmt.Errorf("record at %d declares metadata_len %d, minimum is %d", off, metaLen, metadataLen)
		case eventLen < uint32(metaLen):
			return out, fmt.Errorf("record at %d declares event_len %d, below its metadata_len %d", off, eventLen, metaLen)
		case uint64(eventLen) > uint64(len(rest)):
			return out, fmt.Errorf("record at %d declares event_len %d, %d bytes remain", off, eventLen, len(rest))
		}
		out = append(out, event{
			Len:  eventLen,
			Mask: binary.NativeEndian.Uint64(rest[8:16]),
			Fd:   int32(binary.NativeEndian.Uint32(rest[16:20])),
			Pid:  int32(binary.NativeEndian.Uint32(rest[20:24])),
		})
		off += int(eventLen)
	}
	return out, nil
}

// encodeResponse is struct fanotify_response: the descriptor the event named, then the response word.
func encodeResponse(fd int32, response uint32) [8]byte {
	var raw [8]byte
	binary.NativeEndian.PutUint32(raw[0:4], uint32(fd))
	binary.NativeEndian.PutUint32(raw[4:8], response)
	return raw
}
