// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"encoding/binary"
	"fmt"
	"structs"
	"unsafe"
)

// ObjectUprobeSSL is bpf/uprobe_ssl.bpf.c: the plaintext capture probes of docs/p0/capture-derive.md §5
// R1-R9. It is the only object that carries the capture maps; the three tier-2 objects compile without them.
const ObjectUprobeSSL Object = "uprobe_ssl"

// Capture map names, pinned by name beside the shared maps under /sys/fs/bpf/tego/<bpf_hash>/maps (§3). The
// capture rings and their counters (MapCaptureEvents, MapCaptureLost, MapCaptureMiss) are shared maps: every
// object declares them, so the tier-2 loader can make a run's capture ring before any capture object loads.
const (
	// MapSSLScratch holds one row per in-flight SSL_read, keyed by SSLKey (R5). Its value is struct
	// tego_ssl_scratch, but the map cannot share that name: bpf2go's -type lookup sees both (maps.h).
	MapSSLScratch = "tego_ssl_reads"
	// MapSSLCurrent maps a thread to the SSL* of its innermost in-flight read, which is how the
	// argument-less uretprobe rebuilds an SSLKey.
	MapSSLCurrent = "tego_ssl_current"
	// MapSSLSeq is each connection's chunk counter, keyed by SSLKey and shared by both directions: every
	// chunk takes the next number before its reserve (I2).
	MapSSLSeq = "tego_ssl_seq"
)

// CaptureMaps lists the maps only ObjectUprobeSSL defines, in pin order.
var CaptureMaps = []string{MapSSLScratch, MapSSLCurrent, MapSSLSeq}

// Program names in ObjectUprobeSSL. Which symbol each attaches to is userspace's choice (R1, R2): the
// object only says what runs once it is there.
const (
	// ProgSSLWrite attaches to SSL_write, whose length argument is an int.
	ProgSSLWrite = "tego_ssl_write"
	// ProgSSLWriteEx attaches to whichever one of SSL_write_ex2 and SSL_write_ex exists (R2), whose
	// length argument is a size_t.
	ProgSSLWriteEx = "tego_ssl_write_ex"
	// ProgSSLRead is the SSL_read entry probe.
	ProgSSLRead = "tego_ssl_read"
	// ProgSSLReadEx is the SSL_read_ex entry probe.
	ProgSSLReadEx = "tego_ssl_read_ex"
	// ProgSSLReadReturn is the uretprobe both reads share; it decides the length by R3's rule.
	ProgSSLReadReturn = "tego_ssl_read_return"
	// ProgSSLFree is the SSL_free entry probe: it says a connection is over, so a new SSL* at the same
	// address starts a new one (R3a).
	ProgSSLFree = "tego_ssl_free"
	// ProgSSLMultiEnter and ProgSSLMultiReturn dispatch the same handlers by
	// attach cookie. Their special attach type is optional on older kernels.
	ProgSSLMultiEnter  = "tego_ssl_multi_enter"
	ProgSSLMultiReturn = "tego_ssl_multi_return"
)

// SSLSinglePrograms is the required individual-probe fallback.
var SSLSinglePrograms = []string{ProgSSLWrite, ProgSSLWriteEx, ProgSSLRead, ProgSSLReadEx, ProgSSLReadReturn, ProgSSLFree}

// SSLPrograms lists the complete object, including optional multi dispatchers.
var SSLPrograms = append(append([]string(nil), SSLSinglePrograms...), ProgSSLMultiEnter, ProgSSLMultiReturn)

// SSL attach cookies are private dispatcher operations, mirrored in the C.
const (
	SSLCookieWrite   uint64 = 1
	SSLCookieWriteEx uint64 = 2
	SSLCookieRead    uint64 = 3
	SSLCookieReadEx  uint64 = 4
	SSLCookieFree    uint64 = 5
)

// SSLEntryPrograms maps each entry probe to the OpenSSL symbols it may be attached to, which is the whole
// of R1-R3 as a table. SSL_read and SSL_read_ex additionally need ProgSSLReadReturn on their return.
var SSLEntryPrograms = map[string][]string{
	ProgSSLWrite:   {"SSL_write"},
	ProgSSLWriteEx: {"SSL_write_ex2", "SSL_write_ex"},
	ProgSSLRead:    {"SSL_read"},
	ProgSSLReadEx:  {"SSL_read_ex"},
	ProgSSLFree:    {"SSL_free"},
}

// Capture sizing, mirrored from bpf/include/events.h (§5 R5, R6).
const (
	// SSLChunkMax is the most plaintext one chunk carries: headroom over the 16 KiB TLSPlaintext
	// fragment RFC 8446 §5.1 fixes, plus verifier-friendly fixed sizing.
	SSLChunkMax = 32768
	// SSLChunksMax is how many chunks one SSL_write or SSL_read is split into; past that the
	// remainder is dropped and the last chunk says so.
	SSLChunksMax = 4
	// SSLScratchMax is the scratch map's row count: one per in-flight read.
	SSLScratchMax = 8192
	// SSLSeqMax is MapSSLSeq's row count: one per (thread, SSL*) that moved plaintext.
	SSLSeqMax = 16384
	// SSLClassSmall and SSLClassMedium are the two smaller data sizes a chunk record is reserved at; the
	// largest is SSLChunkMax. The kernel takes the smallest that holds the chunk, so a stream of small reads
	// costs the ring what it carries (R6).
	SSLClassSmall  = 512
	SSLClassMedium = 4096
	// SSLMaxCallNS bounds the gap between a read's entry and its return probe; a wider pair's buffer is not
	// trusted and the read is emitted as an SSLHoleStale hole (edge case #3). It catches a row whose own
	// return was missed, never a slow answer: 30 minutes is three times the 10-minute default request timeout
	// of the Anthropic and OpenAI SDKs.
	SSLMaxCallNS = 30 * 60 * 1_000_000_000
)

// Why a chunk carries no bytes although its call moved some (enum tego_ssl_hole).
const (
	// SSLHoleNone is a chunk whose Data holds its bytes.
	SSLHoleNone uint8 = 0
	// SSLHoleUnreadable is a chunk whose bytes the probe could not read; Skipped counts them.
	SSLHoleUnreadable uint8 = 1
	// SSLHoleStale is a read whose scratch row was older than SSLMaxCallNS (edge case #3): its buffer was not
	// read, and Skipped is the length the call reported, 0 when that could not be read either.
	SSLHoleStale uint8 = 2
	// SSLHoleEvicted is a read whose scratch row the LRU evicted before its return (R5): its buffer and, for
	// SSL_read_ex, its length are unknown, so Skipped is 0.
	SSLHoleEvicted uint8 = 3
	// SSLHoleNoLength is an SSL_read_ex that returned 1 whose *readbytes the return probe could not read (edge
	// case #13): the call moved bytes, how many is unknown, so Skipped is 0.
	SSLHoleNoLength uint8 = 4
)

// SSL chunk directions (enum tego_ssl_dir).
const (
	// SSLWrite is plaintext the process sent: the request half of a connection.
	SSLWrite uint8 = 0
	// SSLRead is plaintext the process received: the response half.
	SSLRead uint8 = 1
)

// OpenSSL entry points a scratch row can come from (enum tego_ssl_call).
const (
	// SSLCallRead is SSL_read, whose length is the return value when positive.
	SSLCallRead uint8 = 0
	// SSLCallReadEx is SSL_read_ex, whose length is *readbytes when the return is 1.
	SSLCallReadEx uint8 = 1
)

// SSLKey is the scratch map's key: struct tego_ssl_key (R5).
type SSLKey struct {
	_       structs.HostLayout
	PidTgid uint64
	SSLPtr  uint64
}

// SSLScratch is the scratch map's value: struct tego_ssl_scratch.
type SSLScratch struct {
	_ structs.HostLayout
	// Buf is the user pointer the call will fill.
	Buf uint64
	// LenPtr is SSL_read_ex's size_t *readbytes; zero for SSL_read.
	LenPtr uint64
	// EnterNS is bpf_ktime_get_ns() at the entry probe.
	EnterNS uint64
	// Call is SSLCallRead or SSLCallReadEx.
	Call uint8
	Pad  [7]uint8
}

// SSLMeta is struct tego_ev_ssl: the fixed head of a chunk record.
type SSLMeta struct {
	_      structs.HostLayout
	Hdr    Header
	SSLPtr uint64
	// Len is the bytes used in the record's Data, at most SSLChunkMax.
	Len uint32
	// Direction is SSLWrite or SSLRead.
	Direction uint8
	// Truncated is 1 when bytes of this call before Data were lost: an earlier part never reached the ring.
	Truncated uint8
	// Hole says why Len is 0 although the call moved bytes: an SSLHole value.
	Hole uint8
	Pad  uint8
	// Seq is this chunk's number on its (pid_tgid, ssl_ptr), both directions counted together, taken from
	// MapSSLSeq before the reserve: a chunk that never reached the ring leaves a hole the reader finds at
	// the connection's next chunk (I2).
	Seq  uint32
	Pad2 uint32
	// Skipped is how many bytes of this call followed Data and are not on the ring: the tail past
	// SSLChunksMax chunks (R6), or this chunk's own bytes when the probe could not read them.
	Skipped uint64
}

// SSLEvent is struct tego_ev_ssl_chunk: one plaintext chunk at its largest. The kernel reserves a record of
// the head plus SSLClassSmall, SSLClassMedium or SSLChunkMax data bytes, the smallest that holds the chunk, and
// a stale read's hole as the head alone (SSLRecordSizes); Meta.Len says how much of Data is filled and the rest
// is whatever the ring buffer last held, never read.
type SSLEvent struct {
	_    structs.HostLayout
	Meta SSLMeta
	Data [SSLChunkMax]byte
}

// SSLClose is struct tego_ev_ssl_close: the record SSL_free's probe writes when a connection is over
// (R3a).
type SSLClose struct {
	_      structs.HostLayout
	Hdr    Header
	SSLPtr uint64
}

// SSLCloseSize is the wire width of one close record.
const SSLCloseSize = int(unsafe.Sizeof(SSLClose{}))

// DecodeSSLClose validates a close record and returns it. Like DecodeSSLChunk it never panics.
func DecodeSSLClose(b []byte) (SSLClose, error) {
	var out SSLClose
	h, err := parseHeader(b)
	if err != nil {
		return out, err
	}
	if h.Version != EventsVersion {
		return out, fmt.Errorf("%w: %d", ErrVersion, h.Version)
	}
	if Kind(h.Kind) != KindSSLClose {
		return out, fmt.Errorf("%w: %s is not a close record", ErrKind, Kind(h.Kind))
	}
	if int(h.Size) != SSLCloseSize || len(b) < SSLCloseSize {
		return out, fmt.Errorf("%w: close record declares %d bytes and has %d, struct is %d", ErrShortRecord, h.Size,
			len(b), SSLCloseSize)
	}
	out.Hdr = h
	out.SSLPtr = binary.NativeEndian.Uint64(b[HeaderSize : HeaderSize+8])
	return out, nil
}

// SSLEventSize is the wire width of one chunk record.
const SSLEventSize = int(unsafe.Sizeof(SSLEvent{}))

// sslDataOffset is where a chunk record's payload begins.
const sslDataOffset = int(unsafe.Offsetof(SSLEvent{}.Data))

// SSLRecordSizes are the widths a chunk record can have: the head alone (a stale read's hole) and the head
// with each size class of data (R6).
var SSLRecordSizes = [...]int{sslDataOffset, sslDataOffset + SSLClassSmall, sslDataOffset + SSLClassMedium, SSLEventSize}

// sslRecordSize reports whether size is one of SSLRecordSizes.
func sslRecordSize(size int) bool {
	for _, s := range SSLRecordSizes {
		if size == s {
			return true
		}
	}
	return false
}

// sslSkippedOffset and sslSeqOffset are where a chunk record's Skipped and Seq lie.
const (
	sslSkippedOffset = int(unsafe.Offsetof(SSLMeta{}.Skipped))
	sslSeqOffset     = int(unsafe.Offsetof(SSLMeta{}.Seq))
)

// SSLChunk is one decoded chunk record. Data aliases the ring-buffer sample it was decoded from, which the
// kernel reuses as soon as the reader moves on: a caller that keeps the bytes past the next Read copies
// them. Decoding this way rather than into an SSLEvent value is what keeps the drain from copying a whole
// record when the useful part is usually a few hundred bytes.
type SSLChunk struct {
	Hdr       Header
	SSLPtr    uint64
	Direction uint8
	Truncated bool
	// Hole is SSLMeta.Hole: why Data is empty although the call moved bytes.
	Hole uint8
	// Seq is SSLMeta.Seq: the chunk's number on its connection.
	Seq uint32
	// Skipped is SSLMeta.Skipped: bytes of the call after Data that the reader never sees.
	Skipped uint64
	Data    []byte
}

// DecodeSSLChunk validates a capture ring-buffer record and returns it with Data aliasing b. It never
// panics and never allocates: a record whose size is not one of SSLRecordSizes, or whose declared length runs
// past the record itself, is ErrShortRecord rather than a slice out of bounds.
func DecodeSSLChunk(b []byte) (SSLChunk, error) {
	var out SSLChunk
	h, err := parseHeader(b)
	if err != nil {
		return out, err
	}
	if h.Version != EventsVersion {
		return out, fmt.Errorf("%w: %d", ErrVersion, h.Version)
	}
	if Kind(h.Kind) != KindSSLChunk {
		return out, fmt.Errorf("%w: %s is not a chunk record", ErrKind, Kind(h.Kind))
	}
	size := int(h.Size)
	if !sslRecordSize(size) {
		return out, fmt.Errorf("%w: chunk declares %d bytes, a record is one of %v", ErrShortRecord, h.Size,
			SSLRecordSizes)
	}
	if len(b) < size {
		return out, fmt.Errorf("%w: chunk needs %d bytes, got %d", ErrShortRecord, size, len(b))
	}
	o := binary.NativeEndian
	out.Hdr = h
	out.SSLPtr = o.Uint64(b[HeaderSize : HeaderSize+8])
	length := o.Uint32(b[HeaderSize+8 : HeaderSize+12])
	out.Direction = b[HeaderSize+12]
	out.Truncated = b[HeaderSize+13] != 0
	out.Hole = b[HeaderSize+14]
	out.Skipped = o.Uint64(b[sslSkippedOffset : sslSkippedOffset+8])
	out.Seq = o.Uint32(b[sslSeqOffset : sslSeqOffset+4])
	if uint64(length) > uint64(size-sslDataOffset) {
		return out, fmt.Errorf("%w: chunk declares %d bytes of plaintext in a %d-byte record", ErrShortRecord, length,
			size)
	}
	if out.Direction != SSLWrite && out.Direction != SSLRead {
		return out, fmt.Errorf("%w: chunk direction %d", ErrKind, out.Direction)
	}
	out.Data = b[sslDataOffset : sslDataOffset+int(length)]
	return out, nil
}
