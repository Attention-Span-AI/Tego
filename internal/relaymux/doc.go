// SPDX-License-Identifier: Apache-2.0

// Package relaymux is the framed multiplex the Windows dashboard relay speaks over one long-lived wsl.exe child's
// standard input and output (docs/adr/0123-dashboard-threat-model.md, "A browser on Windows"). Every browser
// connection the Windows end accepts is one stream; the Linux end makes one loopback connection to the dashboard
// per stream. One pipe carries all of them, because each new wsl.exe costs about a second.
//
// A frame is a type byte, a 4-byte stream id and a 4-byte payload length (both big-endian), then the payload:
// HELLO (stream 0, both ends, first: the protocol magic and, from the Linux end, the dashboard port it serves),
// OPEN (Windows end only), DATA, WINDOW (credit returned), CLOSEWRITE (half-close), CLOSE (abort, with a short
// reason) and GOAWAY (stream 0: the sender ends the session, with a reason). Each stream has its own send window:
// a sender may have at most Window bytes of DATA unacknowledged, and the receiver returns credit only as it hands
// the bytes on, so one slow stream holds back only itself while the pipe keeps moving for the others. The reader
// never blocks on a stream: it buffers at most the window it granted. A peer that sends past its window, an
// oversized or unknown frame, a second OPEN of a live id or anything before HELLO ends the whole session: it fails
// closed.
//
// The pure frame codec (ReadFrame, AppendFrame) is fuzzed; Session is the stream layer on top of it. Session's
// goroutines (one reader, plus the caller's) end when the pipe ends or Close is called.
//
// Imports: standard library only
// Must not import: any other package of this module
package relaymux
