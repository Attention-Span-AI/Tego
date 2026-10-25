// SPDX-License-Identifier: Apache-2.0

// Package askproto is the wire format of a run's ask broker, <ledger_root>/<run>/ask.sock (ADR 0008, ADR 0057,
// ADR 0100 (7)): the frames a person's client and the broker exchange, the error codes and their sentinel errors,
// the limits, and the strict decoders. It is the one definition both sides use: the broker in
// internal/runtime/ask encodes its replies and decodes commands with it, and internal/askclient encodes commands and
// decodes replies with it, for the tego CLI and for tego-control alike.
//
// One exchange is three SOCK_SEQPACKET packets on one connection. The broker sends a hello, {"ready":"<nonce>"},
// with a fresh 32-hex-digit nonce; the client sends one Command carrying that nonce (an alternate answer passes its
// file as the one SCM_RIGHTS descriptor of that packet, and every other packet passes none); the broker sends one
// Response and closes.
//
// A refusal is one error Response and a close, or a close alone, in one of three places:
//
//   - In place of the hello, once the broker has checked the connecting peer (SO_PEERCRED): a peer whose
//     credentials it cannot read, that it does not authorize, or that it cannot open a pidfd for gets an
//     unauthorized Response; a failed credential pass (SO_PASSCRED) gets an unavailable one.
//   - After the hello, in place of the command's answer, once the broker has checked the command packet itself: a
//     packet whose SCM_CREDENTIALS pid is not the connection's or is not authorized, or whose sender has exited, gets
//     an unauthorized Response; a malformed packet or control message, a wrong nonce or a wrong descriptor count gets
//     a protocol one.
//   - No reply at all: a peer that has already exited before the hello, a nonce the broker cannot draw, or a command
//     packet it cannot read ends in a close with no packet, which internal/askclient reads as io.EOF.
//
// A client therefore reads the first packet as either the hello or a refusal, and the second as the answer or a
// refusal. The format moved here from internal/runtime/ask unchanged, byte for byte (TestAskWireGolden holds it to
// frames recorded before the move); it has no version field yet.
//
// Standard library only (Layer 0).
package askproto
