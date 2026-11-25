#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Safety checks for the disposable source-overlay builder, with no binary run."""

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("local-roles-fault-overlay.py")
SPEC = importlib.util.spec_from_file_location("roles_overlay", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class OverlayTests(unittest.TestCase):
    def setUp(self):
        # TEGO_ROLES_SCRATCH names a disk-backed parent for the case folders; unset, the system temporary folder is used.
        scratch = os.environ.get("TEGO_ROLES_SCRATCH") or None
        if scratch:
            Path(scratch).mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "tree"
        self.source = self.root / "internal/ledger/approval.go"
        self.source.parent.mkdir(parents=True)
        self.original = (SCRIPT.parents[2] / "internal/ledger/approval.go").read_text()
        self.source.write_text(self.original)
        self.socket = self.root / "internal/runtime/ask/socket.go"
        self.socket.parent.mkdir(parents=True)
        self.socket_original = (SCRIPT.parents[2] / "internal/runtime/ask/socket.go").read_text()
        self.socket.write_text(self.socket_original)

    def test_source_is_preserved_and_overlay_is_explicit(self):
        out = Path(self.temp.name) / "adapter"
        overlay = MODULE.generate(self.root, out)
        replacements = json.loads(overlay.read_text())["Replace"]
        self.assertEqual(replacements, {str(self.source): str(out / "approval.go")})
        self.assertEqual(self.source.read_text(), self.original)
        changed = (out / "approval.go").read_text()
        self.assertEqual(changed.count("return w.syncRequired()"), 2)
        self.assertIn('os.Getenv("TEGO_DISPOSABLE_HOST") != "kvm"', changed)
        self.assertIn('os.Lstat("/run/roles1-guest")', changed)

    def test_negative_witness_weakens_append_only(self):
        out = Path(self.temp.name) / "negative"
        MODULE.generate(self.root, out, negative_sync=True)
        changed = (out / "approval.go").read_text()
        self.assertEqual(changed.count("return w.syncRequired()"), 1)
        self.assertIn("deliberate qualification mutant", changed)
        self.assertEqual(self.source.read_text(), self.original)

    def test_broker_witness_copies_only_actual_error_replies(self):
        out = Path(self.temp.name) / "broker"
        replacements = MODULE.generate_broker_witness(self.root, out)
        self.assertEqual(replacements, {str(self.socket): str(out / "socket.go")})
        self.assertEqual(self.socket.read_text(), self.socket_original)
        changed = (out / "socket.go").read_text()
        self.assertIn('func (s *server) reply(c *net.UnixConn, r response) {\n\trolesGuestReplyWitness(c, r, s.packetPIDFD)', changed)
        self.assertIn('r.Code == "" { return }', changed)
        self.assertIn('unix.SO_PEERCRED', changed)
        self.assertIn('peer_pid', changed)
        self.assertIn('peer_uid', changed)
        self.assertIn('panic("broker witness append")', changed)
        # a refusal written to a connection the broker's shutdown closed reaches no one: not a witness failure
        self.assertIn('if errors.Is(err, net.ErrClosed) { return }', changed)
        self.assertLess(changed.index('if errors.Is(err, net.ErrClosed) { return }'), changed.index('panic("broker witness peer")'))
        self.assertNotIn('r.Ready', MODULE.BROKER_WITNESS)
        self.assertNotIn('r.Decision', MODULE.BROKER_WITNESS)
        barrier = changed.index('\trolesGuestPacketBarrier(buf[:n])\n')
        self.assertLess(changed.index('writer.PID != connectionPeer.PID'), barrier)
        self.assertLess(barrier, changed.index('now, nowStarted, err := s.identify(c)'))
        self.assertIn('packet-entered', changed)
        self.assertIn('packet-resume', changed)
        self.assertIn('cmd.Action != "answer" { return }', changed)
        self.assertIn('mode == "after-packet"', MODULE.HOOK)

    def test_post_packet_identity_source_change_refuses_generation(self):
        self.socket.write_text(self.socket_original.replace('now, nowStarted, err := s.identify(c)', 'now, nowStarted, err := changedIdentify(c)'))
        with self.assertRaisesRegex(ValueError, "post-packet identity read changed"):
            MODULE.generate_broker_witness(self.root, Path(self.temp.name) / "refused-barrier")

    def test_broker_reply_source_change_refuses_generation(self):
        self.socket.write_text(self.socket_original.replace('func (s *server) reply(', 'func (s *server) changedReply('))
        with self.assertRaisesRegex(ValueError, "broker reply changed"):
            MODULE.generate_broker_witness(self.root, Path(self.temp.name) / "refused-broker")

    def test_changed_source_refuses_generation(self):
        self.source.write_text(self.original.replace("w.appendNext(e)", "w.changedAppend(e)"))
        out = Path(self.temp.name) / "refused"
        with self.assertRaisesRegex(ValueError, "AppendSync changed"):
            MODULE.generate(self.root, out)
        self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
