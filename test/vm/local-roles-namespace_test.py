#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host-safe controls for preconnected namespace witnesses; no namespace calls."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("local-roles-namespace.py")
SPEC = importlib.util.spec_from_file_location("roles_namespace", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def scenario(kind="user", mode="private", approve=True, fault=None):
    state = dict(pid=61, start_boot_ns=10000000, uid=0, user_namespace=10,
                 cgroup_namespace=20, cgroup="0::/outside\n")
    events = []
    hello = dict(ready="a" * 32)
    reply = dict(code="owner-only", error="only root may answer once; request remains pending")
    if mode == "send-restore":
        reply = dict(decision=dict(ask_id="q-one", approved=approve))
    if fault == "not-ready":
        hello = dict(error="permission denied")
    elif fault == "wrong-code":
        reply["code"] = "unavailable"
    elif fault == "filesystem":
        reply["error"] = "only root may answer once: permission denied"
    elif fault == "success":
        reply = dict(decision=dict(ask_id="q-one", approved=approve))
    elif fault == "wrong-ask":
        reply["decision"]["ask_id"] = "other"
    elif fault == "wrong-decision":
        reply["decision"]["approved"] = not approve

    class Connection:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def settimeout(self, timeout): pass
        def connect(self, path):
            if fault == "connect-filesystem":
                raise PermissionError("permission denied")
            events.append("connect")
        def getsockopt(self, *args):
            return struct.pack("3i", 999 if fault == "wrong-launcher" else 100, 0, 0)
        def recv(self, size):
            if "ready" not in events:
                MODULE.require(events == ["connect"], "namespace changed before broker ready")
                events.append("ready")
                return json.dumps(hello).encode()
            MODULE.require("send" in events, "response requested before packet")
            if fault == "missing-reply": return b""
            if mode != "private": MODULE.require(events[-1] == "resume", "reply requested before state publication")
            return json.dumps(reply).encode()
        def send(self, packet):
            decoded = json.loads(packet)
            MODULE.require(decoded == dict(action="answer", nonce="a" * 32, ask_id="q-one", approve=approve), "wrong actual answer packet")
            if mode in ("private", "send-restore"):
                MODULE.require(events[-1] == "enter", "packet was not sent inside namespace")
            else:
                MODULE.require(events[-1] == "ready", "packet was not sent outside namespace")
            events.append("send")

    def enter(kind, governed):
        MODULE.require(bool(events) and events[-1] == ("ready" if mode in ("private", "send-restore") else "barrier"),
                       "namespace entered before preconnection or packet barrier")
        if fault == "setup": raise PermissionError("operation not permitted")
        if fault != "unchanged":
            if kind == "governed": state["cgroup"] = "0::/governed/child\n"
            else: state[kind + "_namespace"] += 1
        if fault == "other-process": state["pid"] += 1
        events.append("enter")

    def wait_packet(directory):
        MODULE.require(events[-1] == "send", "barrier before packet")
        if fault == "no-barrier": raise AssertionError("broker did not capture packet")
        events.append("barrier")

    def restore(fd):
        MODULE.require(events[-1] == "barrier", "restore before broker captured packet")
        if fault != "bad-restore": state["cgroup_namespace"] = 20
        events.append("restore")

    def resume(directory):
        MODULE.require(events[-1] == ("restore" if mode == "send-restore" else "enter"), "resume before transition")
        events.append("resume")

    with patch.object(MODULE.socket, "socket", return_value=Connection()), \
            patch.object(MODULE, "facts", side_effect=lambda: copy.deepcopy(state)), \
            patch.object(MODULE, "enter", side_effect=enter), \
            patch.object(MODULE, "restore", side_effect=restore), \
            patch.object(MODULE, "wait_packet", side_effect=wait_packet), \
            patch.object(MODULE, "resumed", side_effect=resume):
        return MODULE.witness("/not-opened", 100, "q-one", approve, kind, mode,
                              "/not-opened", "/sys/fs/cgroup/governed/child")


def self_check():
    for approve in (True, False):
        for kind in ("user", "cgroup"):
            scenario(kind, approve=approve)
        for kind in ("user", "cgroup", "governed"):
            scenario(kind, mode="enter-after-send", approve=approve)
        scenario("cgroup", mode="send-restore", approve=approve)
    cases = [(fault, "user", "private") for fault in (
        "connect-filesystem", "not-ready", "wrong-launcher", "wrong-code", "filesystem",
        "success", "missing-reply", "setup", "unchanged", "other-process")]
    cases += [(fault, "cgroup", "send-restore") for fault in (
        "bad-restore", "no-barrier", "wrong-ask", "wrong-decision")]
    for fault, kind, mode in cases:
        try:
            scenario(kind, mode, fault=fault)
        except (AssertionError, OSError, ValueError):
            print("namespace-" + fault + "\tFAIL (expected)")
        else:
            raise AssertionError("self-check accepted wrong namespace outcome: " + fault)
    print("NAMESPACE-SELF-CHECK-DONE: " + str(len(cases)) + " wrong outcomes rejected")


if __name__ == "__main__":
    self_check()
