#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Same-process, preconnected namespace answers for the disposable guest only."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import socket
import struct
import sys
import time


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def facts():
    stat = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()
    return dict(pid=os.getpid(), uid=os.getuid(),
                start_boot_ns=int(stat[19]) * (1000000000 // os.sysconf("SC_CLK_TCK")),
                user_namespace=os.stat("/proc/self/ns/user").st_ino,
                cgroup_namespace=os.stat("/proc/self/ns/cgroup").st_ino,
                cgroup=Path("/proc/self/cgroup").read_text())


def namespace_call(name, value):
    libc = ctypes.CDLL(None, use_errno=True)
    call = getattr(libc, name)
    if call(value) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def enter(kind, governed):
    if kind == "user":
        namespace_call("unshare", 0x10000000)
        Path("/proc/self/setgroups").write_text("deny\n")
        Path("/proc/self/uid_map").write_text("0 0 1\n")
        Path("/proc/self/gid_map").write_text("0 0 1\n")
    elif kind == "cgroup":
        namespace_call("unshare", 0x02000000)
    elif kind == "governed":
        Path(governed, "cgroup.procs").write_text(str(os.getpid()) + "\n")
    else:
        raise ValueError("unknown namespace transition")


def restore(fd):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.setns(fd, 0x02000000) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def wait_packet(directory):
    deadline = time.monotonic() + 5
    entered = Path(directory, "packet-entered")
    while time.monotonic() < deadline:
        if entered.exists():
            require(entered.read_text() == "after-packet\n", "wrong broker barrier phase")
            return
        time.sleep(.01)
    raise AssertionError("broker did not capture packet before namespace transition")


def resumed(directory):
    Path(directory, "packet-resume").write_text("resume\n")


def validate_transition(before, after, kind, governed):
    require(after["pid"] == before["pid"] and after["start_boot_ns"] == before["start_boot_ns"],
            "namespace answer switched sending process")
    require(after["uid"] == 0, "namespace sender is not mapped real root")
    if kind in ("user", "cgroup"):
        key = kind + "_namespace"
        require(after[key] != before[key], "namespace did not change")
    else:
        expected = str(governed).removeprefix("/sys/fs/cgroup")
        require(after["cgroup"] == "0::" + expected + "\n", "sender did not enter governed descendant")


def validate_reply(reply, ask, approve, admitted):
    if admitted:
        decision = reply.get("decision", {})
        require(not reply.get("error") and not reply.get("code")
                and decision.get("ask_id") == ask and decision.get("approved") is approve,
                "restored host root did not receive its exact admitted decision")
    else:
        require(reply.get("code") == "owner-only"
                and "only root may answer once" in reply.get("error", "")
                and not reply.get("decision"), "missing actual broker owner-only response")
        require("permission denied" not in reply["error"].lower()
                and "operation not permitted" not in reply["error"].lower(),
                "filesystem or namespace setup refusal cannot qualify broker admission")


def witness(directory, launcher, ask, approve, kind, mode, barrier, governed=None):
    before = facts()
    saved = os.open("/proc/self/ns/cgroup", os.O_RDONLY) if mode == "send-restore" else None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
            connection.settimeout(10)
            # Connect and verify initial root admission before losing DAC override.
            connection.connect(str(Path(directory) / "ask.sock"))
            pid, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(pid == launcher and uid == 0, "socket is not the driver's actual root launcher")
            hello = json.loads(connection.recv(65536))
            require(len(hello.get("ready", "")) == 32 and not hello.get("error"),
                    "initial root did not receive broker ready before namespace entry")
            if mode in ("private", "send-restore"):
                enter(kind, governed)
                validate_transition(before, facts(), kind, governed)
            sent = facts()
            packet = dict(action="answer", nonce=hello["ready"], ask_id=ask, approve=approve)
            connection.send(json.dumps(packet).encode())
            if mode != "private":
                wait_packet(barrier)
                if mode == "send-restore":
                    restore(saved)
                    require(facts()["cgroup_namespace"] == before["cgroup_namespace"],
                            "sender failed to restore its initial cgroup namespace")
                else:
                    enter(kind, governed)
                    validate_transition(before, facts(), kind, governed)
            decided = facts()
            require(decided["pid"] == before["pid"] and decided["start_boot_ns"] == before["start_boot_ns"],
                    "decision facts switched sending process")
            if mode != "private":
                resumed(barrier)
            reply = json.loads(connection.recv(65536))
            validate_reply(reply, ask, approve, mode == "send-restore")
            return dict(before=before, sent=sent, decision=decided, approve=approve,
                        broker_response=reply, connected_before_namespace=True)
    finally:
        if saved is not None:
            os.close(saved)


def main():
    if sys.argv[1:] == ["--self-check"]:
        # Import the host controls only for the explicit host-safe entry point.
        import runpy
        runpy.run_path(str(Path(__file__).with_name("local-roles-namespace_test.py")), run_name="roles_namespace_controls")["self_check"]()
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory")
    parser.add_argument("launcher", type=int)
    parser.add_argument("ask")
    parser.add_argument("decision", choices=("approve", "deny"))
    parser.add_argument("kind", choices=("user", "cgroup", "governed"))
    parser.add_argument("--mode", choices=("private", "send-restore", "enter-after-send"), default="private")
    parser.add_argument("--barrier", type=Path)
    parser.add_argument("--governed", type=Path)
    parser.add_argument("--identity", type=Path)
    args = parser.parse_args()
    require(os.getuid() == 0 and os.environ.get("TEGO_DISPOSABLE_HOST") == "kvm"
            and Path("/run/roles1-guest").is_file(), "requires explicit disposable guest root")
    require(args.mode != "send-restore" or args.kind == "cgroup", "restore requires cgroup namespace")
    evidence = witness(args.directory, args.launcher, args.ask, args.decision == "approve",
                       args.kind, args.mode, args.barrier, args.governed)
    if args.identity:
        args.identity.write_text(json.dumps(evidence["decision"]) + "\n")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
