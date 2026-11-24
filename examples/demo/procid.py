#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Which process a demo helper's pid file names, and whether it is still the one the demo started.

A pid number alone says nothing: the process may have ended and the number been given to another program, and a
process can be alive and be something else. The demo writes each helper's file as "<pid> <start time>" (the start
time is field 22 of /proc/<pid>/stat, in clock ticks since boot, which a reused pid cannot share), and trusts the
file only when the process with that pid

  - still has that start time,
  - runs the helper's own script (an element of its argument list is that exact path), and
  - for the sink, holds the listening socket on 127.0.0.1:<port> (found by the socket's inode in its open files).

   procid.py stamp PID            prints "<pid> <start time>"; exit 1 when there is no such process
   procid.py ours FILE SCRIPT [PORT]  exit 0 when FILE names a process that passes all of the above
   procid.py stop FILE SCRIPT [PORT]  SIGTERM to that process when it passes, else nothing. Exit 0: it was sent; 10: FILE
                                  names no live process (no file, a file with no pid, a process that has ended); 11: it
                                  names a live process that does not pass, which is left running

It reads /proc only. Any doubt (a missing file, an unreadable entry, a second field that is no number) is "not ours".
"""
import os, signal, sys


def start_time(pid):
    try:
        with open("/proc/%d/stat" % pid, "rb") as f:
            data = f.read().decode("utf-8", "replace")
    except OSError:
        return None
    # The command name is in parentheses and may hold spaces and parentheses: the fields start after the last ")".
    rest = data[data.rfind(")") + 1:].split()
    return rest[19] if len(rest) > 19 and rest[19].isdigit() else None  # field 22 overall, the 20th after the name


def argv_of(pid):
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as f:
            return [a.decode("utf-8", "replace") for a in f.read().split(b"\0") if a]
    except OSError:
        return []


def listener_inodes(port):
    want = "0100007F:%04X" % port
    out = set()
    try:
        with open("/proc/net/tcp") as f:
            next(f, None)
            for line in f:
                p = line.split()
                if len(p) > 9 and p[1] == want and p[3] == "0A":  # LISTEN
                    out.add(p[9])
    except OSError:
        pass
    return out


def holds_listener(pid, port):
    inodes = listener_inodes(port)
    if not inodes:
        return False
    try:
        for fd in os.listdir("/proc/%d/fd" % pid):
            try:
                link = os.readlink("/proc/%d/fd/%s" % (pid, fd))
            except OSError:
                continue
            if link.startswith("socket:[") and link[8:-1] in inodes:
                return True
    except OSError:
        return False
    return False


def ours(path, script, port):
    try:
        with open(path) as f:
            fields = f.read().split()
    except OSError:
        return None
    if len(fields) != 2 or not fields[0].isdigit() or not fields[1].isdigit():
        return None
    pid = int(fields[0])
    if pid <= 1 or start_time(pid) != fields[1] or script not in argv_of(pid):
        return None
    if port is not None and not holds_listener(pid, port):
        return None
    return pid


def stop(path, script, port):
    """0 when SIGTERM was sent to the helper FILE names, 10 when it names no live process, 11 when the process it
    names is alive and is not the helper (nothing is sent to it)."""
    try:
        with open(path) as f:
            fields = f.read().split()
    except OSError:
        return 10
    if not fields or not fields[0].isdigit() or int(fields[0]) <= 1:
        return 10
    if not os.path.isdir("/proc/%s" % int(fields[0])):
        return 10
    pid = ours(path, script, port)
    if not pid:
        return 11
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return 11 if os.path.isdir("/proc/%d" % pid) else 10
    return 0


def main(argv):
    if len(argv) == 3 and argv[1] == "stamp" and argv[2].isdigit():
        st = start_time(int(argv[2]))
        if st is None:
            return 1
        print(argv[2], st)
        return 0
    if len(argv) in (4, 5) and argv[1] in ("ours", "stop"):
        port = int(argv[4]) if len(argv) == 5 and argv[4].isdigit() else None
        if argv[1] == "ours":
            return 0 if ours(argv[2], argv[3], port) else 1
        return stop(argv[2], argv[3], port)
    print(__doc__.split("\n\n")[0], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
