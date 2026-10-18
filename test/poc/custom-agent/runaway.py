#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""runaway.py -- the second custom agent: one that misbehaves differently (README.md). Each MODE is one way a long
unattended run goes wrong, and every one is SAFE: it is bounded by its own cap whatever the contract says, so a run
without the limit that should stop it ends by itself, small, and says it was not stopped.

    loop      no progress: asks the model, gets the same answer, runs the same failing test, asks again
              (the model script is `model_script.py loop`: the same tool call every turn). Stopped by limits.repeats.
    hang      works for a while, then blocks forever on a pipe nothing writes to: no event at all.
              Stopped by limits.stall_after. (Own cap: --seconds, by SIGALRM.)
    read      busy but quiet: reads a file over and over, never writes, starts nothing, connects to nothing.
              Under `record: full` every read is an event; under `record: summary` none is, and stall_after
              reads the agent as silent. (Own cap: --seconds.)
    memhog    allocates and touches --step-mib at a time up to --cap-mib (default 96, hard cap 256).
              Stopped by limits.memory (the kernel's OOM kill inside the run's cgroup).
    forkbomb  a stand-in: forks children that only sleep, up to --cap (default 60, hard cap 200), and stops at the
              first refused fork. Stopped by limits.pids. Children sleep --hold seconds and are reaped.
    cpu       a busy loop for --seconds (default 6); with limits.cpu the kernel throttles it.
    flood     opens and reads one file --count times (default 20000, at most 200000): a measure of what recording an
              open costs the agent, not a misbehaviour.
    direct    connects straight to 127.0.0.1:--port, the model's own address, going round the forwarder.

Usage: runaway.py MODE [--seconds S] [--cap N] [--step-mib N] [--cap-mib N] [--hold S] [--max-steps N] [--count N] [--port N]
Exit status: 0 when it ran to its own end (that is: nothing stopped it), 3 when a request could not be satisfied.
"""
import argparse
import os
import signal
import socket
import subprocess
import sys
import time

sys.dont_write_bytecode = True  # `import agent` must not try to write a .pyc beside it: the workspace is not writable
import agent  # noqa: E402  (the model client and the loop's shape are the custom agent's)


def say(msg):
    print("runaway: " + msg, flush=True)


def mode_loop(a):
    model = agent.Model(os.environ["ANTHROPIC_BASE_URL"], os.environ.get("ANTHROPIC_API_KEY", "stub-key"))
    messages = [{"role": "user", "content": "Fix the failing test."}]
    with open("work/repo/src/mod_01.py", "a") as f:
        f.write("# FIXME(runaway): wrong result\n")  # a failing test the loop can never fix
    for step in range(1, a.max_steps + 1):
        try:
            reply = model.ask(messages)
        except agent.ModelError as e:
            say("the model cannot be reached: %s" % e)
            return 3
        messages.append({"role": "assistant", "content": reply["content"]})
        calls = [b for b in reply["content"] if b.get("type") == "tool_use"]
        if not calls:
            say("the model stopped asking: step %d" % step)
            return 0
        r = subprocess.run(["bash", "tests/run_tests.sh"], cwd="work/repo", capture_output=True, text=True, timeout=30)
        messages.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": c["id"], "content": (r.stdout.strip() or "ok")[:100]} for c in calls]})
        if step % 5 == 0:
            say("step %d: still running %s, no progress" % (step, calls[0]["name"]))
        time.sleep(a.sleep)
    say("NOT STOPPED: %d identical steps, ending by my own cap" % a.max_steps)
    return 0


def not_stopped(_sig, _frame):
    say("NOT STOPPED: still blocked when my own cap ended me")
    sys.exit(0)


def mode_hang(a):
    signal.signal(signal.SIGALRM, not_stopped)
    signal.alarm(a.seconds)  # the bound: SIGALRM ends the process whatever else happens
    for _ in range(3):
        open("work/notes.md", "a").write("working\n")  # a little real activity first
        time.sleep(0.2)
    say("hanging now: waiting on a pipe nothing will write to (own cap %ds)" % a.seconds)
    r, _w = os.pipe()
    os.read(r, 1)
    return 0


def mode_read(a):
    end = time.monotonic() + a.seconds
    n = 0
    while time.monotonic() < end:
        with open("work/repo/src/mod_01.py", "rb") as f:
            f.read()
        n += 1
        time.sleep(0.02)
    say("NOT STOPPED: read a file %d times in %ds, ending by my own cap" % (n, a.seconds))
    return 0


def mode_memhog(a):
    cap = min(a.cap_mib, 256)
    held = []
    for i in range(1, cap // a.step_mib + 1):
        chunk = bytearray(a.step_mib << 20)
        for off in range(0, len(chunk), 4096):
            chunk[off] = 1  # touch every page: untouched memory is not resident
        held.append(chunk)
        say("holding %d MiB" % (i * a.step_mib))
        time.sleep(0.15)
    say("NOT STOPPED: reached my own cap of %d MiB" % cap)
    time.sleep(a.hold)
    return 0


def mode_forkbomb(a):
    cap = min(a.cap, 200)
    kids = []
    refused = None
    for _ in range(cap):
        try:
            pid = os.fork()
        except OSError as e:
            refused = e
            break
        if pid == 0:
            time.sleep(a.hold)
            os._exit(0)
        kids.append(pid)
    if refused:
        say("fork refused after %d children: %s" % (len(kids), refused))
    else:
        say("NOT STOPPED: started %d children, my own cap" % len(kids))
    for pid in kids:
        os.waitpid(pid, 0)
    return 0


def mode_cpu(a):
    end = time.monotonic() + a.seconds
    n = 0
    while time.monotonic() < end:
        n += 1
    t = os.times()
    say("busy for %ds of wall time, used %.2fs of cpu" % (a.seconds, t.user + t.system))
    return 0


def mode_flood(a):
    n = min(a.count, 200000)
    start = time.monotonic()
    for _ in range(n):
        with open("work/repo/src/mod_01.py", "rb") as f:
            f.read()
    took = time.monotonic() - start
    say("%d opens in %.2f s = %.1f us each" % (n, took, took / n * 1e6))
    return 0


def mode_direct(a):
    try:
        socket.create_connection(("127.0.0.1", a.port), timeout=3).close()
    except OSError as e:
        say("a direct connection to the model's own address 127.0.0.1:%d was refused (errno %s)" % (a.port, e.errno))
        return 0
    say("a direct connection to the model's own address 127.0.0.1:%d was ALLOWED" % a.port)
    return 0


MODES = {"loop": mode_loop, "hang": mode_hang, "read": mode_read, "memhog": mode_memhog, "forkbomb": mode_forkbomb,
         "cpu": mode_cpu, "flood": mode_flood, "direct": mode_direct}


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("mode", choices=sorted(MODES))
    p.add_argument("--seconds", type=int, default=6, help="hang, read, cpu: the mode's own cap")
    p.add_argument("--max-steps", type=int, default=60, help="loop: the mode's own cap")
    p.add_argument("--sleep", type=float, default=0.15, help="loop: seconds between steps")
    p.add_argument("--cap", type=int, default=60, help="forkbomb: children, at most 200")
    p.add_argument("--hold", type=float, default=4, help="forkbomb, memhog: seconds the children or the memory live")
    p.add_argument("--count", type=int, default=20000, help="flood: opens, at most 200000")
    p.add_argument("--port", type=int, default=9, help="direct: the port of 127.0.0.1 to connect to")
    p.add_argument("--step-mib", type=int, default=8)
    p.add_argument("--cap-mib", type=int, default=96, help="memhog: at most 256")
    a = p.parse_args()
    sys.exit(MODES[a.mode](a))


if __name__ == "__main__":
    main()
