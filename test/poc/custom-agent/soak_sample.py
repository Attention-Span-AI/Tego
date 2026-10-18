#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""soak_sample.py -- the soak's sampler (soak.sh, README.md). Every INTERVAL seconds it appends one row to samples.csv:
what tego and the agent cost right now (resident memory, cpu, open descriptors, threads) and what the ledger has
become (bytes, directory size, events by kind). It reads /proc, the run's cgroup and the ledger; it signals nothing.

Resumable: it counts the ledger's lines incrementally (the offset and counts are kept in kinds.json, per run), so a
sampler that was killed and started again carries on with the same file and the same totals.

Usage: soak_sample.py ARMDIR RUN_ID TEGO_PID SEGMENT DEADLINE_EPOCH [INTERVAL]
It stops when tego's process is gone (after one last row) or at DEADLINE_EPOCH.
"""
import json
import os
import sys
import time

COLS = ["ts", "elapsed_s", "segment", "run", "tego_alive", "tego_rss_kb", "tego_hwm_kb", "tego_threads",
        "tego_fds", "tego_cpu_s", "agent_alive", "agent_rss_kb", "agent_tree_rss_kb", "agent_procs", "agent_fds",
        "cg_cpu_s", "cg_mem_kb", "cg_mem_peak_kb", "cg_pids", "agent_steps", "ledger_bytes", "ledger_dir_kb",
        "events", "ev_fs", "ev_exec", "ev_net", "ev_refused", "ev_model", "ev_gap", "ev_other", "disk_free_kb"]
TICK = os.sysconf("SC_CLK_TCK")
KINDS = {"fs": "ev_fs", "exec": "ev_exec", "net": "ev_net", "refused": "ev_refused", "ssl_request": "ev_model",
         "gap": "ev_gap"}


def status_kb(pid, key):
    try:
        with open("/proc/%d/status" % pid) as f:
            for line in f:
                if line.startswith(key + ":"):
                    return int(line.split()[1])
    except OSError:
        pass
    return -1


def cpu_s(pid):
    try:
        with open("/proc/%d/stat" % pid) as f:
            rest = f.read().rsplit(")", 1)[1].split()
        return (int(rest[11]) + int(rest[12])) / TICK  # utime + stime
    except (OSError, IndexError, ValueError):
        return -1


def nfds(pid):
    try:
        return len(os.listdir("/proc/%d/fd" % pid))
    except OSError:
        return -1


def alive(pid):
    try:
        with open("/proc/%d/stat" % pid) as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def children(pid):
    out = []
    for d in os.listdir("/proc"):
        if d.isdigit():
            try:
                with open("/proc/%s/stat" % d) as f:
                    if int(f.read().rsplit(")", 1)[1].split()[1]) == pid:
                        out.append(int(d))
            except (OSError, ValueError, IndexError):
                pass
    return out


def cmdline(pid):
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as f:
            return f.read().replace(b"\0", b" ").decode(errors="replace")
    except OSError:
        return ""


def cgroup_dir(pid):
    try:
        with open("/proc/%d/cgroup" % pid) as f:
            for line in f:
                if line.startswith("0::"):
                    return "/sys/fs/cgroup" + line[3:].strip()
    except OSError:
        pass
    return None


def read_int(path):
    try:
        with open(path) as f:
            return int(f.read().split()[0])
    except (OSError, ValueError, IndexError):
        return -1


def cg_usage_s(cg):
    try:
        with open(os.path.join(cg, "cpu.stat")) as f:
            for line in f:
                if line.startswith("usage_usec"):
                    return int(line.split()[1]) / 1e6
    except (OSError, ValueError):
        pass
    return -1


def dir_kb(path):
    total = 0
    for root, _dirs, files in os.walk(path):
        for n in files:
            try:
                total += os.lstat(os.path.join(root, n)).st_blocks * 512
            except OSError:
                pass
    return total // 1024


def last_line(path, size=16384):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            n = f.tell()
            f.seek(max(0, n - size))
            lines = f.read().splitlines()
        return lines[-1].decode(errors="replace") if lines else ""
    except OSError:
        return ""


class Counter:
    """Counts a ledger's lines by kind, reading only what was appended since the last call."""

    def __init__(self, ledger, state_path):
        self.ledger, self.state_path = ledger, state_path
        self.offset, self.total, self.kinds = 0, 0, {}
        try:
            with open(state_path) as f:
                s = json.load(f)
            if s.get("ledger") == ledger and s["offset"] <= os.path.getsize(ledger):
                self.offset, self.total, self.kinds = s["offset"], s["total"], s["kinds"]
        except (OSError, ValueError, KeyError):
            pass

    def update(self):
        try:
            with open(self.ledger, "rb") as f:
                f.seek(self.offset)
                while True:
                    line = f.readline()
                    if not line.endswith(b"\n"):
                        break  # the writer is mid-line: read it next time
                    self.offset += len(line)
                    self.total += 1
                    i = line.find(b'"kind":"')
                    if i >= 0:
                        k = line[i + 8:line.find(b'"', i + 8)].decode()
                        self.kinds[k] = self.kinds.get(k, 0) + 1
        except OSError:
            pass
        tmp = self.state_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"ledger": self.ledger, "offset": self.offset, "total": self.total, "kinds": self.kinds}, f)
        os.replace(tmp, self.state_path)


def sample(arm, run, ev_pid, seg, t0, counter, ledger_dir, ledger):
    now = time.time()
    row = dict.fromkeys(COLS, -1)
    row.update(ts=int(now), elapsed_s=int(now - t0), segment=seg, run=run, tego_alive=int(alive(ev_pid)))
    if row["tego_alive"]:
        row.update(tego_rss_kb=status_kb(ev_pid, "VmRSS"), tego_hwm_kb=status_kb(ev_pid, "VmHWM"),
                   tego_threads=status_kb(ev_pid, "Threads"), tego_fds=nfds(ev_pid), tego_cpu_s=cpu_s(ev_pid))
        agent = next((c for c in children(ev_pid) if "agent.py" in cmdline(c)), None)
        row["agent_alive"] = int(agent is not None)
        if agent:
            row.update(agent_rss_kb=status_kb(agent, "VmRSS"), agent_fds=nfds(agent))
            cg = cgroup_dir(agent)
            if cg:
                procs = []
                try:
                    with open(os.path.join(cg, "cgroup.procs")) as f:
                        procs = [int(x) for x in f.read().split()]
                except (OSError, ValueError):
                    pass
                row.update(agent_procs=len(procs), agent_tree_rss_kb=sum(max(status_kb(p, "VmRSS"), 0) for p in procs),
                           cg_cpu_s=cg_usage_s(cg), cg_mem_kb=read_int(os.path.join(cg, "memory.current")) // 1024,
                           cg_mem_peak_kb=read_int(os.path.join(cg, "memory.peak")) // 1024,
                           cg_pids=read_int(os.path.join(cg, "pids.current")))
    try:
        step_line = last_line(os.path.join(arm, "ws-soak", "work", "agent.log.jsonl"))
        row["agent_steps"] = json.loads(step_line)["step"] if step_line else -1
    except (ValueError, KeyError):
        pass
    counter.update()
    row.update(events=counter.total, ledger_dir_kb=dir_kb(ledger_dir))
    try:
        row["ledger_bytes"] = os.path.getsize(ledger)
        st = os.statvfs(ledger_dir)
        row["disk_free_kb"] = st.f_bavail * st.f_frsize // 1024
    except OSError:
        pass
    other = counter.total
    for kind, col in KINDS.items():
        row[col] = counter.kinds.get(kind, 0)
        other -= row[col]
    row["ev_other"] = other
    return row


def main():
    arm, run, ev_pid, seg, deadline = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), float(sys.argv[5])
    interval = float(sys.argv[6]) if len(sys.argv) > 6 else 60
    ledger_dir = os.path.join(arm, "tego", "runs", run)
    ledger = os.path.join(ledger_dir, "events.jsonl")
    csv_path = os.path.join(arm, "samples.csv")
    new = not os.path.exists(csv_path)
    # the elapsed clock is the segment's own; the soak's total is the sum of its segments (soak_analyze.py)
    t0 = float(open(os.path.join(arm, "segment-%d.start" % seg)).read())
    counter = Counter(ledger, os.path.join(arm, "kinds-%d.json" % seg))
    with open(csv_path, "a", buffering=1) as out:
        if new:
            out.write(",".join(COLS) + "\n")
        while True:
            started = time.time()
            row = sample(arm, run, ev_pid, seg, t0, counter, ledger_dir, ledger)
            out.write(",".join(str(row[c]) for c in COLS) + "\n")
            if not row["tego_alive"] or time.time() >= deadline:
                return 0
            while time.time() - started < interval and alive(ev_pid):  # wake early when tego is gone: one last row
                time.sleep(1)


if __name__ == "__main__":
    sys.exit(main())
