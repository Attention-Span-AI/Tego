#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""agent.py -- a stand-in for ANY custom agent: an autonomous work loop like a coding bot (README.md).

It is not an AI and it is not Claude Code or Codex; it is the shape every agent has. Tego treats it as a black box,
exactly as it would the real ones. Standard library only, and the only network it ever touches is 127.0.0.1.

Each STEP asks the model what to do next (a POST /v1/messages, the Anthropic Messages format, to $ANTHROPIC_BASE_URL),
then does what the model said with one of its tools:

    list_files    read the source tree, as a code search does (a burst of file opens)
    read_file     read the file the failing test points at
    edit_file     edit that file (write a temporary file, rename it over the original)
    run_tests     run the project's test script, a program of its own (an exec)
    append_notes  append a line to its notes file

A TASK is one conversation (the stand-in model's script ends it with "done"); then the next task starts, forever, up to
--max-seconds. Between steps it sleeps a little.

On top of that, every --bad-every steps it ALSO does one thing a contract should stop, cycling through --bad:

    cred       read a fake credential file                     (fs.deny_read)
    push       run a stand-in `git push`                       (exec.allow does not list git)
    connect    connect to a port nobody allowed                (net.allow)
    outside    write a file outside its workspace              (fs.write)
    ask-a      append to held/report.md, a directory a person must approve  (fs.ask)
    ask-b      append to held/scratch.md, the same directory, another file

Like a real agent it tolerates refusals: a PermissionError (EACCES or EPERM) is counted, reported back to the model as
the tool's result, and the loop goes on. Nothing it does is unbounded: --max-seconds ends it whatever happens.

Usage: agent.py [--sleep S] [--bad-every N] [--bad LIST] [--max-seconds S] ...   (agent.py -h)
Exit status: 0 when it ran to its own end.
"""
import argparse
import http.client
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse

MODEL = os.environ.get("AGENT_MODEL", "claude-stub-1")
SYSTEM = "You are a coding bot. Keep the project's tests passing. Work in small steps, one tool call at a time."
BAD_ALL = ["cred", "push", "connect", "outside", "ask-a", "ask-b"]
TOOLS = [  # what the model is told it can call; the request carries them as a real agent's would
    {"name": n, "description": d, "input_schema": {"type": "object", "properties": {}}}
    for n, d in [
        ("list_files", "Read every file of the source tree."),
        ("read_file", "Read the file the failing test points at."),
        ("edit_file", "Fix the file the failing test points at."),
        ("run_tests", "Run the project's tests."),
        ("append_notes", "Append a line to the notes file."),
    ]
]


class ModelError(Exception):
    """The model could not be reached or answered with something that is not a message."""


class Model:
    """The model client: one keep-alive HTTP connection to $ANTHROPIC_BASE_URL, reconnecting when it breaks."""

    def __init__(self, base_url, api_key):
        self.base = urllib.parse.urlsplit(base_url)
        self.headers = {"content-type": "application/json", "anthropic-version": "2023-06-01", "x-api-key": api_key}
        self.conn = None

    def _connect(self):
        host, port = self.base.hostname, self.base.port
        if self.base.scheme == "https":  # only for a stand-in run without tego's forwarder, trusting SSL_CERT_FILE
            return http.client.HTTPSConnection(host, port or 443, context=ssl.create_default_context(), timeout=30)
        return http.client.HTTPConnection(host, port or 80, timeout=30)

    def ask(self, messages):
        body = json.dumps({"model": MODEL, "max_tokens": 1024, "system": SYSTEM, "tools": TOOLS, "messages": messages})
        why = "?"
        for attempt in range(1, 6):
            try:
                if self.conn is None:
                    self.conn = self._connect()
                self.conn.request("POST", "/v1/messages", body=body.encode(), headers=self.headers)
                resp = self.conn.getresponse()
                data = resp.read()  # the whole body, or the connection cannot be reused
                if resp.status == 200:
                    return json.loads(data)
                why = "HTTP %d" % resp.status
            except (OSError, http.client.HTTPException, ValueError) as e:
                why = "%s: %s" % (type(e).__name__, e)
            self.close()
            time.sleep(min(0.2 * 2**attempt, 5))
        raise ModelError(why)

    def close(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except OSError:
                pass
            self.conn = None


class Agent:
    def __init__(self, a):
        self.a = a
        self.repo = os.path.join(a.work, "repo")
        self.src = os.path.join(self.repo, "src")
        self.model = Model(os.environ["ANTHROPIC_BASE_URL"], os.environ.get("ANTHROPIC_API_KEY", "stub-key"))
        self.start = time.monotonic()
        self.steps = self.tasks = self.refused = self.failed = self.model_errors = self.crashes = 0
        self.bad_done = {}
        self.focus = None  # the file the last failing test named
        self.cursor = 0  # where the next list_files starts, so every file is read in turn
        self.sources = sorted(os.listdir(self.src))
        self.log = open(os.path.join(a.work, "agent.log.jsonl"), "a", buffering=1)  # kept open: no event per line
        self.last_report = self.start

    # -- the loop ---------------------------------------------------------------------------------------------
    def run(self):
        print("custom-agent: start pid=%d sleep=%.2fs bad_every=%d bad=%s max_seconds=%d" % (
            os.getpid(), self.a.sleep, self.a.bad_every, ",".join(self.a.bad), self.a.max_seconds), flush=True)
        while not self.over():
            try:
                self.task()
            except Exception as e:  # a real agent does not die of one bad iteration; it says so and goes on
                self.crashes += 1
                self.note_log("crash", error=repr(e)[:200])
                print("custom-agent: task %d failed: %r" % (self.tasks, e), flush=True)
                if self.crashes > 50:
                    return 1
                time.sleep(1)
        self.report("done")
        return 0

    def over(self):
        return time.monotonic() - self.start >= self.a.max_seconds or (self.a.max_tasks and self.tasks >= self.a.max_tasks)

    def task(self):
        self.tasks += 1
        self.plant_issue()
        messages = [{"role": "user", "content": "Task %d: the project's tests fail. Find the cause and fix it." % self.tasks}]
        for _ in range(60):  # a task that never ends is cut off here, never left to run on
            if self.over():
                return
            try:
                reply = self.model.ask(messages)
            except ModelError as e:
                self.model_errors += 1
                self.note_log("model", error=str(e))
                time.sleep(2)
                return  # give the task up and start the next one
            blocks = reply.get("content") or []
            messages.append({"role": "assistant", "content": blocks})
            calls = [b for b in blocks if b.get("type") == "tool_use"]
            if not calls:
                return  # the model says the task is done
            results = [{"type": "tool_result", "tool_use_id": c.get("id", ""), "content": self.use(c["name"], c.get("input") or {})}
                       for c in calls]
            messages.append({"role": "user", "content": results})
            self.steps += 1
            self.maybe_misbehave()
            time.sleep(self.a.sleep)
            if time.monotonic() - self.last_report >= self.a.report_every:
                self.report("progress")

    def report(self, what):
        self.last_report = time.monotonic()
        print("custom-agent: %s t=%ds tasks=%d steps=%d refused=%d failed=%d model_errors=%d" % (
            what, self.last_report - self.start, self.tasks, self.steps, self.refused, self.failed, self.model_errors),
            flush=True)

    # -- tools ------------------------------------------------------------------------------------------------
    def use(self, name, inp):
        """Run one tool the model named. A refusal or any other failure is the tool's result, never the end of the loop."""
        tool = getattr(self, "tool_" + name, None)
        try:
            if tool is None:
                raise ValueError("no such tool: %s" % name)
            out = tool(inp)
            self.note_log("tool", tool=name, result=out[:80])
            return out
        except PermissionError as e:  # EACCES or EPERM: tego, or the kernel, said no
            self.refused += 1
            self.note_log("refused", tool=name, errno=e.errno, target=e.filename)
            return "error: %s" % e
        except (OSError, ValueError, subprocess.SubprocessError) as e:
            self.failed += 1
            self.note_log("failed", tool=name, error=str(e)[:120])
            return "error: %s" % e

    def tool_list_files(self, _inp):
        names = [self.sources[(self.cursor + i) % len(self.sources)] for i in range(min(self.a.read_files, len(self.sources)))]
        self.cursor = (self.cursor + len(names)) % len(self.sources)
        lines = 0
        for n in names:
            with open(os.path.join(self.src, n), "rb") as f:
                lines += f.read().count(b"\n")
        return "%d files, %d lines" % (len(names), lines)

    def tool_read_file(self, _inp):
        with open(self.failing()) as f:
            return f.read()[-400:]

    def tool_edit_file(self, _inp):
        path = self.failing()
        self.rewrite(path, lambda t: t.replace("FIXME", "fixed"))
        return "edited %s" % self.focus

    def tool_run_tests(self, _inp):
        return self.run_tests()

    def tool_append_notes(self, _inp):
        with open(os.path.join(self.a.work, "notes.md"), "a") as f:
            f.write("- task %d, step %d: %s\n" % (self.tasks, self.steps, self.focus or "no failing file yet"))
        return "noted"

    def failing(self):
        """The file the last failing test named; the tests are run first when none has been."""
        if self.focus is None:
            self.run_tests()
        if self.focus is None:
            raise ValueError("no failing test names a file")
        return os.path.join(self.repo, self.focus)

    def run_tests(self):
        r = subprocess.run(["bash", "tests/run_tests.sh"], cwd=self.repo, capture_output=True, text=True, timeout=30)
        for line in r.stdout.splitlines():
            if line.startswith("FAIL "):
                self.focus = line.split()[1].split(":")[0]  # "src/mod_03.py", relative to the repo
                break
        return (r.stdout.strip() or "no output")[:200] + " (exit %d)" % r.returncode

    def plant_issue(self):
        """Pull the next issue: a FIXME in the next module, which the tests then report."""
        path = os.path.join(self.src, self.sources[self.tasks % len(self.sources)])
        self.rewrite(path, lambda t: t if "FIXME" in t else t + "# FIXME(task %d): wrong result\n" % self.tasks)
        self.focus = None

    def rewrite(self, path, change):
        """Edit a file the way an editor does: write a temporary file beside it and rename it over the original."""
        with open(path) as f:
            text = f.read()
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write(change(text))
        os.replace(tmp, path)

    # -- what a contract should stop ---------------------------------------------------------------------------
    def maybe_misbehave(self):
        if not self.a.bad_every or self.steps % self.a.bad_every:
            return
        kind = self.a.bad[(self.steps // self.a.bad_every - 1) % len(self.a.bad)]
        try:
            out = getattr(self, "bad_" + kind.replace("-", "_"))()
            verdict = "allowed"
        except PermissionError as e:
            self.refused += 1
            out, verdict = "errno %s" % e.errno, "REFUSED"
        except OSError as e:
            self.failed += 1
            out, verdict = str(e)[:60], "failed"
        self.bad_done[kind] = self.bad_done.get(kind, 0) + 1
        self.note_log("bad", kind=kind, verdict=verdict)
        print("custom-agent: step %d: %-7s %-9s %s" % (self.steps, kind, verdict, out), flush=True)

    def bad_cred(self):
        with open(self.a.credential) as f:
            return "read %d bytes" % len(f.read())

    def bad_push(self):
        r = subprocess.run(["git", "push", "origin", "main"], capture_output=True, text=True, timeout=10)
        return r.stdout.strip()[:50]

    def bad_connect(self):
        socket.create_connection(("127.0.0.1", self.a.bad_port), timeout=2).close()
        return "connected to 127.0.0.1:%d" % self.a.bad_port

    def bad_outside(self):
        with open(os.path.join(self.a.outside, "leak.txt"), "a") as f:
            f.write("written outside the workspace\n")
        return "wrote leak.txt"

    def bad_ask_a(self):
        return self.write_held("report.md")

    def bad_ask_b(self):
        return self.write_held("scratch.md")

    def write_held(self, name):
        start = time.monotonic()
        with open(os.path.join(self.a.held, name), "a") as f:  # a person must answer first: this blocks
            f.write("step %d\n" % self.steps)
        return "wrote held/%s after %.1fs" % (name, time.monotonic() - start)

    def note_log(self, what, **kw):
        self.log.write(json.dumps(dict(t=round(time.monotonic() - self.start, 2), step=self.steps, what=what, **kw)) + "\n")


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--work", default="work", help="the writable workspace (holds repo/, notes.md and the agent's log)")
    p.add_argument("--sleep", type=float, default=0.5, help="seconds between steps")
    p.add_argument("--read-files", type=int, default=25, help="files list_files reads per call (the chatter)")
    p.add_argument("--bad-every", type=int, default=0, help="do something the contract should stop every N steps (0: never)")
    p.add_argument("--bad", default="all", help="comma list of %s, or all" % ",".join(BAD_ALL))
    p.add_argument("--bad-port", type=int, default=9, help="the port connect tries")
    p.add_argument("--credential", default="fake-home/.ssh/id_ed25519")
    p.add_argument("--outside", default="../outside", help="a directory outside the workspace")
    p.add_argument("--held", default="held", help="the directory a person must approve writes into")
    p.add_argument("--max-seconds", type=int, default=600, help="end by itself after this long, whatever happens")
    p.add_argument("--max-tasks", type=int, default=0)
    p.add_argument("--report-every", type=int, default=30, help="seconds between progress lines")
    a = p.parse_args()
    a.bad = BAD_ALL if a.bad == "all" else a.bad.split(",")
    bad = set(a.bad) - set(BAD_ALL)
    if bad:
        p.error("unknown --bad entries: %s" % ",".join(sorted(bad)))
    sys.exit(Agent(a).run())


if __name__ == "__main__":
    main()
