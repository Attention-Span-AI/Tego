# SPDX-License-Identifier: Apache-2.0
#
# ptyscreen.py — what the pty driver (drive.py) is built on: a program on a pseudo-terminal, and a small terminal
# emulator that turns its output into the text a person would see on the screen. Claude Code's interface redraws
# itself with cursor movements and erasures, so matching the raw byte stream (or the stream with its escape
# sequences cut out) finds text that is no longer on the screen and misses text that is; the emulator keeps a grid.
# It understands what Ink (Claude Code's renderer) and bash emit: printable text, CR/LF/BS/TAB, cursor movement
# (CUU CUD CUF CUB CUP HVP CHA VPA CNL CPL), erase in display and in line, insert/delete line, save/restore cursor,
# and it ignores colours and modes. It is not a general terminal.
import fcntl
import os
import pty
import re
import select
import signal
import struct
import termios
import time


class Screen:
    def __init__(self, rows=50, cols=140):
        self.rows, self.cols = rows, cols
        self.grid = [[" "] * cols for _ in range(rows)]
        self.history = []  # lines scrolled off the top, so a long answer is not lost
        self.r = self.c = 0
        self.saved = (0, 0)
        self._buf = ""

    def _scroll(self):
        self.history.append("".join(self.grid[0]).rstrip())
        self.grid = self.grid[1:] + [[" "] * self.cols]

    def _put(self, ch):
        if self.c >= self.cols:
            self.c = 0
            self._lf()
        self.grid[self.r][self.c] = ch
        self.c += 1

    def _lf(self):
        if self.r == self.rows - 1:
            self._scroll()
        else:
            self.r += 1

    def _csi(self, params, final):
        nums = [int(p) if p.isdigit() else 0 for p in re.split(r"[;:]", params.lstrip("?<>=")) if p != ""] or []
        n1 = nums[0] if nums and nums[0] else 1
        if params and params[0] in "?<>=":
            return  # private modes (alternate screen, synchronized output, bracketed paste ...): ignored
        if final == "A":
            self.r = max(0, self.r - n1)
        elif final == "B":
            self.r = min(self.rows - 1, self.r + n1)
        elif final == "C":
            self.c = min(self.cols - 1, self.c + n1)
        elif final == "D":
            self.c = max(0, self.c - n1)
        elif final == "E":
            self.r, self.c = min(self.rows - 1, self.r + n1), 0
        elif final == "F":
            self.r, self.c = max(0, self.r - n1), 0
        elif final == "G":
            self.c = min(self.cols - 1, n1 - 1)
        elif final == "d":
            self.r = min(self.rows - 1, n1 - 1)
        elif final in "Hf":
            self.r = min(self.rows - 1, (nums[0] if nums and nums[0] else 1) - 1)
            self.c = min(self.cols - 1, (nums[1] if len(nums) > 1 and nums[1] else 1) - 1)
        elif final == "J":
            mode = nums[0] if nums else 0
            if mode == 0:
                self.grid[self.r][self.c:] = [" "] * (self.cols - self.c)
                for i in range(self.r + 1, self.rows):
                    self.grid[i] = [" "] * self.cols
            elif mode in (2, 3):
                self.grid = [[" "] * self.cols for _ in range(self.rows)]
            elif mode == 1:
                for i in range(self.r):
                    self.grid[i] = [" "] * self.cols
                self.grid[self.r][: self.c + 1] = [" "] * (self.c + 1)
        elif final == "K":
            mode = nums[0] if nums else 0
            if mode == 0:
                self.grid[self.r][self.c:] = [" "] * (self.cols - self.c)
            elif mode == 1:
                self.grid[self.r][: self.c + 1] = [" "] * (self.c + 1)
            else:
                self.grid[self.r] = [" "] * self.cols
        elif final == "X":
            self.grid[self.r][self.c:self.c + n1] = [" "] * min(n1, self.cols - self.c)
        elif final == "L":
            for _ in range(n1):
                self.grid.insert(self.r, [" "] * self.cols)
                self.grid.pop()
        elif final == "M":
            for _ in range(n1):
                self.grid.pop(self.r)
                self.grid.append([" "] * self.cols)
        elif final == "P":
            row = self.grid[self.r]
            del row[self.c:self.c + n1]
            row.extend([" "] * (self.cols - len(row)))
        elif final == "@":
            row = self.grid[self.r]
            row[self.c:self.c] = [" "] * n1
            del row[self.cols:]
        # m (colours), h/l (modes), n, t, r, s, u: no effect on the text

    def feed(self, data):
        s = self._buf + data
        self._buf = ""
        i = 0
        while i < len(s):
            ch = s[i]
            if ch == "\x1b":
                if i + 1 >= len(s):
                    self._buf = s[i:]
                    break
                nx = s[i + 1]
                if nx == "[":
                    m = re.match(r"\x1b\[([0-9;:?<>=!]*)([ -/]*)([@-~])", s[i:])
                    if not m:
                        self._buf = s[i:]
                        break
                    self._csi(m.group(1), m.group(3))
                    i += m.end()
                elif nx == "]":  # OSC, ends at BEL or ST
                    m = re.match(r"\x1b\][^\x07\x1b]*(\x07|\x1b\\)", s[i:])
                    if not m:
                        self._buf = s[i:]
                        break
                    i += m.end()
                elif nx in "()":
                    i += 3
                elif nx == "7":
                    self.saved = (self.r, self.c)
                    i += 2
                elif nx == "8":
                    self.r, self.c = self.saved
                    i += 2
                else:
                    i += 2
            elif ch == "\r":
                self.c = 0
                i += 1
            elif ch == "\n":
                self._lf()
                i += 1
            elif ch == "\b":
                self.c = max(0, self.c - 1)
                i += 1
            elif ch == "\t":
                self.c = min(self.cols - 1, (self.c // 8 + 1) * 8)
                i += 1
            elif ch >= " " and ch != "\x7f":
                self._put(ch)
                i += 1
            else:
                i += 1

    def lines(self):
        return [("".join(r)).rstrip() for r in self.grid]

    def text(self):
        ls = self.lines()
        while ls and not ls[-1]:
            ls.pop()
        return "\n".join(ls)

    def everything(self):
        return "\n".join(self.history + self.lines())


class Session:
    """A program on a pty with a Screen. send() types, wait_for() waits for text to be on the screen."""

    def __init__(self, argv, env, cwd, rows=50, cols=140):
        self.screen = Screen(rows, cols)
        self.raw = b""
        self.log = []  # (time, what) of every action the driver took
        self.t0 = time.time()
        # A shell the program starts on this terminal writes its history when it exits: never into the operator's own
        # ~/.bash_history (tools/isocheck, SH-2).
        env = dict(env, HISTFILE="/dev/null")
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.chdir(cwd)
            os.execve(argv[0], argv, env)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        self.alive = True
        self.status = None
        self._dec = __import__("codecs").getincrementaldecoder("utf-8")("replace")

    def note(self, what):
        self.log.append((time.time() - self.t0, what))
        print(f"[{time.time() - self.t0:7.1f}s] {what}", flush=True)

    def pump(self, seconds=0.2):
        end = time.time() + seconds
        while self.alive and time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if not r:
                continue
            try:
                d = os.read(self.fd, 65536)
            except OSError:
                d = b""
            if not d:
                self.alive = False
                break
            self.raw += d
            self.screen.feed(self._dec.decode(d))
        if self.alive:
            p, st = os.waitpid(self.pid, os.WNOHANG)
            if p:
                self.alive, self.status = False, st
        return self.alive

    def send(self, text, pause=0.1):
        os.write(self.fd, text if isinstance(text, bytes) else text.encode())
        self.pump(pause)

    def type(self, text, delay=0.01):
        for ch in text:
            self.send(ch, delay)

    def wait_for(self, pattern, timeout=30, flags=re.S):
        """Pump until the regex matches the current screen text; return the match, or None on timeout."""
        rx = re.compile(pattern, flags)
        end = time.time() + timeout
        while True:
            m = rx.search(self.screen.text())
            if m:
                return m
            if time.time() >= end or not self.pump(0.25) and not rx.search(self.screen.text()):
                return rx.search(self.screen.text())

    def wait_any(self, patterns, timeout=30):
        """Wait until one of the regexes (a dict name -> pattern) matches; return its name or None."""
        end = time.time() + timeout
        rxs = {k: re.compile(v, re.S) for k, v in patterns.items()}
        while True:
            t = self.screen.text()
            for k, rx in rxs.items():
                if rx.search(t):
                    return k
            if time.time() >= end or not self.pump(0.25):
                t = self.screen.text()
                for k, rx in rxs.items():
                    if rx.search(t):
                        return k
                return None

    def close(self, grace=3.0):
        if self.alive:
            try:
                os.kill(self.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            self.pump(grace)
        if self.status is None:
            try:
                p, st = os.waitpid(self.pid, os.WNOHANG)
                if not p:
                    os.kill(self.pid, signal.SIGKILL)
                    p, st = os.waitpid(self.pid, 0)
                self.status = st
            except ChildProcessError:
                pass
        return os.waitstatus_to_exitcode(self.status) if self.status is not None else None
