# SPDX-License-Identifier: Apache-2.0
"""Held-pidfd cleanup for the VM shell regressions' private process trees."""
import os
import select
import signal
import subprocess
import time


def state(pid):
    with open('/proc/%d/stat' % pid, 'rb') as source:
        data = source.read()
    fields = data[data.rindex(b')') + 2:].split()
    return int(fields[1]), int(fields[19])


def ready(fd):
    return bool(select.select([fd], [], [], 0)[0])


class OwnedProcess:
    def __init__(self, argv, **kwargs):
        self.refs = {}
        self.proc = subprocess.Popen(argv, start_new_session=True, **kwargs)
        try:
            birth = state(self.proc.pid)[1]
            fd = os.pidfd_open(self.proc.pid)
            try:
                if state(self.proc.pid)[1] != birth:
                    raise RuntimeError('root process changed during pidfd admission')
                self.refs[self.proc.pid] = (fd, birth)
            except BaseException:
                os.close(fd)
                raise
        except BaseException:
            # No caller has polled or waited this known child yet.
            self.proc.kill()
            self.proc.communicate(timeout=2)
            raise

    def pin(self, pid, seen=None):
        if pid in self.refs:
            fd, birth = self.refs[pid]
            if ready(fd) or state(pid)[1] != birth:
                raise RuntimeError('parent process has already exited')
            return
        seen = set() if seen is None else seen
        if pid in seen or len(seen) >= 16:
            raise RuntimeError('process is not an owned descendant')
        seen.add(pid)
        parent, birth = state(pid)
        self.pin(parent, seen)
        parent_fd, parent_birth = self.refs[parent]
        if ready(parent_fd) or state(parent)[1] != parent_birth:
            raise RuntimeError('parent process changed')
        fd = os.pidfd_open(pid)
        committed = False
        try:
            if state(pid) != (parent, birth) or ready(parent_fd) or state(parent)[1] != parent_birth:
                raise RuntimeError('descendant relation changed during admission')
            self.refs[pid] = (fd, birth)
            committed = True
        finally:
            if not committed:
                os.close(fd)

    def exited(self, pid):
        return ready(self.refs[pid][0])

    def send(self, sig):
        signal.pidfd_send_signal(self.refs[self.proc.pid][0], sig)

    def close(self):
        try:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                for fd, _ in self.refs.values():
                    if not ready(fd):
                        try:
                            signal.pidfd_send_signal(fd, sig)
                        except ProcessLookupError:
                            pass
                deadline = time.monotonic() + 1
                while time.monotonic() < deadline and any(not ready(fd) for fd, _ in self.refs.values()):
                    time.sleep(.01)
            self.proc.communicate(timeout=2)
            if any(not ready(fd) for fd, _ in self.refs.values()):
                raise RuntimeError('owned process survived bounded cleanup')
        finally:
            for fd, _ in self.refs.values():
                os.close(fd)
            self.refs.clear()


def await_file(path, owner):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if path.exists() and path.read_text().strip():
            pid = int(path.read_text())
            owner.pin(pid)
            return pid
        if owner.proc.poll() is not None:
            raise RuntimeError('fixture exited before readiness: ' + str(path))
        time.sleep(.01)
    raise RuntimeError('fixture readiness deadline: ' + str(path))
