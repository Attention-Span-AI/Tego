# SPDX-License-Identifier: Apache-2.0
#
# report.py — reads one run's ledger back and says what it proves (run.sh calls it). It trusts nothing the driver
# printed: every claim README.md makes about a run is a check here against ledger events.
#
# Usage: report.py <root> <run-id> <real-home> [probe|probe-attempts]
#   probe: only the network checks (the run was a startup probe, not the whole session);
#   probe-attempts: the same, and the probe must have tried an Anthropic address (every attempt refused).
#   Exit 1 when a check fails.
import json
import os
import re
import sys
from collections import Counter

root, run, real_home = sys.argv[1], sys.argv[2], sys.argv[3]
probe = len(sys.argv) > 4 and sys.argv[4].startswith("probe")
attempts = len(sys.argv) > 4 and sys.argv[4] == "probe-attempts"
ev = [json.loads(line) for line in open(f"{root}/state/runs/{run}/events.jsonl")]
failed = 0


def subj(e):
    return e.get("path") or e.get("dst") or e.get("target") or " ".join(e.get("argv") or []) or ""


def clean(s):
    return s.replace(root, "$ROOT").replace(real_home, "$HOME")


def check(ok, what):
    global failed
    print(("PASS  " if ok else "FAIL  ") + what)
    failed += not ok
    return ok


def line(e, note=""):
    t = e.get("ts", "")[11:23]
    return clean(f"   seq {e['seq']:<5} {t}  {e['kind']:<8} {note}")


ANTH = re.compile(r"160\.79\.104\.|2607:6bc0:|anthropic\.com")
# every refusal is recorded twice: on the event of its kind (fs, exec, net) with verdict refused, and as a kind=refused
# event that carries the reason; the second is the one counted here
refused = [e for e in ev if e["kind"] == "refused"]

print("-- events by kind: " + ", ".join(f"{k} {v}" for k, v in Counter(e["kind"] for e in ev).most_common()))
c = Counter((e.get("reason"), (e.get("rule") or "")[:40]) for e in refused)
print("-- refusals by reason and rule:")
for (reason, rule), n in c.most_common():
    print(f"   {n:>4}  {reason:<26} {clean(rule)}")

# ---- network: what the contract allowed, and whether an Anthropic address was ever reached ------------------------
print("-- every network connection or datagram the contract ALLOWED:")
allowed = Counter((e.get("rule"), e.get("dst")) for e in ev if e["kind"] == "net" and e.get("verdict") == "allow")
for (rule, dst), n in sorted(allowed.items(), key=lambda kv: str(kv[0])):
    print(f"   {n:>4}  {rule}  {dst}")
ok_rule = re.compile(r"^(net\[unix:/var/run/nscd/socket\]|net\.resolver|net\.capture\[127\.0\.0\.1:\d+\])$")
other = sorted({str(r) for (r, _d) in allowed if not ok_rule.match(str(r))})
anth = [e for e in ev if ANTH.search(subj(e)) or ANTH.search(e.get("host") or "")]
nref = Counter(e.get("target") for e in refused if e.get("op") in ("net", "connect") or str(e.get("reason")) == "net-not-allowed")
print("-- network refusals (the targets Claude Code tried and was not allowed): " + clean(", ".join(f"{t} x{n}" for t, n in nref.most_common())))
print("-- ledger events that name an Anthropic address or host:")
for e in anth:
    print(line(e, f"{e.get('verdict') or ''} {e.get('reason') or ''}  {subj(e)}"))
if not anth:
    print("   none")
if attempts:
    check(bool(anth), f"the startup check tried an Anthropic address ({len(anth)} ledger events name one)")
check(not other, f"the only network allowed: the name-service socket, the system resolver, and the forwarder's listener on 127.0.0.1 (other: {other or 'none'})")
check(all(e.get("verdict") == "refused" or e["kind"] == "refused" for e in anth),
      "no event naming an Anthropic address has any verdict but refused")
home_open = [e for e in ev if e["kind"] == "fs" and e.get("verdict") == "allow"
             and re.match(re.escape(real_home) + r"/(\.claude|\.codex|\.config/anthropic|\.tego)", e.get("path") or "")]
denied = [e for e in refused if e.get("reason") == "read-denied"]
check(not home_open, f"no open of the real account's ~/.claude, ~/.claude.json, ~/.codex, ~/.config/anthropic or ~/.tego was allowed ({len(denied)} were refused)")

if probe:
    sys.exit(1 if failed else 0)

# ---- model traffic ------------------------------------------------------------------------------------------------
stub = [json.loads(x) for x in open(f"{root}/stub/requests.log") if x.strip()]
req = [e for e in ev if e["kind"] == "ssl_request"]
resp = [e for e in ev if e["kind"] == "ssl_response"]
check(len(stub) > 0 and len(req) == len(stub) and all(e.get("source") == "forwarder" for e in req) and len(resp) == len(stub),
      f"every model request the stand-in answered ({len(stub)}) is an ssl_request source=forwarder ({len(req)}) with an ssl_response ({len(resp)})")
check(all(e.get("host") == "127.0.0.1" for e in req), "every model request went to the stand-in at 127.0.0.1")
check(all(m.get("status") == 200 for m in stub), "the stand-in answered every request with 200; its turns: " + ",".join(str(m.get("turn")) for m in stub))

# ---- the steps ------------------------------------------------------------------------------------------------------
print("-- the steps, in the ledger:")
leak = [e for e in refused if "leak.txt" in subj(e)]
for e in leak:
    print(line(e, f"refused {e['reason']}  {subj(e)}"))
check(any(e["reason"] == "write-outside-contract" for e in leak), "a write outside the workspace was refused (write-outside-contract) and the file does not exist: "
      + str(not os.path.exists(f"{root}/outside/leak.txt")))
push = [e for e in ev if e["kind"] == "exec" and e.get("verdict") == "refused" and (e.get("path") or "").endswith("/ws/bin/git") and "push" in (e.get("argv") or [])]
for e in push:
    print(line(e, f"refused {e['reason']}  exec {' '.join(e['argv'])}  ({clean(e['path'])})"))
check(any(e.get("reason") == "exec-not-allowed" for e in push), "git push was refused (exec-not-allowed)")

asks = [e for e in ev if e["kind"] == "ask"]
answers = {e["ask_id"]: e for e in ev if e["kind"] == "answer"}
for e in asks:
    print(line(e, f"held {e.get('hold')}  {subj(e)}  [{e['ask_id']}]"))
    a = answers.get(e["ask_id"])
    if a:
        print(line(a, f"approved={a.get('approved')}  by {a.get('by')}  after {a.get('after_s', 0):.1f}s"))
rep = [e for e in asks if "held/report.txt" in subj(e)]
jour = [e for e in asks if subj(e).endswith("held/journal.txt")]
check(len(rep) == 1 and answers.get(rep[0]["ask_id"], {}).get("approved") is True, "the Write tool's file in held/ held the session and a person approved it")
rn = [e for e in refused if e["kind"] == "refused" and e.get("reason") == "rename-outside-contract" and "report.txt.tmp" in subj(e)]
for e in rn:
    print(line(e, f"refused {e['reason']}  {subj(e)}"))
check(bool(rn), "FINDING: Claude Code's Write tool writes a temporary file and renames it; the open was approved, the rename in the fs.ask directory was refused (rename-outside-contract)")
first = [e for e in jour if e["ask_id"] in answers and not str(answers[e["ask_id"]].get("by", "")).startswith("standing:")]
second = [e for e in jour if str(answers.get(e["ask_id"], {}).get("by", "")).startswith("standing:")]
check(len(first) == 1 and answers[first[0]["ask_id"]].get("approved") is True and "always" in str(answers[first[0]["ask_id"]].get("by", "")),
      "an in-place write to held/journal.txt held the session until a person ran tego approve --always")
if first and second:
    a2 = answers[second[0]["ask_id"]]
    dt = (second[0]["mono_ns"] and (a2["mono_ns"] - second[0]["mono_ns"]) / 1e6)
    check(a2["by"] == "standing:" + first[0]["ask_id"] and a2.get("approved") is True,
          f"the same write again was answered at once from the standing answer ({a2['by']}), {dt:.2f} ms after the ask was recorded")
else:
    check(False, "the same write again was answered from the standing answer")

end = [e for e in ev if e["kind"] == "run_end"]
check(bool(end) and end[-1].get("reason") == "exit", f"the run ended by Claude Code's own exit: {end[-1].get('reason') if end else None}")
sys.exit(1 if failed else 0)
