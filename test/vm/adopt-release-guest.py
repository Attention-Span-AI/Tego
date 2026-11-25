#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# Disposable-guest recipe, never run on the development host (TEGO_DISPOSABLE_HOST=kvm is required). Run as the ordinary
# user (uid 1000) with passwordless sudo, in a guest with a user manager and cgroup v2, against the ORDINARY build (no
# tegotesthooks, no TEGO_TEST_* variable, the guest's own ~/.tego), as a person would run it:
#   sudo tego adopt --pid <agent> --boundary <contract>   then   sudo tego adopt --release --pid <agent>
# Usage: adopt-release-guest.py <ordinary tego> <workdir> [shell|lone]. Prints a JSON object and "VERDICT ...".
# shell: a shell stays in the origin scope beside the agent, so the release puts the agent back in its own scope.
# lone: the agent is the scope's only process, systemd removes the scope when it leaves, and the release must put
# the agent in a leaf (tego-released-<run>) beside where it was, outside tego.slice, not leave it in the Tego scope.
# The agent is a shell reading commands from a fifo; before the adoption `/usr/bin/id` runs, during it the contract's
# exec allow-list refuses it, after the release it runs again. Not part of CI: a guest run by hand.
import glob, json, os, signal, subprocess, sys, time

if os.environ.get("TEGO_DISPOSABLE_HOST") != "kvm":
    sys.exit("requires a disposable guest: TEGO_DISPOSABLE_HOST=kvm")

tego, work = sys.argv[1:3]
mode = sys.argv[3] if len(sys.argv) > 3 else "shell"  # shell: a shell stays in the origin scope; lone: the agent is the scope's only process
checks, unknown, facts = [], [], {}
me = os.environ.get("USER", "probe")


def check(name, ok, detail=""):
    checks.append({"check": name, "ok": bool(ok), "detail": str(detail)})


def sh(*a, **kw):
    r = subprocess.run(a, capture_output=True, text=True, **kw)
    return r.returncode, r.stdout + r.stderr


def cg(pid):
    try:
        for l in open("/proc/%d/cgroup" % pid):
            if l.startswith("0::"):
                return l[3:].strip()
    except OSError:
        pass
    return ""


def waitfor(pred, secs, step=0.2):
    end = time.time() + secs
    while time.time() < end:
        if pred():
            return True
        time.sleep(step)
    return False


sh("rm", "-rf", work)
for d in ("ws", "contract"):
    os.makedirs(os.path.join(work, d))
os.chmod(work, 0o755)
fifo, acks = os.path.join(work, "ws", "cmds"), os.path.join(work, "ws", "acks")
os.mkfifo(fifo)
open(acks, "w").close()
open(os.path.join(work, "contract", "boundary.yaml"), "w").write("""version: 0
name: b-boundary
command: ["/bin/sh"]
record: full
fs:
  write: ["%s/ws", "/dev/null"]
exec:
  allow: ["/bin/sh", "/usr/bin/sleep", "/usr/bin/cat", "/usr/bin/echo", "/usr/bin/python3"]
""" % work)
os.chmod(os.path.join(work, "contract", "boundary.yaml"), 0o644)
open(os.path.join(work, "agent.sh"), "w").write("""#!/bin/sh
echo $$ > "%(w)s/agent.pid"
exec 3<>"%(w)s/ws/cmds"
while IFS= read -r line <&3; do
	case "$line" in
	id) /usr/bin/id >/dev/null 2>&1; echo "id $?" >>"%(w)s/ws/acks" ;;
	write) echo hello >"%(w)s/ws/f" 2>/dev/null; echo "write $?" >>"%(w)s/ws/acks" ;;
	quit) break ;;
	esac
done
""" % {"w": work})
os.chmod(os.path.join(work, "agent.sh"), 0o755)

rc, doc = sh(tego, "doctor")
open(os.path.join(work, "doctor.txt"), "w").write(doc)
facts["doctor_head"] = doc[:1500]

# the "terminal": the user's own scope, a shell beside the agent
# (the shell stays behind in the scope, as a terminal's shell does: the adoption moves the agent, not its parent)
if mode == "lone":
    argv = ["systemd-run", "--user", "--scope", "--quiet", "--", os.path.join(work, "agent.sh")]
else:
    argv = ["systemd-run", "--user", "--scope", "--quiet", "--", "/bin/sh", "-c", '"$0"; exec sleep 600', os.path.join(work, "agent.sh")]
term = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
adopter = None
try:
    if not waitfor(lambda: os.path.exists(os.path.join(work, "agent.pid")), 30):
        unknown.append("the stand-in agent did not start")
        raise SystemExit
    agent = int(open(os.path.join(work, "agent.pid")).read())
    cg_before = cg(agent)
    facts.update(agent=agent, cgroup_before=cg_before)

    def ask(cmd, timeout=15):
        n = len(open(acks).read().splitlines())
        with open(fifo, "w") as f:
            f.write(cmd + "\n")
        if not waitfor(lambda: len(open(acks).read().splitlines()) > n, timeout):
            return None
        return open(acks).read().splitlines()[-1]

    r = ask("id")
    check("before the adoption /usr/bin/id runs in the agent (premise)", r == "id 0", r)
    # ---- the adoption, by the ordinary build, as a person runs it
    t0 = time.time()
    out_f, err_f = open(os.path.join(work, "adopt.out"), "wb"), open(os.path.join(work, "adopt.err"), "wb")
    adopter = subprocess.Popen(["sudo", "-n", tego, "adopt", "--pid", str(agent), "--boundary", os.path.join(work, "contract", "boundary.yaml")],
                               stdin=subprocess.DEVNULL, stdout=out_f, stderr=err_f)
    moved = waitfor(lambda: cg(agent) != cg_before or adopter.poll() is not None, 240, 0.2)
    facts["seconds_to_move"] = round(time.time() - t0, 1)
    time.sleep(1.5)
    facts["adopt_out"] = open(os.path.join(work, "adopt.out"), errors="replace").read()[-800:]
    facts["adopt_err"] = open(os.path.join(work, "adopt.err"), errors="replace").read()[-1200:]
    cg_now = cg(agent)
    if not moved or cg_now == cg_before:
        unknown.append("the ordinary build did not adopt the agent (exit %s): %s" % (adopter.poll(), (facts["adopt_err"] + facts["adopt_out"]).replace("\n", " ")[:500]))
        raise SystemExit
    facts["cgroup_adopted"] = cg_now
    facts["mode"] = mode
    facts["origin_exists_after_move"] = os.path.exists("/sys/fs/cgroup" + cg_before)
    anc = {}
    p = os.path.dirname(cg_before)
    while p not in ("/", ""):
        d = "/sys/fs/cgroup" + p
        try:
            anc[p] = {"subtree_control": open(d + "/cgroup.subtree_control").read().strip(), "type": open(d + "/cgroup.type").read().strip(), "procs": len(open(d + "/cgroup.procs").read().split())}
        except OSError as e:
            anc[p] = str(e)
        p = os.path.dirname(p)
    facts["origin_ancestors"] = anc
    check("the agent moved into a Tego scope of its own", cg_now != cg_before and "tego" in cg_now, cg_now)
    r = ask("id")
    check("under the adoption /usr/bin/id is refused by the contract's exec allow-list", r is not None and r != "id 0", r)
    r = ask("write")
    check("a write inside the allowed folder works (the boundary does not over-block)", r == "write 0", r)
    # while the adoption runs the run directory is root's (handed to the user at its end): read it as root
    rc, o = sh("sudo", "-n", "sh", "-c", "ls -dt %s/.tego/runs/*/events.jsonl | head -n 1" % os.path.expanduser("~"))
    ev = [o.strip()] if rc == 0 and o.strip() else []
    facts["events_file"] = ev[-1] if ev else None

    def read_events():
        rc, o = sh("sudo", "-n", "cat", ev[-1])
        return [json.loads(l) for l in o.splitlines() if l.strip()]
    lines = read_events() if ev else []
    kinds = [l.get("kind") for l in lines]
    facts["kinds"] = kinds[:40]
    rs = [l for l in lines if l.get("kind") == "run_start"]
    check("the record has a run_start of this adoption", len(rs) == 1, kinds[:10])
    if rs:
        facts["run_start"] = {k: rs[0].get(k) for k in ("record_minor", "mode", "adopted", "launcher", "tier", "backend", "enforcement", "adoption")}
    denied = [l for l in lines if l.get("kind") in ("refusal", "decision", "exec", "event") and "/usr/bin/id" in json.dumps(l)]
    check("the record names the refused /usr/bin/id", bool(denied), "%d lines mention it" % len(denied))
    # ---- release
    rc, o = sh("sudo", "-n", tego, "adopt", "--release", "--pid", str(agent))
    facts["release"] = "rc %s %s" % (rc, o[-300:])
    facts["release_rc"] = rc
    facts["agent_cgroup_after_release"] = cg(agent)
    check("tego adopt --release exits 0", rc == 0, facts["release"])
    try:
        adopter.wait(timeout=60)
    except subprocess.TimeoutExpired:
        pass
    facts["adopter_rc"] = adopter.returncode
    check("the adopting process ended after the release", adopter.returncode is not None, adopter.returncode)
    time.sleep(1.5)
    if mode == "lone":
        # the origin scope is gone (systemd removed it when its only process left): the agent goes to a leaf beside where it was
        leaf_now = cg(agent)
        facts["leaf"] = leaf_now
        check("the agent is in a cgroup made for it beside its removed origin, outside tego.slice",
              leaf_now.startswith(os.path.dirname(cg_before) + "/tego-released-") and not leaf_now.startswith("/tego.slice"), "%s vs %s" % (leaf_now, cg_before))
        check("the agent's old scope is not back (systemd removed it)", not os.path.exists("/sys/fs/cgroup" + cg_before), cg_before)
    else:
        check("the agent is back in its own cgroup", cg(agent) == cg_before, "%s vs %s" % (cg(agent), cg_before))
    check("the adoption's scope is gone", not os.path.exists("/sys/fs/cgroup" + cg_now), cg_now)
    r = ask("id")
    check("after the release /usr/bin/id runs again", r == "id 0", r)
    run_id = os.path.basename(os.path.dirname(ev[-1])) if ev else ""
    rc, o = sh(tego, "events", run_id, "--verify")
    check("tego events --verify passes", rc == 0, "rc %s: %s" % (rc, o.strip()[-150:]))
    lines = read_events()
    check("the record ends with run_end", lines[-1].get("kind") == "run_end", lines[-1].get("kind"))
    facts["run_end"] = {k: lines[-1].get(k) for k in ("reason", "exit_code", "detail")}
except SystemExit:
    pass
finally:
    try:
        with open(fifo, "w") as f:
            f.write("quit\n")
    except Exception:
        pass
    if adopter is not None and adopter.poll() is None:
        sh("sudo", "-n", "kill", "-TERM", str(adopter.pid))
        time.sleep(2)
    try:
        term.wait(timeout=10)
    except Exception:
        term.kill()
    if mode == "lone" and facts.get("leaf"):
        time.sleep(1)
        facts["leaf_exists_after_agent_exit"] = os.path.exists("/sys/fs/cgroup" + facts["leaf"])

status = "UNKNOWN" if unknown else ("PASS" if checks and all(c["ok"] for c in checks) else "FAIL")
if status == "FAIL":
    note = "; ".join("%s (%s)" % (c["check"], c["detail"]) for c in checks if not c["ok"])
elif status == "UNKNOWN":
    note = "; ".join(unknown)
else:
    note = "ordinary build adopted the agent in %.1f s, enforced the exec allow-list, released it, record verified" % facts.get("seconds_to_move", 0)
print(json.dumps({"status": status, "note": note, "checks": checks, "facts": facts, "unknown": unknown}, indent=1, default=str))
print("VERDICT %s %s" % (status, note.replace("\n", " ")[:600]))
