#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# Disposable-guest recipe, never run on the development host (TEGO_DISPOSABLE_HOST=kvm is required). Run as the ordinary
# user with passwordless sudo, against the ORDINARY build. A run launched with `sudo tego run` at a root tier keeps its
# folder root 0700 until it ends; the person's own lift, grant, restore, block, mcp and route against it must say it was
# launched as root and to repeat the command with sudo (exit 1, [root-run]), not `permission denied [io]` (exit 125),
# and root's own lift must work. The person's own dashboard is read for what it shows of the run.
# Usage: root-run-guest.py <ordinary tego> <workdir> <tier>. Prints a JSON object and "VERDICT ...". Not part of CI.
import glob, json, os, shutil, signal, subprocess, sys, time

if os.environ.get("TEGO_DISPOSABLE_HOST") != "kvm":
    sys.exit("requires a disposable guest: TEGO_DISPOSABLE_HOST=kvm")

tego, work, tier = sys.argv[1:4]
checks, unknown, facts = [], [], {}


def check(name, ok, detail=""):
    checks.append({"check": name, "ok": bool(ok), "detail": str(detail)})


def sh(*a, **kw):
    r = subprocess.run(a, capture_output=True, text=True, **kw)
    return r.returncode, r.stdout, r.stderr


def waitfor(pred, secs, step=0.1):
    end = time.time() + secs
    while time.time() < end:
        if pred():
            return True
        time.sleep(step)
    return False


shutil.rmtree(work, ignore_errors=True)
proj, vault, tools = [os.path.join(work, d) for d in ("proj", "vault", "tools")]
out = os.path.join(proj, "out")
for d in (out, vault, tools):
    os.makedirs(d, mode=0o755)
os.chmod(work, 0o755)
secret, tool = os.path.join(vault, "token"), os.path.join(tools, "hello")
open(secret, "w").write("lifted\n")
os.chmod(secret, 0o644)
open(tool, "w").write("#!/bin/sh\nexit 0\n")
os.chmod(tool, 0o755)
allow = ['"/bin/sh"']
progs = {}
for name in ("sh", "cat", "sleep"):
    p = shutil.which(name)
    real = os.path.realpath(p)
    for q in (p, real):
        if '"%s"' % q not in allow:
            allow.append('"%s"' % q)
    progs[name] = p
open(os.path.join(proj, "agent.yaml"), "w").write("""version: 0
name: b-e47
command: ["/bin/sh", "./agent.sh"]
tier: %s
fs:
  write: ["./out/"]
  deny_read: ["%s"]
exec:
  allow: [%s]
net: {}
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 64
record: summary
live:
  mode: adjustable
  fence:
    read: ["%s"]
    exec: ["%s"]
""" % (tier, vault, ", ".join(allow), vault, tool))
open(os.path.join(proj, "agent.sh"), "w").write("""#!/bin/sh
n=0
while [ ! -e out/stop ] && [ "$n" -lt 3000 ]; do
  n=$((n + 1))
  if "%s" "%s" >out/got 2>out/err; then echo ok >out/read; else echo refused >out/read; fi
  if "%s" >out/xout 2>&1; then echo ok >out/exec; else echo refused >out/exec; fi
  "%s" 0.1
done
""" % (progs["cat"], secret, tool, progs["sleep"]))
os.chmod(os.path.join(proj, "agent.sh"), 0o755)
for f in glob.glob(os.path.join(work, "**"), recursive=True):
    pass

runout = open(os.path.join(work, "run.out"), "wb")
runerr = open(os.path.join(work, "run.err"), "wb")
run = subprocess.Popen(["sudo", "-n", tego, "run", "agent.yaml"], cwd=proj, stdin=subprocess.DEVNULL, stdout=runout, stderr=runerr)
run_id = ""


def rd(n):
    try:
        return open(os.path.join(out, n)).read().strip()
    except OSError:
        return None


def says(name, want, secs=15):
    end = time.time() + secs
    while time.time() < end:
        if rd(name) == want:
            time.sleep(0.4)
            if rd(name) == want:
                return True
        time.sleep(0.05)
    return False


import http.cookiejar, re, urllib.request, html as htmlmod
tego_control = os.path.join(os.path.dirname(tego), "tego-control")
try:
    if not waitfor(lambda: rd("read") is not None, 120):
        unknown.append("the Adjustable run never started: %s" % open(os.path.join(work, "run.err"), errors="replace").read()[-600:])
        raise SystemExit
    rc, o, e = sh("sudo", "-n", "sh", "-c", "ls -t %s/.tego/runs | head -n 1" % os.path.expanduser("~"))
    run_id = o.strip()
    facts["run_id"] = run_id
    rc, o, e = sh("stat", "-c", "%U %a", os.path.expanduser("~/.tego/runs/" + run_id))
    facts["run_dir_owner_mode"] = o.strip() + e.strip()

    def user(*args, as_root=False):
        a = (["sudo", "-n", tego] if as_root else [tego]) + list(args)
        rc, o, e = sh(*a)
        facts.setdefault("commands", []).append({"as_root": as_root, "argv": list(args)[:1] + ["<run>"] + list(args)[2:], "rc": rc, "stderr": e[-600:], "stdout": o[-160:]})
        return rc, o, e

    # the person's own commands against a run launched with sudo
    rc, o, e = user("lift", run_id, "read", vault, "--for", "1m", "--yes")
    facts["user_lift"] = {"rc": rc, "stderr": e.strip()}
    rc2, o2, e2 = user("grant", run_id, "exec", tool, "--yes")
    rc3, o3, e3 = user("restore", run_id, "read", vault)
    rc4, o4, e4 = user("block", run_id, "net", "example.invalid:443")
    rc5, o5, e5 = user("block", "--list", run_id)
    rc6, o6, e6 = user("mcp", "allow", run_id, "srv", "tool", "--yes")
    rc7, o7, e7 = user("route", "set", run_id, "ep", "r1", "--yes")
    facts["user_refusals"] = {"grant": [rc2, e2.strip()], "restore": [rc3, e3.strip()], "block": [rc4, e4.strip()], "block_list": [rc5, e5.strip()],
                              "mcp_allow": [rc6, e6.strip()], "route_set": [rc7, e7.strip()]}
    # the product's words: a refusal that names the cause and what to do, exit 1, [root-run]; not a bare permission denied
    for name, (rcx, ex) in [("lift", (rc, e)), ("grant", (rc2, e2)), ("restore", (rc3, e3)), ("block", (rc4, e4)), ("block --list", (rc5, e5)), ("mcp allow", (rc6, e6)), ("route set", (rc7, e7))]:
        check("the person's own `tego %s` against a root-launched run says it was launched as root and to use sudo, exit 1, [root-run]" % name,
              rcx == 1 and "[root-run]" in ex and "launched as root" in ex and "with sudo" in ex and "permission denied" not in ex, "rc %s %s" % (rcx, ex.strip()[:300]))
    check("the agent's read was not lifted by any of them", rd("read") == "refused", rd("read"))
    # the person's dashboard
    srv = subprocess.Popen([tego_control, "serve", "--addr", "127.0.0.1:8486"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        url = None
        end = time.time() + 20
        buf = ""
        import select
        while time.time() < end and url is None:
            r, _, _ = select.select([srv.stdout], [], [], 0.5)
            if r:
                line = srv.stdout.readline()
                buf += line
                m = re.search(r"(http://127\.0\.0\.1:8486/\?t=\S+)", line)
                if m:
                    url = m.group(1)
        if url is None:
            unknown.append("the dashboard printed no sign-in URL: " + buf[-300:])
            raise SystemExit
        op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        op.open(url, timeout=10).read()
        pages = {}
        for route in ("/runs", "/runs/" + run_id):
            try:
                r = op.open("http://127.0.0.1:8486" + route, timeout=15)
                body = r.read().decode(errors="replace")
                st = r.status
            except Exception as ex:
                body, st = "ERROR %s" % ex, getattr(ex, "code", 0)
            text = re.sub(r"\s+", " ", htmlmod.unescape(re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", re.sub(r"<[^>]+>", " ", body), flags=re.S)))
            pages[route] = {"status": st, "has_run_id": run_id[:14] in body, "lift_form": "/lift" in body, "text_head": text[:700]}
            open(os.path.join(work, "dash-%s.html" % route.strip("/").replace("/", "_")), "w").write(re.sub(r'(name="csrf" value=")[^"]+', r"\1REDACTED", body))
        facts["dashboard_pages"] = pages
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=10)
        except Exception:
            srv.kill()
    # control: root can, as docs/OPERATIONS says
    rc, o, e = user("lift", run_id, "read", vault, "--for", "1m", "--yes", as_root=True)
    check("as root (sudo) the same lift is asked and applied", rc == 0 and ": lifted " in o, "rc %s %s %s" % (rc, o[-120:], e[-160:]))
    check("after root's lift the agent's read goes through", says("read", "ok"), rd("read"))
    rc, o, e = user("restore", run_id, "read", vault, as_root=True)
    check("as root the restore is applied", rc == 0, "rc %s %s" % (rc, e[-160:]))
    rc, o, e = sh("sudo", "-n", tego, "stop", run_id)
    try:
        run.wait(timeout=60)
    except subprocess.TimeoutExpired:
        run.kill()
except SystemExit:
    pass
finally:
    try:
        open(os.path.join(out, "stop"), "w").write("1")
    except OSError:
        pass
    try:
        run.wait(timeout=30)
    except Exception:
        run.kill()
    rc, o, e = sh("pgrep", "-f", os.path.join(proj, "agent.sh"))
    for pid in o.split():
        sh("sudo", "-n", "kill", "-KILL", pid)

status = "UNKNOWN" if unknown else ("PASS" if checks and all(c["ok"] for c in checks) else "FAIL")
if status == "FAIL":
    note = "; ".join("%s (%s)" % (c["check"], c["detail"]) for c in checks if not c["ok"])
elif status == "UNKNOWN":
    note = "; ".join(unknown)
else:
    note = "the user's own lift, grant, restore, block, mcp and route against a root-launched run say [root-run] with sudo; root's lift works"
print(json.dumps({"status": status, "note": note, "checks": checks, "facts": facts, "unknown": unknown}, indent=1, default=str))
print("VERDICT %s %s" % (status, note.replace("\n", " ")[:700]))
