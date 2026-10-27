#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# mcp-tools-e2e.sh — per-tool MCP rules behind Tego's relay, end to end (ADR 0126 §4, package MCPTOOLS A3).
#
# One tier-landlock run of a python agent with two MCP servers behind the relay: files (stdio, the fake server of
# test/workloads/fake-mcp started through `tego mcp relay`) and web (the same server over HTTP on 127.0.0.1:$PORT,
# reached through the relay URL). The agent reads TEGO_MCP_CONFIG, starts the shim, and checks what the relay does:
# tools/list hides delete_file, read_file passes, delete_file is answered -32001 and never reaches the server (its
# call log), nor does one hidden between lone CRs in a ping, which the server frames as the official Python SDK does
# (universal newlines), write_file is held for a person (this script answers with tego approve, then tego deny), a direct start
# of the declared server is refused (rule mcp[files].relay), a live `tego mcp allow` lets the next delete_file
# through and a live `tego mcp deny` refuses the next read_file; the same on web, and a direct connect to the web
# server is refused by net. The ledger is then checked for the lines ADR 0126 §5 names.
#
# Isolation: everything under $W (ledger_root, chain anchor, own log, HOME); never the real ~/.tego. No model, no
# real agent. Needs TEGO (a -tags tegotesthooks build), python3 and jq.
#
# Exit 0 when every check passed, 1 when one failed, 77 when the box cannot run it.
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEGO="${TEGO:-$repo/bin/tego}"
W="${W:?set W to a scratch directory}"
PORT="${PORT:-9523}"
command -v python3 >/dev/null || { echo "SKIP: no python3"; exit 77; }
command -v jq >/dev/null || { echo "SKIP: no jq"; exit 77; }
[ -x "$TEGO" ] || { echo "SKIP: no tego at $TEGO"; exit 77; }

# Tego's own state ($S) and the agent's files ($A) are separate trees: the agent may never write tego's own.
S="$W/state"
A="$W/agent"
rm -rf "$W"
umask 077
mkdir -p "$S/ledger" "$S/own" "$W/home" "$A/work"
chmod 700 "$W" "$S" "$S/ledger"
printf 'ledger_root: %s\n' "$S/ledger" >"$S/tego.yaml"
chmod 600 "$S/tego.yaml"
mkdir -p "$W/xdg"
chmod 700 "$W/xdg"
# The run's runtime directory (TEGO_MCP_CONFIG's file) under the scratch tree, never the invoking user's /run/user.
export TEGO_CONFIG="$S/tego.yaml" TEGO_TEST_CHAIN_ANCHOR="$S/chain.log" TEGO_TEST_OWN_LOG_HOME="$S/own" HOME="$W/home" \
	XDG_RUNTIME_DIR="$W/xdg"

fails=0
check() { # check <name> <condition result 0/1>
	if [ "$2" = 0 ]; then echo "PASS $1"; else echo "FAIL $1"; fails=$((fails + 1)); fi
}

server="$repo/test/workloads/fake-mcp/server.py"
python3 "$server" --http "$PORT" --log "$W/web-calls.log" &
webpid=$!
trap 'kill $webpid 2>/dev/null' EXIT
sleep 0.5

cat >"$A/agent.py" <<'PY'
import errno, json, os, socket, subprocess, sys, time, urllib.request
W = sys.argv[1]
work = os.path.join(W, "work")
res = {}
def save():
    with open(os.path.join(work, "result.json"), "w") as f:
        json.dump(res, f, indent=1)
def wait_for(name, timeout=60):
    p = os.path.join(work, name)
    end = time.time() + timeout
    while time.time() < end:
        if os.path.exists(p):
            return True
        time.sleep(0.1)
    return False
def mark(name):
    open(os.path.join(work, name), "w").close()

cfg = json.load(open(os.environ["TEGO_MCP_CONFIG"]))["mcpServers"]
res["config"] = cfg
files = cfg["files"]
p = subprocess.Popen([files["command"]] + files["args"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
n = [0]
def rpc(method, params=None):
    n[0] += 1
    msg = {"jsonrpc": "2.0", "id": n[0], "method": method}
    if params is not None:
        msg["params"] = params
    p.stdin.write(json.dumps(msg) + "\n"); p.stdin.flush()
    return json.loads(p.stdout.readline())
def call(tool):
    return rpc("tools/call", {"name": tool, "arguments": {}})
def smuggle(tool):
    # One line, a ping with a member x, to the relay; forwarded as it came, a tools/call to a universal-newlines reader.
    n[0] += 2
    hidden = json.dumps({"jsonrpc": "2.0", "id": n[0], "method": "tools/call", "params": {"name": tool, "arguments": {}}})
    p.stdin.write('{"jsonrpc":"2.0","id":%d,"method":"ping","x":\r%s\r}\n' % (n[0] - 1, hidden)); p.stdin.flush()
    return json.loads(p.stdout.readline())
res["init"] = rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "e2e", "version": "1"}})
res["list"] = [t["name"] for t in rpc("tools/list")["result"]["tools"]]
res["read1"] = call("read_file")
res["delete1"] = call("delete_file")
res["smuggled"] = smuggle("delete_file")
def write_around(path):
    # A write-open through /proc needs no ptrace attach. A pipe opens, and what is written reaches the server undecided.
    try:
        fd = os.open(path, os.O_WRONLY)
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e.errno))
    os.write(fd, (json.dumps({"jsonrpc": "2.0", "id": 900, "method": "tools/call", "params": {"name": "delete_file", "arguments": {}}}) + "\n").encode())
    os.close(fd)
    return "opened"
kids = []
for task in os.listdir("/proc/%d/task" % p.pid):
    with open("/proc/%d/task/%s/children" % (p.pid, task)) as f:
        kids += f.read().split()
res["reopen"] = {"/proc/%s/fd/0" % k: write_around("/proc/%s/fd/0" % k) for k in kids}
for fd in os.listdir("/proc/%d/fd" % p.pid):
    path = "/proc/%d/fd/%s" % (p.pid, fd)
    try:
        if os.readlink(path).startswith("socket:["):
            res["reopen"][path] = write_around(path)
    except OSError:
        pass
save()
mark("ask1")                     # the script approves the next held call
res["write_approved"] = call("write_file")
mark("ask2")                     # the script denies this one
res["write_denied"] = call("write_file")
mark("ask3")                     # the script answers this one from the dashboard (POST /approvals/answer)
res["write_dashboard"] = call("write_file")
save()
try:
    q = subprocess.run(files["args"][5:], input=b"", capture_output=True, timeout=10)
    res["direct"] = {"rc": q.returncode, "err": q.stderr[-300:].decode(errors="replace")}
except Exception as e:
    res["direct"] = {"error": repr(e)}
save()
mark("phase2")                   # the script allows delete_file and denies read_file, live
wait_for("go2")
res["delete2"] = call("delete_file")
res["read2"] = call("read_file")
save()
web = cfg["web"]["url"]
def post(body):
    req = urllib.request.Request(web, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=10).read())
res["web_list"] = [t["name"] for t in post({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]]
res["web_read"] = post({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "read_file"}})
res["web_delete"] = post({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "delete_file"}})
try:
    s = socket.create_connection(("127.0.0.1", int(sys.argv[2])), timeout=5)
    res["web_direct"] = "connected"
    s.close()
except Exception as e:
    res["web_direct"] = repr(e)
save()
mark("phase3")                   # the script allows web delete_file live
wait_for("go3")
res["web_delete2"] = post({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "delete_file"}})
save()
p.stdin.close()
p.wait(timeout=10)
mark("done")
PY

cat >"$A/agent.yaml" <<YAML
version: 0
name: mcp-e2e
command: ["python3", "$A/agent.py", "$A", "$PORT"]
env:
  pass: [PATH, LANG, HOME, TEGO_MCP_RELAY, TEGO_MCP_CONFIG]
tier: landlock
fs:
  write: ["$A/work/"]
net:
  allow: []
ask:
  timeout: 2m
mcp:
  - name: files
    command: ["python3", "$server", "--log", "$A/work/files-calls.log"]
    tools: {deny: [delete_file], ask: [write_file]}
  - name: web
    url: "http://127.0.0.1:$PORT/mcp"
    tools: {deny: [delete_file]}
YAML

"$TEGO" run "$A/agent.yaml" >"$W/run.out" 2>"$W/run.err" &
runpid=$!
waitf() { # waitf <file> [seconds]
	local i=0 n=$((${2:-60} * 10))
	while [ ! -e "$A/work/$1" ] && [ $i -lt $n ]; do sleep 0.1; i=$((i + 1)); done
	[ -e "$A/work/$1" ]
}
run_id() { # the newest run folder in the scratch ledger
	local d n=""
	for d in "$S"/ledger/r-*; do
		[ -d "$d" ] || continue
		if [ -z "$n" ] || [ "$d" -nt "$S/ledger/$n" ]; then n="${d##*/}"; fi
	done
	echo "$n"
}
answer() { # answer approve|deny: answers the one pending ask of the run
	local i=0 id=""
	while [ $i -lt 100 ]; do
		id="$("$TEGO" ask "$(run_id)" --json 2>/dev/null | jq -r '.. | objects | select(has("ask_id")) | .ask_id' 2>/dev/null | head -1)"
		[ -n "$id" ] && break
		sleep 0.2
		i=$((i + 1))
	done
	[ -n "$id" ] || { echo "no pending ask"; return 1; }
	"$TEGO" "$1" "$(run_id)" "$id"
}
waitf ask1 60 || { echo "FAIL the agent never reached its first ask"; cat "$W/run.err"; exit 1; }
answer approve
check "tego approve answers the held write_file" $?
waitf ask2 60
answer deny
check "tego deny answers the held write_file" $?
waitf ask3 60
# The dashboard's answer: tego-control serve on its own port, signed in with its token, the form's CSRF token, and
# the Origin a browser sends.
DPORT="${DPORT:-9521}"
TG_CONTROL="${TEGO_CONTROL:-$(dirname "$TEGO")/tego-control}"
"$TG_CONTROL" serve --addr "127.0.0.1:$DPORT" --ledger "$S/ledger" >"$W/serve.out" 2>&1 &
servepid=$!
trap 'kill $webpid $servepid 2>/dev/null' EXIT
for _ in $(seq 50); do grep -q "Tego dashboard: " "$W/serve.out" && break; sleep 0.1; done
durl="$(sed -n 's/^Tego dashboard: //p' "$W/serve.out" | head -1)"
jar="$W/cookies"
curl -s -c "$jar" -o /dev/null "$durl"
dask=""
for _ in $(seq 100); do
	dask="$("$TEGO" ask "$(run_id)" --json 2>/dev/null | jq -r '.. | objects | select(has("ask_id")) | .ask_id' 2>/dev/null | head -1)"
	[ -n "$dask" ] && break
	sleep 0.2
done
csrf="$(curl -s -b "$jar" "http://127.0.0.1:$DPORT/approvals" | grep -o 'name="csrf" value="[0-9a-f]*"' | head -1 | sed 's/.*value="//; s/"//')"
code="$(curl -s -o /dev/null -w '%{http_code}' -b "$jar" -H "Origin: http://127.0.0.1:$DPORT" \
	--data-urlencode "csrf=$csrf" --data-urlencode "run=$(run_id)" --data-urlencode "ask=$dask" --data-urlencode "decision=approve" \
	"http://127.0.0.1:$DPORT/approvals/answer")"
check "the dashboard's POST /approvals/answer approves the held write_file (HTTP $code)" "$(if [ "$code" = 303 ] && [ -n "$dask" ]; then echo 0; else echo 1; fi)"
waitf phase2 60
R="$(run_id)"
"$TEGO" mcp allow "$R" files delete_file --yes
check "tego mcp allow (loosening, --yes)" $?
"$TEGO" mcp deny "$R" files read_file
check "tego mcp deny (tightening)" $?
sleep 0.7
# MCP_E2E_HOLD=<seconds> keeps the run live here, in its mixed state, for a person (or a screenshot) to look at.
if [ -n "${MCP_E2E_HOLD:-}" ]; then
	echo "HOLD $durl run=$R"
	sleep "$MCP_E2E_HOLD"
fi
touch "$A/work/go2"
waitf phase3 60
"$TEGO" mcp allow "$R" web delete_file --yes
check "tego mcp allow on the HTTP server" $?
"$TEGO" mcp tools "$R" >"$W/tools.out" 2>&1
check "tego mcp tools" $?
sleep 0.7
touch "$A/work/go3"
waitf "done" 60
wait $runpid
echo "run exit: $?"

r="$A/work/result.json"
j() { jq -e "$1" "$r" >/dev/null; echo $?; }
check "tools/list hides delete_file" "$(j '(.list | index("delete_file")) == null and (.list | index("write_file")) != null')"
check "read_file allowed" "$(j '.read1.result != null')"
check "delete_file refused -32001" "$(j '.delete1.error.code == -32001 and .delete1.error.data.tego.reason == "mcp-tool-denied"')"
check "delete_file hidden between CRs in a ping stays in the ping" "$(j '.smuggled.error.code == -32601')"
check "the server's stdin, and the shim's sockets, cannot be opened through /proc" "$(j '(.reopen | length) >= 3 and ([.reopen[] | select(. == "opened")] | length) == 0')"
check "held write_file approved" "$(j '.write_approved.result != null')"
check "held write_file denied" "$(j '.write_denied.error.data.tego.reason == "ask-denied"')"
check "held write_file approved from the dashboard" "$(j '.write_dashboard.result != null')"
check "direct start of the server refused" "$(j '.direct.rc != 0')"
check "live allow: delete_file passes" "$(j '.delete2.result != null')"
check "live deny: read_file refused" "$(j '.read2.error.data.tego.rule == "mcp[files].live[read_file]"')"
check "web tools/list hides delete_file" "$(j '(.web_list | index("delete_file")) == null')"
check "web read_file allowed" "$(j '.web_read.result != null')"
check "web delete_file refused" "$(j '.web_delete.error.code == -32001')"
check "direct connect to the web server refused" "$(j '.web_direct != "connected"')"
check "web live allow: delete_file passes" "$(j '.web_delete2.result != null')"
deletes="$(grep -c delete_file "$A/work/files-calls.log" 2>/dev/null)"
check "files server executed exactly one delete_file (after the live allow)" "$(if [ "$deletes" = 1 ]; then echo 0; else echo 1; fi)"
wdeletes="$(grep -c delete_file "$W/web-calls.log" 2>/dev/null)"
check "web server executed exactly one delete_file (after the live allow)" "$(if [ "$wdeletes" = 1 ]; then echo 0; else echo 1; fi)"

ev="$S/ledger/$R/events.jsonl"
jl() { jq -s -e "$1" "$ev" >/dev/null; echo $?; }
check "ledger: record_minor 25+" "$(jl '.[0].record_minor >= 25')"
check "ledger: mcp refused mcp-tool-denied by the contract" "$(jl 'map(select(.kind=="mcp" and .source=="proxy" and .verdict=="refused" and .reason=="mcp-tool-denied" and .rule=="mcp[files].tools.deny[delete_file]")) | length >= 1')"
check "ledger: mcp allow by human after the ask (CLI and dashboard)" "$(jl 'map(select(.kind=="mcp" and .authority=="human" and .verdict=="allow" and .tool=="write_file")) | length == 2')"
check "ledger: the dashboard's answer line (by tego-control's pid)" "$(jl 'map(select(.kind=="answer" and .approved==true and (.by | endswith("pid:'"$servepid"'")))) | length == 1')"
check "ledger: mcp refused ask-denied" "$(jl 'map(select(.kind=="mcp" and .reason=="ask-denied")) | length == 1')"
check "ledger: ask lines with op mcp_tool" "$(jl 'map(select(.kind=="ask" and .op=="mcp_tool")) | length == 3')"
check "ledger: exec refused mcp[files].relay" "$(jl 'map(select(.kind=="exec" and .rule=="mcp[files].relay" and .verdict=="refused")) | length >= 1')"
check "ledger: gap mcp-tool-changed per live change" "$(jl 'map(select(.kind=="gap" and .why=="mcp-tool-changed")) | length == 3')"
check "ledger: live rule on the refused read_file" "$(jl 'map(select(.kind=="mcp" and .rule=="mcp[files].live[read_file]")) | length == 1')"
check "ledger: http transport lines" "$(jl 'map(select(.kind=="mcp" and .transport=="http")) | length >= 3')"
"$TEGO" events "$R" --verify >"$W/verify.out" 2>&1
check "tego verify the run" $?
echo "run: $R  ledger: $ev"
[ $fails -eq 0 ] && { echo "ALL PASS"; exit 0; }
echo "$fails FAILED"
exit 1
