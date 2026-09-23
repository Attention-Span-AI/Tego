#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# kt6-fresh-vm.sh — kill test 6 (P0-DESIGN §10 "6 fresh VM in three halves (R16 as revised)"; §12
# acceptance items 1 and 2; docs/FEATURES.md "R16 / kill test 6": "one static binary; `doctor` prints
# the capability matrix with the machine's values, the highest tier it allows, what the next tier is
# missing, and the exact one-line fix; exit 0 when any tier runs, 211 when a requested tier cannot.
# Acceptance on a fresh Ubuntu 24.04 LTS image ... and only the binary: (a) as the invoking user,
# `doctor` reports `tier: landlock` and `tego run` passes R3 and R4 (refusal errno is EACCES in this
# tier, Python `PermissionError` either way); (b) with `sudo` and no boot change, `doctor` reports
# `tier: cgroup` and R5 host-level deny passes; (c) after adding `bpf` to `lsm=` exactly as printed and
# one reboot, `tier: bpflsm` and R5 passes with the in-kernel reason.").
#
# What it attacks: that a single static binary, dropped on a machine with nothing else installed,
# correctly identifies and uses whatever tier that machine actually offers — never claiming a tier
# it cannot enforce, never refusing to run at all when a real tier is available.
#
# The acceptance lines are what each half runs: R3 "two concurrent runs, 100% event
# attribution" is kill test 1 at tier landlock; R4 "write outside the worktree raises PermissionError;
# inside unaffected"; R5 "model endpoint reachable; undeclared host refused", made host-level by giving
# the declared and the undeclared host the same port, so only a rule that tells hosts apart refuses one
# and admits the other.
#
# The errno of a refused connect is EACCES in every tier (spec/policy/SEMANTICS.md §5, docs/p0/supervisor.md
# R10). At tier cgroup the supervisor that tier 2 inherits decides a connect first and never relays one it
# refuses, so the agent's refusal of the undeclared host is the supervisor's, and an EACCES alone shows
# nothing of tier 2's own program. Half (b) therefore also asks for its verdicts: tier 2's connect4 program
# writes each decision to a reason breadcrumb keyed by the run's cgroup (docs/p0/enforce-cgroup-observe.md R5),
# and this script reads it from the pinned map while the agent waits after its connects. The breadcrumb must
# show the agent's relayed connect to the declared host decided in the kernel; then a connect made from the
# run's cgroup by a process the supervisor does not see must be refused by the kernel for the undeclared
# host, with the kernel's own EPERM and a breadcrumb reading refused, net-not-allowed, and allowed for the
# declared one on the same port.
#
# Halves: `kt6-fresh-vm.sh [a] [b] [c]` (default: all three).
#   (a) runs as the invoking user. Started as root under sudo, it runs as SUDO_UID through setpriv, the
#       user sudo was typed by, so one `sudo kt6-fresh-vm.sh` covers all three halves.
#   (b) needs root under sudo. The kernel matrix runs it on a boot with the kernel's own lsm= list.
#   (c) needs root under sudo and `bpf` in the active LSM list. When bpf is not active, it prints the fix
#       doctor printed, `KT6-LSM-FIX <lsm= value>`, which test/vm/matrix.sh boots with for "exactly as
#       printed and one reboot" (passing the value back as KT6_LSM_FIX), and skips naming it. With bpf
#       active it says what activated it — that printed line, when the kernel's command line carries
#       exactly KT6_LSM_FIX, or the kernel's own default list, when the command line has no lsm= — and
#       requires tier bpflsm; where doctor refuses it, that is the half's named skip, with what activated
#       bpf in its text. Otherwise R5 must hold at tier bpflsm with the in-kernel reason, the breadcrumb
#       the run's network program wrote (as in half (b)), and the half passes only then.
#
# Exit 0 when every half that ran passed and at least one ran, 1 when one failed, 2 when none could run
# — see test/e2e/lib.sh. Each half prints a KT-HALF line.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=test/e2e/lib.sh
. "$repo_root/e2e/lib.sh"
kt_need_jq

halves=("$@")
[ "${#halves[@]}" -gt 0 ] || halves=(a b c)

tego="$(kt_ensure_tego)"
failed=0
ran=0
result() { # half verdict text
	kt_half kt6 "$1" "$2" "${*:3}"
	case "$2" in
	PASS) ran=1 ;;
	FAIL) ran=1; failed=1 ;;
	esac
}

# is_static reports whether a file is an ELF executable with no PT_INTERP program header: "one static
# binary" that runs with nothing else installed, not even a loader.
is_static() {
	python3 - "$1" <<-'PY'
	import struct, sys
	with open(sys.argv[1], "rb") as f:
	    ident = f.read(64)
	    if ident[:4] != b"\x7fELF" or ident[4] != 2:
	        sys.exit(1)
	    phoff, = struct.unpack_from("<Q", ident, 32)
	    phentsize, phnum = struct.unpack_from("<HH", ident, 54)
	    for i in range(phnum):
	        f.seek(phoff + i * phentsize)
	        if struct.unpack("<I", f.read(4))[0] == 3:  # PT_INTERP
	            sys.exit(1)
	PY
}

# r4_r5_agent is the workload of R4 and R5: it writes inside the declared directory and outside it, and
# connects to two hosts; it prints one line per attempt with the errno it met. With --hold before the hosts it
# then writes its pid to <out>/held and waits, up to 20 s, for <out>/release, so the run is still alive while
# kernel_probe reads what tier 2 decided.
r4_r5_agent() {
	cat >"$1" <<-'PY'
	import errno, os, socket, sys, time
	out, outside = sys.argv[1], sys.argv[2]
	hosts = sys.argv[3:]
	hold = hosts[:1] == ["--hold"]
	if hold:
	    hosts = hosts[1:]
	def attempt(label, fn):
	    try:
	        fn()
	        print(label, "ok", flush=True)
	    except PermissionError as e:
	        print(label, "PermissionError", errno.errorcode.get(e.errno, e.errno), flush=True)
	    except OSError as e:
	        print(label, "OSError", errno.errorcode.get(e.errno, e.errno), flush=True)
	def write(p):
	    with open(p, "w") as f:
	        f.write("x")
	attempt("write-inside", lambda: write(os.path.join(out, "inside.txt")))
	attempt("write-outside", lambda: write(outside))
	for hp in hosts:
	    host, port = hp.rsplit(":", 1)
	    def dial(host=host, port=int(port)):
	        with socket.create_connection((host, port), timeout=5) as s:
	            if s.recv(3) != b"ok\n":
	                raise OSError(errno.EPROTO, "no banner")
	    attempt("connect-" + hp, dial)
	if hold:
	    with open(os.path.join(out, "held.part"), "w") as f:
	        f.write(str(os.getpid()))
	    os.replace(os.path.join(out, "held.part"), os.path.join(out, "held"))
	    deadline = time.monotonic() + 20
	    while not os.path.exists(os.path.join(out, "release")) and time.monotonic() < deadline:
	        time.sleep(0.05)
	PY
}

# kernel_probe writes the check of tier 2's own verdicts, run as root while the agent of a tier-cgroup run
# holds: python3 <file> <agent pid> <port>. It prints one line, what it saw, and exits 0, or what was wrong
# and exits 1. It reads the breadcrumb through bpf(2) itself, so it needs nothing the kill test does not
# already need; the layout it decodes is bpf/include/events.h's struct tego_reason and its enum values.
#
# The breadcrumb is keyed by the run's cgroup id, the inode of the cgroup the agent was cloned into
# (docs/p0/runtime-launch.md), and it is the last decision only, so each check reads it right after the
# connect it is about. The probe's own connects are made from that cgroup, which is what makes the run's
# program decide them (a socket belongs to the cgroup it was created in), and outside the supervisor, since
# this process carries no seccomp filter: a connect the supervisor refused would never reach the kernel's
# program at all. Everything that opens a file (the maps, the cgroup files) is opened before it joins the
# run's cgroup, where tier 2's fanotify listener would decide its opens by the agent's contract, and it moves
# back out before it exits, so the run ends when its agent does. It is in the cgroup for one connect at a time
# and reads each breadcrumb after it has moved back out: the decision plane refuses every bpf(2) command of a
# governed task (docs/p0/enforce-plane.md §2.20, the `bpf` hook of E54), a map lookup included, and the agent,
# which holds, decides nothing in the cgroup between a connect and its read. While it is in the cgroup the
# run's recorder sees its two connects, so the ledger half (b) saves carries them as net lines from source
# kernel with the probe's pid, beside the agent's own.
kernel_probe() {
	cat >"$1" <<-'PY'
	import ctypes, errno, glob, os, platform, socket, struct, sys
	pid, port = int(sys.argv[1]), int(sys.argv[2])
	def fail(msg):
	    print(msg, flush=True)
	    sys.exit(1)
	NR_BPF = {"x86_64": 321, "aarch64": 280}.get(platform.machine())
	if NR_BPF is None:
	    fail("no bpf(2) number known for " + platform.machine())
	BPF_MAP_LOOKUP_ELEM, BPF_OBJ_GET, BPF_F_RDONLY = 1, 7, 1 << 3
	EV_CONNECT, V_ALLOW, V_REFUSED, R_NET_NOT_ALLOWED = 7, 0, 1, 8  # bpf/include/events.h
	libc = ctypes.CDLL(None, use_errno=True)
	libc.syscall.restype = ctypes.c_long
	def bpf(cmd, attr):
	    buf = ctypes.create_string_buffer(attr, len(attr))
	    r = libc.syscall(ctypes.c_long(NR_BPF), ctypes.c_long(cmd), buf, ctypes.c_long(len(attr)))
	    if r < 0:
	        e = ctypes.get_errno()
	        raise OSError(e, os.strerror(e))
	    return r
	def obj_get(path):
	    p = ctypes.create_string_buffer(path.encode())
	    return bpf(BPF_OBJ_GET, struct.pack("=QII", ctypes.addressof(p), 0, BPF_F_RDONLY))
	def lookup(fd, key):
	    k = ctypes.create_string_buffer(struct.pack("=Q", key))
	    v = ctypes.create_string_buffer(40)
	    try:
	        bpf(BPF_MAP_LOOKUP_ELEM, struct.pack("=IIQQQ", fd, 0, ctypes.addressof(k), ctypes.addressof(v), 0))
	    except OSError as e:
	        if e.errno == errno.ENOENT:
	            return None
	        raise
	    op, verdict, reason, family, proto, _, dport, addr, mono, _, _, _ = struct.unpack("=BBBBBBH16sQIHH", v.raw)
	    dst = socket.inet_ntop(socket.AF_INET, addr[:4]) if family == 2 else socket.inet_ntop(socket.AF_INET6, addr)
	    return {"op": op, "verdict": verdict, "reason": reason, "proto": proto, "dst": "%s:%d" % (dst, dport), "mono": mono}
	def expect(what, crumb, dst, verdict, reason, after):
	    if crumb is None:
	        fail("no breadcrumb for the run's cgroup after " + what)
	    want = {"op": EV_CONNECT, "verdict": verdict, "reason": reason, "proto": socket.IPPROTO_TCP, "dst": dst}
	    got = {k: crumb[k] for k in want}
	    if got != want or crumb["mono"] <= after:
	        fail("after %s the breadcrumb is %s, want %s written after %d" % (what, crumb, want, after))
	    return crumb["mono"]
	with open("/proc/%d/cgroup" % pid) as f:
	    rel = next(l.split("::", 1)[1].strip() for l in f if l.startswith("0::"))
	with open("/proc/self/cgroup") as f:
	    own = next(l.split("::", 1)[1].strip() for l in f if l.startswith("0::"))
	with open("/proc/self/mountinfo") as f:
	    mnt = next(l.split(" - ", 1)[0].split()[4] for l in f if l.split(" - ", 1)[1].split()[0] == "cgroup2")
	run_cg = os.path.join(mnt, rel.lstrip("/"))
	cgid = os.stat(run_cg).st_ino
	maps = {}
	for path in glob.glob("/sys/fs/bpf/tego/*/maps/tego_reason_map"):
	    maps[os.path.basename(os.path.dirname(os.path.dirname(path)))] = obj_get(path)
	if not maps:
	    fail("no pinned tego_reason_map under /sys/fs/bpf/tego: the run's network programs are not loaded")
	rows = {h: c for h, c in ((h, lookup(fd, cgid)) for h, fd in maps.items()) if c is not None}
	if len(rows) != 1:
	    fail("%d builds hold a breadcrumb for the run's cgroup %d (%s), want exactly the one attached to it" % (len(rows), cgid, run_cg))
	build, first = next(iter(rows.items()))
	fd = maps[build]
	t = expect("the agent's own connects", first, "127.0.0.1:%d" % port, V_ALLOW, 0, 0)
	into = os.open(os.path.join(run_cg, "cgroup.procs"), os.O_WRONLY)
	back = os.open(os.path.join(mnt, own.lstrip("/"), "cgroup.procs"), os.O_WRONLY)
	def dial(host):
	    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	    try:
	        s.connect((host, port))
	        s.settimeout(5)
	        return "ok" if s.recv(3) == b"ok\n" else "no banner"
	    except OSError as e:
	        return errno.errorcode.get(e.errno, str(e.errno))
	    finally:
	        s.close()
	def dial_in_run(host):
	    os.write(into, str(os.getpid()).encode())
	    try:
	        return dial(host)
	    finally:
	        os.write(back, str(os.getpid()).encode())
	refused = dial_in_run("127.0.0.2")
	crumb_refused = lookup(fd, cgid)
	allowed = dial_in_run("127.0.0.1")
	crumb_allowed = lookup(fd, cgid)
	if refused != "EPERM":
	    fail("from the run's cgroup, outside the supervisor, 127.0.0.2:%d gave %s, want the kernel's EPERM" % (port, refused))
	t = expect("the probe's connect to 127.0.0.2", crumb_refused, "127.0.0.2:%d" % port, V_REFUSED, R_NET_NOT_ALLOWED, t)
	if allowed != "ok":
	    fail("from the run's cgroup, outside the supervisor, 127.0.0.1:%d gave %s, want the listener's banner" % (port, allowed))
	expect("the probe's connect to 127.0.0.1", crumb_allowed, "127.0.0.1:%d" % port, V_ALLOW, 0, t)
	print("the run's connect4 decided the agent's relayed connect to 127.0.0.1:%d allow (breadcrumb, build %s);"
	      " from the run's cgroup outside the supervisor it refused 127.0.0.2:%d with EPERM, breadcrumb refused"
	      " net-not-allowed, and allowed 127.0.0.1:%d" % (port, build, port, port))
	PY
}

# listen_two serves "ok\n" on 127.0.0.1:<port> and 127.0.0.2:<same port> from outside every run, and
# prints the port. Linux answers the whole of 127.0.0.0/8 on lo, so the two are two hosts on one port.
listen_two() {
	local dir="$1"
	python3 - "$dir/listen.port" >"$dir/listen.log" 2>&1 <<-'PY' &
	import os, socket, sys, threading
	a = socket.create_server(("127.0.0.1", 0))
	port = a.getsockname()[1]
	b = socket.create_server(("127.0.0.2", port))
	def serve(s):
	    while True:
	        c, _ = s.accept()
	        c.sendall(b"ok\n")
	        c.close()
	threading.Thread(target=serve, args=(b,), daemon=True).start()
	with open(sys.argv[1] + ".part", "w") as f:
	    f.write(str(port))
	os.replace(sys.argv[1] + ".part", sys.argv[1])
	serve(a)
	PY
	kt_track_pid "$!"
	for _ in $(seq 100); do
		[ -s "$dir/listen.port" ] && break
		sleep 0.1
	done
	cat "$dir/listen.port" 2>/dev/null
}

# run_r4_r5 runs the R4/R5 agent at one tier under a contract that declares one write directory and,
# given the listeners' port, one host, and prints the work directory. $1 half, $2 tier, $3 port or "", and $4
# "probe" to run kernel_probe while the agent holds after its connects, leaving the probe's line in
# <work>/kernel.out and its exit in <work>/kernel.rc; the agent is released whatever the probe found.
run_r4_r5() {
	local half="$1" tier="$2" port="$3" probe="${4:-}" work out net="" hosts=() pid
	work="$(kt_workdir)"
	out="$work/out"
	mkdir -p "$out"
	kt_agent_owns "$out"
	kt_config "$work" >/dev/null
	r4_r5_agent "$work/agent.py"
	if [ -n "$port" ]; then
		net="net: { allow: [\"127.0.0.1:$port\"] }"
		hosts=("127.0.0.1:$port" "127.0.0.2:$port")
	fi
	cat >"$work/agent.yaml" <<-EOF
	version: 0
	name: kt6-$half
	command: ["python3", "$work/agent.py"]
	fs:
	  write: ["$out/"]
	$net
	exec:
	  allow: ["python3"]
	env:
	  pass: ["PATH", "HOME"]
	limits:
	  pids: 32
	  wall: 30s
	record: summary
	EOF
	if [ "$probe" != probe ]; then
		(cd "$work" && TEGO_CONFIG="$work/config.yaml" kt_run "$tego" run agent.yaml --tier "$tier" --offline -- \
			python3 "$work/agent.py" "$out" "$work/outside.txt" "${hosts[@]}") \
			>"$work/run.out" 2>"$work/run.err"
		echo $? >"$work/exit"
		echo "$work"
		return
	fi
	(cd "$work" && TEGO_CONFIG="$work/config.yaml" kt_run "$tego" run agent.yaml --tier "$tier" --offline -- \
		python3 "$work/agent.py" "$out" "$work/outside.txt" --hold "${hosts[@]}") \
		>"$work/run.out" 2>"$work/run.err" &
	pid=$!
	for _ in $(seq 1200); do
		[ ! -s "$out/held" ] || break
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.1
	done
	if [ -s "$out/held" ]; then
		kernel_probe "$work/probe.py"
		python3 "$work/probe.py" "$(cat "$out/held")" "$port" >"$work/kernel.out" 2>&1
		echo $? >"$work/kernel.rc"
	else
		echo "the agent never reached its hold after the connects, so tier 2's verdicts could not be read" >"$work/kernel.out"
		echo 1 >"$work/kernel.rc"
	fi
	: >"$out/release"
	wait "$pid"
	echo $? >"$work/exit"
	echo "$work"
}

# check_r5 judges a run of the R4/R5 agent for R5: the declared host reached, the undeclared one refused
# in the agent with a PermissionError carrying the errno $3, and on the ledger with a reason, recorded by the
# source $4 when one is given. EACCES is a refused connect's errno in every tier (the header). Prints the
# refusal's reason, or what was wrong.
check_r5() {
	local work="$1" port="$2" errno="$3" source="${4:-}" run reason
	run="$(kt_rundir "$work")"
	grep -q "^connect-127.0.0.1:$port ok" "$work/run.out" || { echo "the declared host 127.0.0.1:$port was not reachable: $(grep connect "$work/run.out")"; return 1; }
	grep -q "^connect-127.0.0.2:$port PermissionError $errno\$" "$work/run.out" ||
		{ echo "the undeclared host 127.0.0.2:$port on the same port was not refused with PermissionError $errno: $(grep "127.0.0.2" "$work/run.out")"; return 1; }
	reason="$(jq -r --arg t "127.0.0.2:$port" --arg s "$source" \
		'select(.kind == "refused" and .target == $t and ($s == "" or .source == $s)) | .reason // empty' "$run/events.jsonl" | head -1)"
	[ -n "$reason" ] || { echo "no refused event with a reason${source:+ from the $source} names 127.0.0.2:$port"; return 1; }
	echo "$reason"
}

# --- (a) as the invoking user --------------------------------------------------------------------
half_a() {
	local rep out tier reason work run
	if ! is_static "$tego"; then
		result a FAIL "$tego is not one static binary (it has a PT_INTERP loader)"
		return
	fi
	if ! out="$("$tego" doctor 2>&1)"; then
		result a FAIL "doctor exited non-zero on a machine where tier landlock runs: $(echo "$out" | tail -2)"
		return
	fi
	for want in "capability matrix for tier landlock" "tier: landlock" "missing for cgroup:" "fix:"; do
		if ! grep -q "$want" <<<"$out"; then
			result a FAIL "doctor's report has no \"$want\" line (R16: matrix, highest tier, what the next tier misses, the fix)"
			return
		fi
	done
	"$tego" doctor --require cgroup >/dev/null 2>&1
	rc=$?
	if [ "$rc" != 211 ]; then
		result a FAIL "doctor --require cgroup as the user exited $rc, R16 wants 211 for a tier that cannot run"
		return
	fi
	if ! out="$(KT_TIER=landlock "$repo_root/e2e/kt1-identity.sh" 2>&1)"; then
		result a FAIL "R3 (kill test 1 at tier landlock): $(echo "$out" | tail -1)"
		return
	fi
	work="$(run_r4_r5 a landlock "")"
	run="$(kt_rundir "$work")"
	[ -z "$run" ] || kt_save_fixture "kt6-a-landlock" "$run"
	if [ "$(cat "$work/exit")" != 0 ] || [ -z "$run" ]; then
		result a FAIL "tego run exited $(cat "$work/exit"): $(kt_err_line "$work/run.err")"
	elif ! grep -q "^write-inside ok" "$work/run.out"; then
		result a FAIL "R4: the write inside the declared directory failed: $(grep write-inside "$work/run.out")"
	elif ! grep -q "^write-outside PermissionError EACCES" "$work/run.out"; then
		result a FAIL "R4: the write outside was not a PermissionError with EACCES: $(grep write-outside "$work/run.out")"
	elif [ -e "$work/outside.txt" ]; then
		result a FAIL "R4: the refused write left $work/outside.txt behind"
	elif ! reason="$(jq -r --arg p "$work/outside.txt" 'select(.kind == "refused" and .target == $p) | .reason // empty' "$run/events.jsonl" | head -1)" || [ -z "$reason" ]; then
		result a FAIL "R4: no refused event with a reason names $work/outside.txt"
	else
		result a PASS "one static binary; doctor: tier landlock, the matrix, the next tier's gap and a fix, 211 for --require cgroup; R3 (kill test 1) passed; R4: EACCES, PermissionError, reason=$reason"
	fi
}

# --- (b) with sudo, no boot change -----------------------------------------------------------------
half_b() {
	local tier port work reason
	tier="$("$tego" doctor --json 2>/dev/null | jq -r '.tier // ""')"
	case "$tier" in
	cgroup | bpflsm) ;;
	*)
		result b FAIL "doctor as root reports tier \"$tier\", R16 (b) wants cgroup with sudo and no boot change: $("$tego" doctor 2>&1 | grep -E '^missing for cgroup' | head -1)"
		return
		;;
	esac
	port="$(listen_two "$(kt_workdir)")"
	[ -n "$port" ] || { result b FAIL "could not listen on 127.0.0.1 and 127.0.0.2"; return; }
	work="$(run_r4_r5 b cgroup "$port" probe)"
	[ -z "$(kt_rundir "$work")" ] || kt_save_fixture "kt6-b-cgroup" "$(kt_rundir "$work")"
	if [ "$(cat "$work/exit")" != 0 ]; then
		result b FAIL "tego run --tier cgroup exited $(cat "$work/exit"): $(kt_err_line "$work/run.err")"
	elif ! reason="$(check_r5 "$work" "$port" EACCES supervisor)"; then
		result b FAIL "R5: $reason"
	elif [ "$(cat "$work/kernel.rc")" != 0 ]; then
		result b FAIL "R5 in tier 2's own program: $(head -1 "$work/kernel.out")"
	else
		result b PASS "doctor: tier $tier as root; R5 host-level deny at tier cgroup: 127.0.0.1:$port reached, 127.0.0.2:$port refused to the agent with PermissionError EACCES by the supervisor, reason=$reason; $(head -1 "$work/kernel.out")"
	fi
}

# --- (c) bpf added to lsm=, one reboot ----------------------------------------------------------------
half_c() {
	local rep active fix lsm out rc port work reason cmdline_lsm booted
	rep="$("$tego" doctor --json 2>/dev/null)"
	active="$(jq -r '.lsm.bpf_active' <<<"$rep")"
	if [ "$active" != true ]; then
		fix="$(jq -r '.results[] | select(.id == "lsm") | .fix // empty' <<<"$rep")"
		lsm="$(sed -n 's/.*lsm=\([^ ]*\).*/\1/p' <<<"$fix")"
		[ -z "$lsm" ] || echo "KT6-LSM-FIX $lsm"
		result c SKIP "bpf is not in the active LSM list; doctor's fix is \"${fix:-<none printed>}\" and needs a reboot this script cannot do"
		return
	fi
	# What made bpf active: the line doctor printed, when test/vm/matrix.sh booted with it and says so in
	# KT6_LSM_FIX and the kernel's command line carries exactly that value, else the kernel's own default
	# list, when no lsm= is on the command line at all.
	cmdline_lsm="$(tr ' ' '\n' </proc/cmdline 2>/dev/null | sed -n 's/^lsm=//p' | tail -1)"
	if [ -z "$cmdline_lsm" ]; then
		booted="bpf is in this kernel's own default LSM list; no boot line was needed"
	elif [ -n "${KT6_LSM_FIX:-}" ] && [ "$cmdline_lsm" = "$KT6_LSM_FIX" ]; then
		booted="bpf is active after one boot with lsm=$cmdline_lsm, the line doctor printed"
	else
		booted="bpf is active with lsm=$cmdline_lsm on the command line, which is not a line doctor printed here"
	fi
	out="$("$tego" doctor --require bpflsm 2>&1)"
	rc=$?
	if [ "$rc" = 211 ]; then
		result c SKIP "$booted; tier bpflsm itself is refused: $(echo "$out" | tail -1)"
		return
	fi
	if [ "$rc" != 0 ]; then
		result c FAIL "doctor --require bpflsm exited $rc: $(echo "$out" | tail -1)"
		return
	fi
	port="$(listen_two "$(kt_workdir)")"
	[ -n "$port" ] || { result c FAIL "could not listen on 127.0.0.1 and 127.0.0.2"; return; }
	# R16 (c) asks for R5 "with the in-kernel reason". Tier bpflsm is tier cgroup's backend with the decision plane in
	# LSM mode (enforce-plane §2.10): its connects are decided by the same connect4 program, so the in-kernel reason
	# is half (b)'s breadcrumb, read the same way, from a run pinned at tier bpflsm (TIER3-PLAN T11).
	work="$(run_r4_r5 c bpflsm "$port" probe)"
	[ -z "$(kt_rundir "$work")" ] || kt_save_fixture "kt6-c-bpflsm" "$(kt_rundir "$work")"
	if [ "$(cat "$work/exit")" != 0 ]; then
		result c FAIL "tego run --tier bpflsm exited $(cat "$work/exit"): $(kt_err_line "$work/run.err")"
	elif ! reason="$(check_r5 "$work" "$port" EACCES supervisor)"; then
		result c FAIL "R5: $reason"
	elif [ "$(cat "$work/kernel.rc")" != 0 ]; then
		result c FAIL "R5 in the kernel's own program at tier bpflsm: $(head -1 "$work/kernel.out")"
	elif ! jq -e 'select(.kind == "run_start") | select(.tier == "bpflsm")' "$(kt_rundir "$work")/events.jsonl" >/dev/null; then
		result c FAIL "the run's run_start does not name tier bpflsm"
	else
		result c PASS "tier bpflsm ($booted): 127.0.0.2:$port refused with EACCES, reason=$reason; $(head -1 "$work/kernel.out")"
	fi
}

for h in "${halves[@]}"; do
	case "$h" in
	a)
		if ! kt_am_root; then
			half_a
		elif kt_sudo_user && command -v setpriv >/dev/null 2>&1; then
			# The invoking user is the one sudo names; the half runs as that user, from this script.
			home="$(getent passwd "$SUDO_UID" | cut -d: -f6)"
			ua="$(kt_workdir)/a.out"
			setpriv --reuid="$SUDO_UID" --regid="${SUDO_GID:-$SUDO_UID}" --clear-groups \
				env -u SUDO_UID -u SUDO_GID -u SUDO_USER -u SUDO_COMMAND HOME="${home:-/}" USER="${SUDO_USER:-}" \
				TEGO_BIN="$tego" TMPDIR=/tmp "$0" a >"$ua" 2>&1
			line="$(grep '^KT-HALF kt6 a ' "$ua" | head -1)"
			[ -n "$line" ] || line="KT-HALF kt6 a FAIL the user half printed no result: $(tail -2 "$ua" | tr '\n' ' ')"
			echo "$line"
			case "$line" in
			*" a PASS "*) ran=1 ;;
			*" a SKIP "*) ;;
			*) ran=1; failed=1 ;;
			esac
		else
			result a SKIP "runs as the invoking user; this is root with no SUDO_UID (or no setpriv) to become that user"
		fi
		;;
	b | c)
		if ! kt_sudo_user; then
			result "$h" SKIP "needs root under sudo"
		elif [ "$h" = b ]; then
			half_b
		else
			half_c
		fi
		;;
	*) echo "usage: $0 [a] [b] [c]" >&2; exit 2 ;;
	esac
done

[ "$failed" = 0 ] || kt_fail "a half of kill test 6 failed (KT-HALF lines above)"
[ "$ran" = 1 ] || kt_skip "no half of kill test 6 could run here (KT-HALF lines above)"
kt_pass "every half of kill test 6 that could run here passed (KT-HALF lines above name any that could not)"
