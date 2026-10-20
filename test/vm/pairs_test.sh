#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests pairs.sh, the host driver of ADR 0021's pairs runs: what it builds and checks before any guest boots (the PIE
# must name a loader and the static build must not), which guests it boots (one per variant and boot, each with its
# variant's phases and environment, PAIRS_N's smoke counts, a kernel-matrix row's kernel), what it refuses before
# anything is built, and its reading of a guest's console into summary.json: a pass, a stall, a failed ledger
# assertion, a listener event answered late (a warning), a missing PAIRS-DONE, a guest that timed out, and a variant
# that fails does not stop the next.
#
# pairs.sh runs as written, from a copy of test/vm in a tree of stand-ins: a go that "builds" by writing a file (its
# elfinterp answers from the file's name, and says the PIE is static on request), a fetch-kernel.py that names rows,
# and a kvm-run.sh that records each boot and writes the console tier2-pairs.sh would have printed for the phases in
# the guest script it was handed, with a fault injected on request, in a serial console's CRLF lines among kernel
# messages. Nothing boots and no network is used.
#
# Usage: test/vm/pairs_test.sh. Exit 0 when every case passed, 1 on the first that did not.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/tego-pairs-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

fail() { echo "FAIL $*" >&2; exit 1; }

repo="$tmp/repo"
mkdir -p "$repo/test/vm/cmd/permlistener" "$repo/test/vm/cmd/elfinterp" "$repo/cmd/tego" "$tmp/bin"
cp "$here/pairs.sh" "$here/tier2-pairs.sh" "$repo/test/vm/"

cat >"$repo/test/vm/fetch-kernel.py" <<'EOF'
import os, sys
rows = dict(r.split(":") for r in os.environ.get("STUB_ROWS", "row-a:full row-d:doctor-only").split())
a = sys.argv[1:]
if a[:1] == ["--name"] and len(a) == 2 and a[1] in rows:
    print("matrix-" + a[1])
elif a[:1] == ["--body"] and len(a) == 2 and a[1] in rows:
    print(rows[a[1]])
elif len(a) == 1 and a[0] in rows:
    if a[0] == os.environ.get("STUB_FETCH_FAIL"):
        print("fetch-kernel: " + a[0] + ": the mirror no longer carries the package", file=sys.stderr)
        sys.exit(97)
    print("/stub/" + a[0] + "/vmlinuz")
else:
    sys.exit(2)
EOF

# kvm-run.sh: one line per boot (kernel, LSM, memory, the --env values, the console's directory), then the console
# tier2-pairs.sh would print for each phase of the guest script, and the status line. STUB_FAULT=<variant>:<fault>
# injects one fault into that variant's guest: stall, assert, late, nodone, notego, timeout.
cat >"$repo/test/vm/kvm-run.sh" <<'EOF'
#!/usr/bin/env python3
import os, re, sys
args = sys.argv[1:]
log = status = guest = None
envs = {}
files = []
i = 0
while i < len(args):
    a = args[i]
    if a == '--':
        break
    if a in ('--log', '--status', '--file', '--env', '--timeout'):
        v = args[i + 1]
        if a == '--log': log = v
        elif a == '--status': status = v
        elif a == '--file': files.append(v)
        elif a == '--env': k, _, val = v.partition('='); envs[k] = val
        i += 2
        continue
    i += 1
cmd = args[i + 1:]
for f in files:
    src, _, dst = f.rpartition(':')
    if dst == '/vm/pairs-guest.sh':
        guest = src
variant = os.path.basename(os.path.dirname(log))
with open(os.environ['STUB_BOOTS'], 'a') as b:
    b.write('variant=%s kernel=%s lsm=%s mem=%s smp=%s env=%s files=%s cmd=%s\n' % (
        variant, os.environ.get('TEGO_VM_KERNEL', 'unset'), os.environ.get('TEGO_VM_LSM', 'unset') or 'unset',
        os.environ.get('TEGO_VM_MEM'), os.environ.get('TEGO_VM_SMP'),
        ','.join('%s=%s' % kv for kv in sorted(envs.items())), ','.join(sorted(d.rpartition(':')[2] for d in files)),
        ' '.join(cmd)))
fault = ''
for f in os.environ.get('STUB_FAULT', '').split():
    v, _, what = f.partition(':')
    if v == variant:
        fault = what
out = ['[    0.000000] Linux version stub', 'Run /init as init process']
st = 'guest 0'
for line in open(guest):
    m = re.match(r"echo 'PAIRS-PHASE (\d+) plane=(\S+) mode=(\S+) pairs=(\d+)'", line)
    if not m:
        continue
    k, plane, mode, n = m.group(1), m.group(2), m.group(3), int(m.group(4))
    got = ('fanotify' if fault == 'autofallback' else 'lsm') if plane == 'auto' else plane
    out.append('PAIRS-PHASE %s plane=%s mode=%s pairs=%d' % (k, plane, mode, n))
    if envs.get('COPY_B') == '1':
        out.append('PAIRS-INODES a=2:1599 b=2:1612')
    lis = envs.get('LISTENER', '')
    if lis:
        out.append('PAIRS-LISTENER-READY pid=140')
    if envs.get('SELF_DENY') == '1':
        out.append('PAIR-CLEANUP 0 attempts=1 status=removed')
        out.append('PAIRS-SELF-DENY ok path=%s plane=%s' % (envs.get('TEGO'), got))
    for p in range(1, n + 1):
        out.append('PAIR %d rc=0,0' % p)
        out.append('[   %d.123456] some kernel line' % p)
        if p == 2 and k == '1':
            out.append('PAIR-CLEANUP 2 attempt=1 status=retry reason=enotempty rm_status=1')
        out.append('PAIR-CLEANUP %d attempts=1 status=removed' % p)
        if fault == 'stall' and p == 3:
            out += ['=== WATCHDOG: pair 4 made no progress for 20s (uptime 99.1); task stacks follow ===',
                    '--- 140 tego state: S (sleeping) wchan:fanotify_get_response',
                    '=== WATCHDOG: RECOVERED 1s after SIGKILL to the launchers (heartbeat 4-start -> 4-waited, uptime 120) ===',
                    '=== WATCHDOG: end of report; powering off ===', 'reboot: Power down']
            st = 'no-report'
            break
        if fault == 'assert' and p == 2 and k == '1':
            out.append('PAIRS-ASSERT-FAIL pair=2 what=refusal launcher=b rc=0 target=0 run=r-x read=refused '
                       'refused=0 end=exit plane=fanotify out=/tmp/pairs/out/b.2')
            break
    else:
        if lis:
            late = 2 if fault == 'late' else 0
            tego = 0 if fault == 'notego' else 41
            out.append('PAIRS-LISTENER rc=0 PERMLISTENER-STATS events=900 tego=%d self=400 late=%d denied=0 exec=90 '
                       'failed=0 malformed=0 mode=allow-touch' % (tego, late))
        kills = (0 if fault == 'killshort' else n - n // 4) if mode == 'kill' else 0
        if not (fault == 'nodone' and k == '2'):
            out.append('PAIRS-DONE %d/%d plane=%s copy_b=%s listener=%d mode=%s kills=%d kills_started=%d '
                       'killed_reads=%d' % (n, n, got, envs.get('COPY_B', '0'), 1 if lis else 0, mode, kills,
                                            kills // 2, kills // 8))
        short = fault == 'killshort' and mode == 'kill'
        if short:
            out.append('PAIRS-KILLS-SHORT landed=0 want=%d pairs=%d kill_min=50' % ((n + 1) // 2, n))
        out.append('PAIRS-PHASE-END %s rc=%d' % (k, 1 if (fault == 'nodone' and k == '2') or short else 0))
        continue
    if st != 'guest 0':
        break
    out.append('PAIRS-PHASE-END %s rc=1' % k)
if fault == 'timeout':
    st = 'timeout'
if st == 'guest 0':
    out.append('TEGO-VM-EXIT:0000:0')
with open(log, 'w', newline='') as f:
    f.write('\r\n'.join(out) + '\r\n')
with open(status, 'w') as f:
    f.write(st + '\n')
sys.exit({'guest 0': 0, 'no-report': 125, 'timeout': 124}[st])
EOF
chmod +x "$repo/test/vm/kvm-run.sh"

# go: build writes the file it is asked for with -o; elfinterp's is a script that answers from the file's name.
cat >"$tmp/bin/go" <<EOF
#!/usr/bin/env bash
echo "\$*" >>"$tmp/go.log"
out=""
while [ \$# -gt 0 ]; do [ "\$1" != -o ] || out="\$2"; shift; done
[ -n "\$out" ] || exit 0
case "\$out" in
*/elfinterp)
	cat >"\$out" <<'ELF'
#!/usr/bin/env bash
echo "\$*" >>"\$STUB_ELF"
want=\$2 f=\$3
kind=static
case "\$f" in *-pie) [ -n "\${STUB_PIE_STATIC:-}" ] || kind=pie ;; *) [ -z "\${STUB_STATIC_DYNAMIC:-}" ] || kind=pie ;; esac
echo "\$kind"
[ "\$kind" = "\$want" ]
ELF
	;;
*) printf '#!/bin/sh\nexit 0\n' >"\$out" ;;
esac
chmod +x "\$out"
EOF
chmod +x "$tmp/bin/go"

# run_pairs runs the copy of pairs.sh with the given variables; its status is in $rc, its stdout in $tmp/out, its
# stderr in $tmp/err, the boots (one line each) in $tmp/boots, the elfinterp checks in $tmp/elf.
run_pairs() {
	rm -rf "$tmp/boots" "$tmp/go.log" "$tmp/elf" "$tmp/vm-out"
	: >"$tmp/boots"
	: >"$tmp/elf"
	rc=0
	env -i PATH="$tmp/bin:$PATH" HOME="$tmp" TMPDIR="$tmp" GO="$tmp/bin/go" VM_OUT="$tmp/vm-out" \
		STUB_BOOTS="$tmp/boots" STUB_ELF="$tmp/elf" "$@" \
		bash "$repo/test/vm/pairs.sh" >"$tmp/out" 2>"$tmp/err" || rc=$?
}

# js prints one value of a summary: js <row/boot/variant> <python expression over s>.
js() { python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$tmp/vm-out/pairs/$1/summary.json" "$2"; }

# 1. Every variant, the bpf boot on this host's kernel: five builds-worth of binaries, the PIE and the static build
# checked before any boot, one guest per variant with its phases and environment, every summary a pass.
run_pairs
[ "$rc" = 0 ] || fail "all variants: exited $rc: $(cat "$tmp/err") $(cat "$tmp/out")"
grep -q -- '-buildmode=exe -tags tegobpf,tegotesthooks .*-o .*/pairs/bin/tego ./cmd/tego' "$tmp/go.log" || fail "no static test-hooks build: $(cat "$tmp/go.log")"
grep -q -- '-buildmode=pie -tags tegobpf,tegotesthooks .*-o .*/pairs/bin/tego-pie ./cmd/tego' "$tmp/go.log" || fail "no PIE test-hooks build: $(cat "$tmp/go.log")"
grep -q -- '-o .*/pairs/bin/permlistener ./test/vm/cmd/permlistener' "$tmp/go.log" || fail "no permlistener build"
{ grep -q '^-want pie .*/tego-pie$' "$tmp/elf" && grep -q '^-want static .*/bin/tego$' "$tmp/elf"; } || fail "the builds were not checked: $(cat "$tmp/elf")"
[ "$(wc -l <"$tmp/boots")" -eq 5 ] || fail "all variants: $(wc -l <"$tmp/boots") boots, want 5: $(cat "$tmp/boots")"
for v in two-inodes third-party guest-freeze pie plane-control; do
	grep -q "^variant=$v kernel=unset lsm=unset mem=1536M smp=2 " "$tmp/boots" || fail "$v: not booted on the host kernel's bpf boot: $(cat "$tmp/boots")"
	[ "$(js "host/bpf/$v" 's["pass"]')" = True ] || fail "$v: summary not a pass: $(cat "$tmp/vm-out/pairs/host/bpf/$v/summary.json")"
	grep -q "^pairs: host bpf $v PASS" "$tmp/out" || fail "$v: no PASS line: $(cat "$tmp/out")"
done
grep -q '^variant=two-inodes .*env=AGENT_SLEEP=0.05,COPY_B=1,TEGO=/usr/local/bin/tego ' "$tmp/boots" || fail "two-inodes env: $(cat "$tmp/boots")"
grep -q '^variant=third-party .*env=AGENT_SLEEP=0.05,LISTENER=/vm/permlistener,TEGO=/usr/local/bin/tego ' "$tmp/boots" || fail "third-party env"
grep -q '^variant=guest-freeze .*env=AGENT_SLEEP=1,CAPTURE=uprobe,TEGO=/usr/local/bin/tego ' "$tmp/boots" || fail "guest-freeze env"
grep -q '^variant=pie .*env=AGENT_SLEEP=0.05,COPY_B=1,SELF_DENY=1,TEGO=/usr/local/bin/tego-pie,TEGO_B=/usr/local/bin/tego ' "$tmp/boots" || fail "pie env"
grep -q '^variant=plane-control .*env=AGENT_SLEEP=0.05,COPY_B=1,LISTENER=/vm/permlistener,TEGO=/usr/local/bin/tego ' "$tmp/boots" || fail "plane-control env"
grep -q 'files=/usr/local/bin/tego,/usr/local/bin/tego-pie,/vm/pairs-guest.sh,/vm/permlistener,/vm/tier2-pairs.sh cmd=/bin/bash /vm/pairs-guest.sh$' "$tmp/boots" || fail "files or command: $(cat "$tmp/boots")"
g="$tmp/vm-out/pairs/host/bpf/two-inodes/guest.sh"
{ grep -q '^PAIRS_DIR=/tmp/pairs-1 PLANE=fanotify MODE=plain PAIRS=400 /bin/bash /vm/tier2-pairs.sh$' "$g" &&
	grep -q '^PAIRS_DIR=/tmp/pairs-2 PLANE=fanotify MODE=timeout PAIRS=300 ' "$g" &&
	grep -q '^PAIRS_DIR=/tmp/pairs-3 PLANE=fanotify MODE=kill PAIRS=300 ' "$g"; } || fail "two-inodes phases: $(cat "$g")"
grep -q '^PAIRS_DIR=/tmp/pairs-2 PLANE=auto MODE=plain PAIRS=50 ' "$tmp/vm-out/pairs/host/bpf/pie/guest.sh" || fail "pie phases"
[ "$(js host/bpf/two-inodes 's["pairs"], s["ok"], s["stall"], s["cleanup_retries"], s["plane"]')" = "(1000, 1000, False, 1, ['fanotify'])" ] ||
	fail "two-inodes summary: $(cat "$tmp/vm-out/pairs/host/bpf/two-inodes/summary.json")"
[ "$(js host/bpf/third-party 's["listener"]')" = "{'events': 2700, 'late': 0, 'tego': 123}" ] || fail "third-party listener: $(js host/bpf/third-party 's["listener"]')"
[ "$(js host/bpf/pie 's["plane"], [p["self_deny"] for p in s["phases"]]')" = "(['fanotify', 'lsm'], [True, True])" ] || fail "pie summary"
[ "$(js host/bpf/guest-freeze 's["pairs"]')" = 500 ] || fail "guest-freeze pairs"

# 2. PAIRS_N=50 is a smoke: every phase runs 50 pairs. PAIRS_BOOT=both boots each variant twice, the second time on the
# kernel's own LSM list. PAIRS_KERNEL=<row> boots the row's kernel and names the row in the results' path.
run_pairs PAIRS_N=50 VARIANTS="two-inodes pie" PAIRS_BOOT=both PAIRS_KERNEL=row-a
[ "$rc" = 0 ] || fail "smoke: exited $rc: $(cat "$tmp/err")"
[ "$(wc -l <"$tmp/boots")" -eq 4 ] || fail "smoke: $(wc -l <"$tmp/boots") boots, want 4"
[ "$(grep -c 'kernel=matrix-row-a lsm=unset' "$tmp/boots")" = 2 ] && [ "$(grep -c 'kernel=matrix-row-a lsm=kernel' "$tmp/boots")" = 2 ] ||
	fail "smoke: boots: $(cat "$tmp/boots")"
{ grep -q 'PAIRS=50 ' "$tmp/vm-out/pairs/row-a/default/two-inodes/guest.sh" && ! grep -Eq 'PAIRS=(400|300|200) ' "$tmp/vm-out/pairs/row-a/default/two-inodes/guest.sh"; } ||
	fail "smoke: phases not 50: $(cat "$tmp/vm-out/pairs/row-a/default/two-inodes/guest.sh")"
[ "$(js row-a/default/two-inodes 's["pairs"]')" = 150 ] || fail "smoke: two-inodes pairs"
[ "$(js row-a/bpf/pie 's["pairs"]')" = 100 ] || fail "smoke: pie pairs"

# 3. A PIE that came out static, or a static build that names a loader, stops everything before a guest boots.
run_pairs STUB_PIE_STATIC=1
{ [ "$rc" = 1 ] && [ ! -s "$tmp/boots" ] && grep -q 'not linked as the pie variant needs' "$tmp/err"; } || fail "a static PIE: rc=$rc boots=$(cat "$tmp/boots") $(cat "$tmp/err")"
run_pairs STUB_STATIC_DYNAMIC=1
[ "$rc" = 1 ] && [ ! -s "$tmp/boots" ] || fail "a dynamic static build: rc=$rc"

# 4. What pairs.sh refuses stops it before anything is built or booted.
refused() {
	local name="$1" want_rc="$2" want_text="$3"
	shift 3
	run_pairs "$@"
	[ "$rc" = "$want_rc" ] || fail "$name: exited $rc, want $want_rc: $(cat "$tmp/err")"
	grep -qF -- "$want_text" "$tmp/err" || fail "$name: stderr lacks \"$want_text\": $(cat "$tmp/err")"
	[ ! -s "$tmp/boots" ] || fail "$name: a guest booted"
	[ ! -s "$tmp/go.log" ] || fail "$name: something was built: $(cat "$tmp/go.log")"
}
refused "a variant that is not one" 2 "weird is not a variant" VARIANTS="two-inodes weird"
refused "a boot that is not one" 2 "PAIRS_BOOT must be" PAIRS_BOOT=lsm
refused "PAIRS_N=0" 2 "PAIRS_N must be a positive count" PAIRS_N=0
refused "PAIRS_N not a number" 2 "PAIRS_N must be a positive count" PAIRS_N=5x
refused "PAIRS_TIMEOUT not a number" 2 "PAIRS_TIMEOUT must be" PAIRS_TIMEOUT=1h
refused "a row that is not one" 2 "is not a kernel-matrix row" PAIRS_KERNEL=no-such-row
refused "a doctor-only row" 2 "doctor-only" PAIRS_KERNEL=row-d
refused "a kernel set by hand for another row" 2 "says another kernel" PAIRS_KERNEL=row-a TEGO_VM_KERNEL=matrix-row-d
refused "a kernel that cannot be fetched" 97 "the mirror no longer carries the package" PAIRS_KERNEL=row-a STUB_FETCH_FAIL=row-a

# 5. The console reader: each fault fails its own variant only, and the next variant still boots and passes.
run_pairs STUB_FAULT="two-inodes:stall third-party:late guest-freeze:assert pie:nodone plane-control:notego"
[ "$rc" = 1 ] || fail "faults: exited $rc, want 1"
[ "$(wc -l <"$tmp/boots")" -eq 5 ] || fail "faults: a failed variant stopped the rest: $(cat "$tmp/boots")"
[ "$(js host/bpf/two-inodes 's["pass"], s["stall"], s["guest"], s["ok"]')" = "(False, True, 'no-report', 0)" ] ||
	fail "stall: $(cat "$tmp/vm-out/pairs/host/bpf/two-inodes/summary.json")"
js host/bpf/two-inodes '"\n".join(s["reasons"])' | grep -q 'a watchdog report (stall)' || fail "stall: no reason"
js host/bpf/two-inodes 's["watchdog"][0]' | grep -q '^=== WATCHDOG: pair 4 made no progress' || fail "stall: watchdog line not kept"
grep -q '^pairs: host bpf two-inodes FAIL 0/1000 stall=true' "$tmp/out" || fail "stall: verdict line: $(cat "$tmp/out")"
# Kill phases count their landed kills: 300 pairs in the kill phase without PAIRS_N, 225 and 112 in the stand-in.
[ "$(js host/bpf/third-party 's["kills"], s["kills_started"], s["phases"][2]["kills"], s["phases"][0]["kills"]')" = "(225, 112, 225, 0)" ] ||
	fail "kills: $(cat "$tmp/vm-out/pairs/host/bpf/third-party/summary.json")"
# and the killed launchers' agents that read the secret in E15's window, 28 of them: disclosed as a warning.
[ "$(js host/bpf/third-party 's["killed_reads"], s["phases"][2]["killed_reads"], s["phases"][0]["killed_reads"]')" = "(28, 28, 0)" ] ||
	fail "killed_reads: $(cat "$tmp/vm-out/pairs/host/bpf/third-party/summary.json")"
grep -q "^pairs: host bpf third-party PASS .* WARN .*phase 3: in 28 pair(s) the killed launcher's agent read SECRET in E15's window" "$tmp/out" ||
	fail "killed_reads: no warning: $(cat "$tmp/out")"
[ "$(js host/bpf/third-party 's["pass"], s["listener"]["late"]')" = "(True, 6)" ] || fail "late: $(cat "$tmp/vm-out/pairs/host/bpf/third-party/summary.json")"
grep -q '^pairs: host bpf third-party PASS .* WARN phase 1: the listener answered 2 event(s) at its deadline' "$tmp/out" || fail "late: no warning: $(cat "$tmp/out")"
[ "$(js host/bpf/guest-freeze 's["pass"], len(s["asserts"])')" = "(False, 1)" ] || fail "assert: $(cat "$tmp/vm-out/pairs/host/bpf/guest-freeze/summary.json")"
js host/bpf/guest-freeze '"\n".join(s["reasons"])' | grep -q 'phase 1: PAIRS-DONE missing, want 200/200' || fail "assert: no missing-done reason"
[ "$(js host/bpf/pie 's["pass"], s["phases"][1]["done"], s["phases"][1]["rc"]')" = "(False, None, 1)" ] || fail "nodone: $(cat "$tmp/vm-out/pairs/host/bpf/pie/summary.json")"
js host/bpf/plane-control '"\n".join(s["reasons"])' | grep -q 'phase 1: the listener saw no tego event' || fail "notego"
# PLANE=auto that ran the fallback: the plane control proves nothing then (a failure); the PIE's plane phase is the
# second half of its variant, so on a row with no plane mode it is a warning, its fallback phase still the proof.
run_pairs VARIANTS="pie plane-control" STUB_FAULT="pie:autofallback plane-control:autofallback"
[ "$rc" = 1 ] || fail "autofallback: exited $rc, want 1"
js host/bpf/plane-control '"\n".join(s["reasons"])' | grep -q 'phase 1: PLANE=auto ran the fanotify fallback, and the plane control needs a plane mode' ||
	fail "autofallback: plane-control: $(cat "$tmp/vm-out/pairs/host/bpf/plane-control/summary.json")"
grep -q '^pairs: host bpf pie PASS .* WARN phase 2: PLANE=auto ran the fanotify fallback (no plane mode on this boot)' "$tmp/out" ||
	fail "autofallback: pie: $(cat "$tmp/out")"
run_pairs VARIANTS=two-inodes STUB_FAULT="two-inodes:killshort"
{ [ "$rc" = 1 ] && js host/bpf/two-inodes '"\n".join(s["reasons"])' | grep -q 'PAIRS-KILLS-SHORT landed=0 want=' &&
	js host/bpf/two-inodes '"\n".join(s["reasons"])' | grep -q 'phase 3: exit 1'; } ||
	fail "killshort: rc=$rc $(cat "$tmp/vm-out/pairs/host/bpf/two-inodes/summary.json")"
run_pairs VARIANTS=guest-freeze STUB_FAULT="guest-freeze:timeout"
{ [ "$rc" = 1 ] && js host/bpf/guest-freeze '"\n".join(s["reasons"])' | grep -q 'guest: timeout'; } || fail "timeout: rc=$rc"

# 6. --summarize alone reads a console it is given, and an empty console (a guest that never printed) is no pass.
printf 'PAIRS-PHASE 1 plane=fanotify mode=plain pairs=2\r\nPAIRS-INODES a=1:2 b=1:3\r\nPAIRS-DONE 2/2 plane=fanotify copy_b=1 listener=0 mode=plain\r\nPAIRS-PHASE-END 1 rc=0\r\n' >"$tmp/c1"
echo "guest 0" >"$tmp/s1"
bash "$repo/test/vm/pairs.sh" --summarize "$tmp/c1" "$tmp/s1" two-inodes host bpf fanotify:plain:2 >"$tmp/j1" || fail "--summarize exited $?"
python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); sys.exit(0 if s["pass"] and s["ok"] == 2 and s["inodes"] == ["a=1:2 b=1:3"] else 1)' "$tmp/j1" || fail "--summarize: $(cat "$tmp/j1")"
bash "$repo/test/vm/pairs.sh" --summarize "$tmp/c1" "$tmp/s1" two-inodes host bpf "fanotify:plain:2 fanotify:kill:2" >"$tmp/j2" || fail "--summarize 2"
python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); sys.exit(0 if not s["pass"] and "phase 2: PAIRS-DONE missing, want 2/2" in s["reasons"] else 1)' "$tmp/j2" || fail "--summarize, a phase never ran: $(cat "$tmp/j2")"
# A kill phase whose PAIRS-DONE has no kill count (a tier2-pairs.sh from before the count) proves no kill landed.
printf 'PAIRS-PHASE 1 plane=fanotify mode=kill pairs=2\r\nPAIRS-INODES a=1:2 b=1:3\r\nPAIRS-DONE 2/2 plane=fanotify copy_b=1 listener=0 mode=kill\r\nPAIRS-PHASE-END 1 rc=0\r\n' >"$tmp/c4"
bash "$repo/test/vm/pairs.sh" --summarize "$tmp/c4" "$tmp/s1" two-inodes host bpf fanotify:kill:2 >"$tmp/j4" || fail "--summarize 4"
python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); sys.exit(0 if not s["pass"] and "phase 1: kill mode with no count of the kills that landed" in s["reasons"] else 1)' "$tmp/j4" || fail "--summarize, a kill phase with no count: $(cat "$tmp/j4")"
: >"$tmp/c3"
bash "$repo/test/vm/pairs.sh" --summarize "$tmp/c3" "$tmp/missing" pie host bpf fanotify:plain:50 >"$tmp/j3" || fail "--summarize 3"
python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); sys.exit(0 if not s["pass"] else 1)' "$tmp/j3" || fail "--summarize, empty console passed"
bash "$repo/test/vm/pairs.sh" --summarize "$tmp/c1" 2>/dev/null && fail "--summarize with too few arguments"

echo "ok pairs_test.sh"
