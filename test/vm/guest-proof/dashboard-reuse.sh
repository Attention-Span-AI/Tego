#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# N8: `tego dashboard` and `tego start` reuse a running dashboard of the same program bytes and start another for
# other bytes. Run as an ordinary user inside a user scope, with /mnt/p2 mounted (guest-proof.py).
# shellcheck source=common.sh
. /mnt/p2/guest-proof/common.sh
OUT=$HOME/proof-out
mkdir -p "$OUT"
inv() { systemctl --user show tego-dashboard -p InvocationID --value; }
mainpid() { systemctl --user show tego-dashboard -p MainPID --value; }
link() { grep -o 'http://127.0.0.1:[0-9]*/?t=[0-9a-f]*' "$HOME/.tego/dashboard.log" | head -1; }
prog() { sed -n 's/^tego program sha256: //p' "$HOME/.tego/dashboard.log" | head -1; }
state() { echo "STATE $1: invocation=$(inv) mainpid=$(mainpid) link=$(link) program=$(prog)"; }
sumof() { sha256sum "$B/tego-control" | cut -d' ' -f1; }
facts

echo "== S1 pair A, no dashboard running: tego dashboard starts one"
inst A
A_SUM=$(sumof)
tego dashboard >"$OUT/s1.out" 2>&1; rc=$?
cat "$OUT/s1.out"; echo "rc=$rc"
state S1
INV1=$(inv); LINK1=$(link)
chk "S1 started a dashboard" "[ \"$rc\" = 0 ] && [ -n '$INV1' ] && grep -q 'Started the dashboard' $OUT/s1.out"
chk "S1 the log records pair A's tego-control bytes" "[ \"\$(prog)\" = '$A_SUM' ]"
PID1=$(mainpid)
echo "== undumpable: the owner cannot read the dashboard's /proc entries"
ls -ld "/proc/$PID1" ; readlink "/proc/$PID1/exe" 2>&1; cat "/proc/$PID1/environ" 2>&1 | head -c 80; echo
chk "the dashboard is undumpable (its /proc/PID/exe cannot be read by its own user)" "! readlink /proc/$PID1/exe >/dev/null 2>&1"
echo "link answers: $(curl -s -o /dev/null -w '%{http_code}' "$LINK1" 2>&1)"

echo "== S2 pair A, same bytes: tego dashboard again reuses it"
tego dashboard >"$OUT/s2.out" 2>&1; rc=$?
cat "$OUT/s2.out"; echo "rc=$rc"
state S2
chk "S2 said already running" "grep -q 'The dashboard is already running' $OUT/s2.out"
chk "S2 the same unit invocation and the same link" "[ \"\$(inv)\" = '$INV1' ] && [ \"\$(link)\" = '$LINK1' ] && grep -q -F '$LINK1' $OUT/s2.out"

echo "== S3 pair A, same bytes: tego start reuses it"
python3 /mnt/p2/guest-proof/drive-start.py "$OUT/s3.transcript"; rc=$?
echo "rc=$rc"; sed -e 's/\x1b\[[0-9;?]*[ -\/]*[@-~]//g' "$OUT/s3.transcript" | tr -d '\r' | grep -v '^\s*$' | tail -40
state S3
chk "S3 tego start finished" "[ $rc = 0 ]"
chk "S3 the same unit invocation and the same link" "[ \"\$(inv)\" = '$INV1' ] && [ \"\$(link)\" = '$LINK1' ]"
chk "S3 the Ready panel shows that link" "sed -e 's/\x1b\[[0-9;?]*[ -\/]*[@-~]//g' $OUT/s3.transcript | tr -d '\r' | grep -q -F '$LINK1'"

echo "== S4 pair B (other tego-control bytes): tego dashboard does not reuse A's dashboard"
inst B
B_SUM=$(sumof)
chk "pair B's tego-control differs from A's" "[ '$A_SUM' != '$B_SUM' ]"
tego dashboard >"$OUT/s4.out" 2>&1; rc=$?
cat "$OUT/s4.out"; echo "rc=$rc"
state S4
INV4=$(inv); LINK4=$(link)
chk "S4 started again on the updated tego" "grep -q 'Started the dashboard again' $OUT/s4.out"
chk "S4 a new unit invocation, another link" "[ -n '$INV4' ] && [ '$INV4' != '$INV1' ] && [ '$LINK4' != '$LINK1' ]"
chk "S4 the log records pair B's tego-control bytes" "[ \"\$(prog)\" = '$B_SUM' ]"

echo "== S5 pair B again: the new dashboard is reused"
tego dashboard >"$OUT/s5.out" 2>&1; rc=$?
cat "$OUT/s5.out"; echo "rc=$rc"
state S5
chk "S5 said already running, same invocation and link" "grep -q 'The dashboard is already running' $OUT/s5.out && [ \"\$(inv)\" = '$INV4' ] && [ \"\$(link)\" = '$LINK4' ]"

echo "== S6 back to pair A: tego start does not reuse B's dashboard"
inst A
python3 /mnt/p2/guest-proof/drive-start.py "$OUT/s6.transcript"; rc=$?
echo "rc=$rc"; sed -e 's/\x1b\[[0-9;?]*[ -\/]*[@-~]//g' "$OUT/s6.transcript" | tr -d '\r' | grep -v '^\s*$' | tail -40
state S6
INV6=$(inv); LINK6=$(link)
chk "S6 tego start finished" "[ $rc = 0 ]"
chk "S6 a new unit invocation, another link, pair A's bytes" "[ '$INV6' != '$INV4' ] && [ '$LINK6' != '$LINK4' ] && [ \"\$(prog)\" = '$A_SUM' ]"
chk "S6 the Ready panel shows the new link" "sed -e 's/\x1b\[[0-9;?]*[ -\/]*[@-~]//g' $OUT/s6.transcript | tr -d '\r' | grep -q -F '$LINK6'"

echo "== S7 pair A: reuse once more, after start's dashboard"
tego dashboard >"$OUT/s7.out" 2>&1; rc=$?
cat "$OUT/s7.out"
chk "S7 said already running, same invocation" "grep -q 'The dashboard is already running' $OUT/s7.out && [ \"\$(inv)\" = '$INV6' ]"

systemctl --user stop tego-dashboard tego-gc.timer tego-gc.service 2>&1 | head -3
echo "FAILS=$FAILS"
exit "$FAILS"
