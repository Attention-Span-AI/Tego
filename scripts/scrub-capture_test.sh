#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# scrub-capture_test.sh — scrub-capture.sh's own test: it plants a home path, a uid, a user name, a host name and an
# e-mail address in a capture and checks that none survives and that the text around them does.
# shellcheck disable=SC2016 # $HOME in single quotes is the placeholder text the scrub writes, on purpose
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
scrub=$here/scrub-capture.sh
fail=0
t=$(mktemp -d "${TMPDIR:-/tmp}/scrub-capture-test.XXXXXX")
trap 'rm -rf "$t"' EXIT

check() { # check <0|1> <what>
	if [ "$1" = 0 ]; then echo "ok    $2"; else echo "FAIL  $2"; fail=1; fi
}
has() { grep -qF -- "$1" "$2"; }
same() { if [ "$1" = "$2" ]; then echo 0; else echo 1; fi; }

export SCRUB_HOME=/home/quokka SCRUB_USER=quokka SCRUB_UID=4242 SCRUB_HOST=wombat-box.example.lan
cat >"$t/in.txt" <<'EOF'
$ ls /home/quokka/.claude/skills
open "/home/quokka/.claude/CLAUDE.md": read-denied (rule fs.deny_read[/home/quokka/.claude])
uid=4242(quokka) gid=4242 groups=4242
{"uid": 4242, "runtime": "/run/user/4242/tego/r-1"}
quokka@wombat-box:~$ hostname
wombat-box.example.lan
Co-Authored-By: someone <quokka.person+tag@mail.example.org>
4242 requests were answered.
~/.claude/projects/-home-quokka-work-x/abc.jsonl
Claude Code's project directory for the home itself: -home-quokka
/tmp/claude-4242/x
Uid:	4242	4242	4242	4242
UID 4242, user QUOKKA on WOMBAT-BOX
    Gid:	4242	4242	4242	4242
> Groups:	27 4242
uid=4242(quokka) gid=4242(quokka) groups=27(sudo),4242(quokka)
euid=4242 ruid=4242 fsgid=4242
{"uid" : 4242}
  File: x  Access: (0644/-rw-r--r--)  Uid: ( 4242/  quokka)   Gid: ( 4242/  quokka)
4242 is the uid that ran it
EOF
rc=0
"$scrub" "$t/in.txt" >"$t/out.txt" || rc=$?
check "$rc" "the scrub of a planted capture exits 0"
for planted in /home/quokka quokka@ "uid=4242" '"uid": 4242' /run/user/4242 wombat-box.example.lan "wombat-box:" quokka.person \
	mail.example.org "(quokka)" -home-quokka claude-4242 "Uid:	4242" "	4242	4242" "UID 4242" QUOKKA WOMBAT-BOX "Gid:	4242" " 4242" "gid=4242" "groups=27(sudo),4242" \
	"euid=4242" "ruid=4242" "fsgid=4242" '"uid" : 4242' "( 4242/" "4242 is"; do
	if has "$planted" "$t/out.txt"; then check 1 "removed: $planted"; else check 0 "removed: $planted"; fi
done
for kept in '$HOME/.claude/skills' 'fs.deny_read[$HOME/.claude]' 'uid=<uid>(<user>)' '"uid": <uid>' '/run/user/<uid>/tego' \
	'<user>@<host>:~$' '<host>' '<email>' '4242 requests were answered.' '.claude/projects/-$HOME-work-x/abc.jsonl' \
	'the home itself: -$HOME' '/tmp/claude-<uid>/x' 'Uid:	<uid>	<uid>	<uid>	<uid>' 'UID <uid>, user <user> on <host>' \
	'    Gid:	<uid>	<uid>	<uid>	<uid>' '> Groups:	27 <uid>' 'uid=<uid>(<user>) gid=<uid>(<user>) groups=27(sudo),<uid>(<user>)' \
	'euid=<uid> ruid=<uid> fsgid=<uid>' '{"uid" : <uid>}' 'Access: (0644/-rw-r--r--)  Uid: ( <uid>/  <user>)   Gid: ( <uid>/  <user>)' \
	'<uid> is the uid that ran it'; do
	if has "$kept" "$t/out.txt"; then check 0 "placeholder or text kept: $kept"; else check 1 "placeholder or text kept: $kept"; fi
done

# The leftover check is a plain substring search, in any case: a name the rules could not match (inside a longer word
# here) leaves the text as it was, says so on stderr and exits 1, and -i leaves such a file untouched.
printf 'quokkas and wombat-boxes are other words; /home/quokkas is another home\n' >"$t/left.txt"
rc=0
"$scrub" "$t/left.txt" >"$t/left.out" 2>"$t/left.err" || rc=$?
check "$(same "$rc" 1)" "a name left inside a longer word exits 1 (exit $rc)"
check "$(same "$(cat "$t/left.out")" 'quokkas and wombat-boxes are other words; /home/quokkas is another home')" \
	"... and the text around it is kept"
if has "still present after scrubbing" "$t/left.err"; then check 0 "... and stderr says so"; else check 1 "... and stderr says so"; fi
cp "$t/left.txt" "$t/left.i"
rc=0
"$scrub" -i "$t/left.i" 2>/dev/null || rc=$?
if [ "$rc" = 1 ] && cmp -s "$t/left.txt" "$t/left.i"; then check 0 "... and -i leaves the file as it was"; else
	check 1 "... and -i leaves the file as it was (exit $rc)"
fi
for w in Quokkas WOMBAT-BOXES; do
	rc=0
	printf '%s\n' "$w" | "$scrub" >/dev/null 2>&1 || rc=$?
	check "$(same "$rc" 1)" "the leftover check ignores case: $w (exit $rc)"
done

# -i scrubs in place; stdin works too.
cp "$t/in.txt" "$t/inplace.txt"
"$scrub" -i "$t/inplace.txt"
cmp -s "$t/inplace.txt" "$t/out.txt"
check "$?" "-i writes the same text in place"
printf 'at /home/quokka/x\n' | "$scrub" >"$t/stdin.txt"
check "$(same "$(cat "$t/stdin.txt")" 'at $HOME/x')" "stdin is scrubbed"

# A ledger line is refused, not scrubbed: its id would still commit to the text the scrub removed.
ledger='{"v":1,"seq":0,"id":"'$(printf 'a%.0s' {1..64})'","prev":"","run":"r-1","path":"/home/quokka/x"}'
printf '%s\n' "$ledger" >"$t/ledger.jsonl"
rc=0
"$scrub" "$t/ledger.jsonl" >"$t/ledger.out" 2>/dev/null || rc=$?
check "$(same "$rc:$(wc -c <"$t/ledger.out")" 2:0)" "a ledger line is refused and nothing is written (exit $rc)"
rc=0
"$scrub" -i "$t/ledger.jsonl" 2>/dev/null || rc=$?
if [ "$rc" = 2 ] && [ "$(cat "$t/ledger.jsonl")" = "$ledger" ]; then check 0 "... and -i leaves it as it was"; else
	check 1 "... and -i leaves it as it was (exit $rc)"
fi

# The real machine's names, read by default, are scrubbed too.
unset SCRUB_HOME SCRUB_USER SCRUB_UID SCRUB_HOST
real_home=$(getent passwd "$(id -u)" | cut -d: -f6)
printf 'home %s host %s\n' "$real_home" "$(hostname 2>/dev/null || uname -n)" | "$scrub" >"$t/real.txt"
check "$(same "$(cat "$t/real.txt")" 'home $HOME host <host>')" "the machine's own home and host name are scrubbed by default ($(cat "$t/real.txt"))"

exit "$fail"
