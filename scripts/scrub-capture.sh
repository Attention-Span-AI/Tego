#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# scrub-capture.sh — removes what names the machine and its account from captured text, before the text is committed
# (an end-to-end RESULTS.md, a terminal transcript): the account's home directory (the passwd database's and $HOME,
# every /home/<user> form, and Claude Code's project-directory name for it, where each character that is not a letter
# or a digit is a '-': -home-<user>-work), the user name (in any case, with anything but a letter, a digit or '_' on
# either side), the numeric uid where it stands as one (every standalone uid number on a line that names a uid, a gid
# or groups: uid=1000, euid= and the other e-, r-, s- and fs- forms, gid=, groups=, UID 1000, "uid" : 1000, every value
# of a /proc/<pid>/status Uid:, Gid: or Groups: line however it is indented or quoted, stat's Uid: ( 1000/ ...); and
# /run/user/1000, /user/1000, Claude Code's /tmp/claude-1000), the host name (long and short, in any case) and every
# e-mail address. Each becomes a placeholder: $HOME, <user>, <uid>, <host>, <email>.
#
# Usage: scrub-capture.sh [FILE...]        writes the scrubbed text to stdout (stdin when no FILE)
#        scrub-capture.sh -i FILE...       scrubs each FILE in place
# SCRUB_HOME, SCRUB_USER, SCRUB_UID and SCRUB_HOST replace what the script reads from the machine (the self-test
# plants its own). Exit 1 when the home, the user name or the host name is still anywhere in the output, as a plain
# substring in any case (inside a longer word too, which the rules leave alone): the scrubbed text is still written
# to stdout, but -i leaves the file untouched, so a person decides. Exit 2 on misuse, which includes text holding a
# ledger line, with nothing written: a line's id is the hash of its text, so a scrubbed line keeps a hash that still
# commits to the name it lost, and confirms a guess at it. Re-chain a ledger instead (test/fixtures/README.md).
set -euo pipefail

inplace=0
if [ "${1:-}" = -i ]; then
	inplace=1
	shift
	[ "$#" -gt 0 ] || { echo "scrub-capture: the in-place flag (-i) needs a file" >&2; exit 2; }
fi

uid=${SCRUB_UID:-$(id -u)}
user=${SCRUB_USER:-$(id -un)}
home=${SCRUB_HOME:-$(getent passwd "$uid" | cut -d: -f6)}
host=${SCRUB_HOST:-$(hostname 2>/dev/null || uname -n)}
env_home=${SCRUB_HOME:-${HOME:-}}

scrub() { # scrub < in > out
	# shellcheck disable=SC2016 # a Python program in single quotes, not shell text
	python3 -I -c '
import re, sys
home, env_home, user, uid, host = sys.argv[1:6]
s = sys.stdin.read()
if re.search(r"(?m)^\s*\{\"v\":\d+,\"seq\":\d+,\"id\":\"[0-9a-f]{64}\"", s):
    sys.stderr.write("scrub-capture.sh: this text holds ledger lines, whose hashes would keep what the scrub removes\n")
    sys.exit(2)
# A name ends where a letter, a digit or an underscore does not follow (or precede) it: "-", ".", "/" and the like
# delimit it, as they do in the forms Claude Code writes (-home-<user>-work, claude-<uid>).
B, A = r"(?<![A-Za-z0-9_])", r"(?![A-Za-z0-9_])"
homes = sorted({p.rstrip("/") for p in (home, env_home) if len(p.rstrip("/")) > 1}, key=len, reverse=True)
for h in homes:
    s = re.sub(re.escape(h) + A, lambda m: "$HOME", s)
for h in homes:  # Claude Code names a project directory after its path, each non-alphanumeric character a "-"
    s = re.sub(re.escape(re.sub(r"[^A-Za-z0-9]", "-", h)) + r"(?![A-Za-z0-9])", lambda m: "-$HOME", s)
if user:
    s = re.sub(r"/home/" + re.escape(user) + A, lambda m: "$HOME", s)
s = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "<email>", s)
if uid:
    u = re.escape(uid)
    # A line that names a uid, a gid or groups (uid=, euid=, fsgid=, groups=, "uid" :, UID, a status Uid: line
    # however it is indented or quoted, the Uid: ( 1000/ ...) of stat) loses every standalone uid number, wherever it
    # sits on that line.
    kw = re.compile(r"(?i)\b(?:e|r|s|fs)?[ug]id\b|\bgroups\b")
    num = re.compile(r"\b" + u + r"\b")
    s = "".join(num.sub("<uid>", ln) if kw.search(ln) else ln for ln in s.splitlines(keepends=True))
    s = re.sub(r"(/user/|/user-|\bclaude-)" + u + r"\b", r"\g<1><uid>", s)
names = []
if host:
    names += [host, host.split(".")[0]]
for n in sorted({n for n in names if len(n) > 1}, key=len, reverse=True):
    s = re.sub(r"(?i)" + B + re.escape(n) + A, "<host>", s)
if user and len(user) > 1:
    s = re.sub(r"(?i)" + B + re.escape(user) + A, "<user>", s)
# The leftover check: a plain substring search in any case, with the placeholders taken out first (a user named
# "user" is not left over in "<user>").
rest = s
for ph in ("$HOME", "<user>", "<uid>", "<host>", "<email>"):
    rest = rest.replace(ph, " ")
rest = rest.lower()
left = [w for w in homes + [user if len(user) > 1 else ""] + names if len(w) > 1 and w.lower() in rest]
sys.stdout.write(s)
if left:
    sys.stderr.write("scrub-capture.sh: still present after scrubbing: %d name(s)\n" % len(left))
    sys.exit(1)
' "$home" "$env_home" "$user" "$uid" "$host"
}

if [ "$inplace" = 1 ]; then
	for f in "$@"; do
		tmp=$(mktemp "$f.scrub.XXXXXX")
		rc=0
		scrub <"$f" >"$tmp" || rc=$?
		if [ "$rc" = 0 ]; then
			mv "$tmp" "$f"
		else
			rm -f "$tmp"
			exit "$rc"
		fi
	done
elif [ "$#" -gt 0 ]; then
	cat -- "$@" | scrub
else
	scrub
fi
