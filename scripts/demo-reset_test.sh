#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Destructive reproductions stay entirely inside a throwaway copy of the demo.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
t=$(mktemp -d "${TMPDIR:-/tmp}/demo-reset.XXXXXX")
trap 'rm -rf "$t"' EXIT
mkdir -p "$t/checkout/examples" "$t/bin" "$t/home"
cp -R "$here/../examples/demo" "$t/checkout/examples/demo"
demo=$t/checkout/examples/demo/demo.sh
cat >"$t/bin/systemctl" <<'EOF'
#!/bin/sh
echo called >>"$HOME/systemctl.log"
EOF
printf '#!/bin/sh\nexit 0\n' >"$t/bin/tego"
# Setup needs no real sink for these filesystem tests.
cat >"$t/bin/python3" <<'EOF'
#!/bin/sh
case $1 in
  -I) command -v python3.real ;;
  -c) test -e "$HOME/sink-started" ;;
  *) : >"$HOME/sink-started" ;;
esac
EOF
ln -s "$(command -v python3)" "$t/bin/python3.real"
chmod +x "$t/bin/systemctl" "$t/bin/tego" "$t/bin/python3"
fail=0
run_demo() {
	local stage=$1; shift
	rc=0
	env -i "HOME=$t/home" "PATH=$t/bin:$PATH" "DEMO_STAGE=$stage" TEGO=tego \
		sh "$demo" "$@" >"$t/out" 2>"$t/err" || rc=$?
}
# H5's original trigger, with an unrelated scratch directory in place of real HOME.
mkdir "$t/unrelated"
echo precious >"$t/unrelated/keep"
run_demo "$t/unrelated" reset
if [ "$rc" = 0 ] || [ ! -f "$t/unrelated/keep" ] || [ -e "$t/home/systemctl.log" ]; then
	echo 'FAIL: reset must refuse an unmarked directory before any cleanup'; fail=1
else echo 'ok: reset refuses an unmarked directory before cleanup'; fi

# A newline-only entry must not disappear in an emptiness check. A failed
# enumeration (even one that emits no entries) must also leave the stage unowned.
for shape in newline newlines hidden listing-error; do
	entry=$'\n'
	case $shape in newlines) entry=$'\n\n' ;; hidden) entry=$'.\n' ;; esac
	stage="$t/nonempty-$shape"
	mkdir -p "$stage/$entry"
	echo precious >"$stage/$entry/keep"
	if [ "$shape" = listing-error ]; then
		for tool in ls find; do printf '#!/bin/sh\nexit 65\n' >"$t/bin/$tool"; chmod +x "$t/bin/$tool"; done
	fi
	run_demo "$stage" setup
	if [ "$rc" = 0 ] || [ ! -f "$stage/$entry/keep" ] || [ -e "$stage/.tego-demo-stage" ]; then
		echo "FAIL: setup adopted a nonempty stage ($shape)"; fail=1
	else echo "ok: setup refuses a nonempty stage ($shape)"; fi
	if [ "$shape" = listing-error ]; then rm "$t/bin/ls" "$t/bin/find"; fi
done

# An actual setup writes the ownership marker. Reset keeps the container and
# unrelated siblings, removing only the explicitly generated children.
run_demo "$t/stage" setup
if [ "$rc" != 0 ]; then cat "$t/err"; exit 1; fi
echo precious >"$t/stage/keep"
mkdir "$t/stage/unrelated"
echo precious >"$t/stage/unrelated/keep"
run_demo "$t/stage" reset
if [ "$rc" != 0 ] || [ ! -f "$t/stage/keep" ] || [ ! -f "$t/stage/unrelated/keep" ] ||
	[ -e "$t/stage/project" ] || [ -e "$t/stage/secrets" ]; then
	echo 'FAIL: reset must retain the stage and unrelated children'; fail=1
else echo 'ok: reset removes generated children and keeps unrelated children'; fi

# Protected aliases must fail even with a correctly spelled marker. HOME and the
# checkout here are scratch copies; no destructive trigger uses a real home/tree.
for protected in "$t/home" "$t/checkout"; do
	printf '%s\n' "$protected" >"$protected/.tego-demo-stage"
	echo precious >"$protected/precious"
	ln -s "$protected" "$t/alias"
	for spelling in "$protected" "$t/alias" "$protected/../${protected##*/}"; do
		rm -f "$t/home/systemctl.log"
		run_demo "$spelling" reset
		if [ "$rc" = 0 ] || [ ! -f "$protected/precious" ] || [ -e "$t/home/systemctl.log" ]; then
			echo "FAIL: protected stage $spelling was not refused before cleanup"; fail=1
		else echo "ok: protected stage refused: $spelling"; fi
	done
	rm "$t/alias"
done

# Guard the root probe with stand-ins for rm, kill and systemctl: even a
# regression cannot delete real data or signal a real process.
cat >"$t/bin/rm" <<'EOF'
#!/bin/sh
echo called >"$HOME/rm.log"
exit 99
EOF
chmod +x "$t/bin/rm"
rc=0
# shellcheck disable=SC2016 # The child shell expands these variables and overrides kill.
env -i "HOME=$t/home" "PATH=$t/bin:$PATH" DEMO_STAGE=/ TEGO=tego \
	sh -c 'kill() { echo called >"$HOME/kill.log"; }; script=$1; shift; . "$script"' \
	"$demo" "$demo" reset >"$t/out" 2>"$t/err" || rc=$?
if [ "$rc" = 0 ] || [ -e "$t/home/rm.log" ] || [ -e "$t/home/kill.log" ] || [ -e "$t/home/systemctl.log" ]; then
	echo 'FAIL: root was not refused before cleanup'; fail=1
else echo 'ok: root refused before cleanup (rm is a stand-in)'; fi
rm "$t/bin/rm"

run_demo "$t/missing" reset
if [ "$rc" = 0 ] || [ -e "$t/missing" ]; then
	echo 'FAIL: reset created or adopted a missing stage'; fail=1
else echo 'ok: reset never creates a stage'; fi

mkdir "$t/forged"
printf '%s\n' "$t/stage" >"$t/forged/.tego-demo-stage"
echo precious >"$t/forged/keep"
run_demo "$t/forged" reset
if [ "$rc" = 0 ] || [ ! -f "$t/forged/keep" ]; then
	echo 'FAIL: reset accepted a copied marker'; fail=1
else echo 'ok: reset refuses a marker copied to another path'; fi
rm "$t/forged/.tego-demo-stage"
ln -s "$t/stage/.tego-demo-stage" "$t/forged/.tego-demo-stage"
run_demo "$t/forged" reset
if [ "$rc" = 0 ]; then echo 'FAIL: reset accepted a symlink marker'; fail=1
else echo 'ok: reset refuses a symlink marker'; fi

# rm of a generated child link may remove the link, never the target.
mkdir "$t/outside"
echo precious >"$t/outside/keep"
ln -s "$t/outside" "$t/stage/project"
run_demo "$t/stage" reset
if [ "$rc" != 0 ] || [ ! -f "$t/outside/keep" ] || [ -L "$t/stage/project" ]; then
	echo 'FAIL: reset followed a generated child symlink'; fail=1
else echo 'ok: reset unlinks a generated child symlink without following it'; fi

# A read that produces the expected marker text but reports I/O failure must
# still refuse; testing only command-substitution text would lose that error.
cat >"$t/bin/cat" <<'EOF'
#!/bin/sh
case $1 in */.tego-demo-stage) printf '%s\n' "${1%/*}"; exit 1 ;; esac
exec /bin/cat "$@"
EOF
chmod +x "$t/bin/cat"
mkdir "$t/stage/project"
echo precious >"$t/stage/project/keep"
run_demo "$t/stage" reset
if [ "$rc" = 0 ] || [ ! -f "$t/stage/project/keep" ]; then
	echo 'FAIL: reset ignored a marker read error'; fail=1
else echo 'ok: reset refuses a marker read error even with matching output'; fi
exit "$fail"
