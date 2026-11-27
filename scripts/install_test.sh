#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Tests install.sh against a release laid out on local disk (curl reads file:// URLs), with stand-ins for
# cosign and gh whose answers each case chooses, so the decision paths run without a network or a real
# signature: which verifier auto mode picks, that a verifier which says no stops the install instead of
# falling back to the checksum, that a missing bundle is refused and a bundle that could not be fetched is a
# download failure, that both verifiers are held to the release workflow at the requested tag (a release
# signed or attested at another tag is refused), that a verifier's own output reaches the user, and that the
# checksum is still checked after all of it. tego-control is installed beside tego when the release lists one,
# held to the same checks and to tego's pin, moved in by rename, and a release from before it installs tego alone
# with a note; a tego that cannot be moved in says whether tego-control was already replaced. Every download tells an asset that is not there (exit 5, a
# question about the tag) from a server error or a network failure (exit 6, named): the archive, the
# checksums, the bundle and the "latest" lookup each have a case. The PATH each case runs with holds only
# the tools install.sh needs and the stand-ins the case wants, so a cosign or gh installed on the machine
# running the test changes nothing.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
installer="${here}/install.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-install-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

fail=0
check() { # check NAME WANT_EXIT GOT_EXIT
	if [ "$2" = "$3" ]; then
		echo "ok   $1"
	else
		echo "FAIL $1: exit $3, want $2" >&2
		sed 's/^/     /' "$tmp/out" >&2
		fail=1
	fi
}
expect() { # expect NAME PATTERN FILE
	if ! grep -q -- "$2" "$3"; then
		echo "FAIL $1: $3 lacks '$2'" >&2
		sed 's/^/     /' "$3" >&2
		fail=1
	fi
}

case "$(uname -m)" in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) echo "install_test: install.sh ships amd64 and arm64 only; nothing to test on $(uname -m)"; exit 0 ;;
esac

# The tools install.sh itself runs, linked into one directory that becomes the whole system PATH.
sysbin="$tmp/sysbin"
mkdir -p "$sysbin"
for t in sh curl sha256sum awk sed grep uname mktemp rm mkdir cp chmod mv basename cat id; do
	p=$(command -v "$t") || { echo "install_test: needs $t" >&2; exit 2; }
	ln -s "$p" "$sysbin/$t"
done

# One release, v0.0.1, whose binaries are scripts: tego answers `version` with the tego-control SHA-256 it pins, as a
# release build's does.
version=v0.0.1
rel="$tmp/releases/$version"
mkdir -p "$rel"
archive="tego_0.0.1_linux_${arch}"
control="tego-control_0.0.1_linux_${arch}"
sums="tego_0.0.1_checksums.txt"
# release [PIN]: writes the release's tego-control, a tego whose version names PIN (default: that tego-control's
# SHA-256) and the checksums file over both.
release() {
	printf '#!/bin/sh\necho "tego-control %s"\n' "$version" >"$rel/$control"
	pin=${1:-$(sha256sum "$rel/$control" | cut -d' ' -f1)}
	printf '#!/bin/sh\necho "tego %s"\necho "control_sha256=%s"\n' "$version" "$pin" >"$rel/$archive"
	resum
}
resum() { (cd "$rel" && sha256sum "$archive" "$control" >"$sums"); }
release
echo '{"stand-in":"bundle"}' >"$rel/$sums.sigstore.json"

# Stand-ins: each records its arguments and exits with what the case put in its environment. cosign and gh
# also play the release's signer: FAKE_SIGNED_TAG is the tag the served release was really signed and
# attested at (default: the one requested), and like the real tools they reject only what the caller asked
# them to pin. A verifier the installer does not hold to the tag therefore passes a release from another tag,
# which is the substitution the tag cases below catch.
fake="$tmp/fake"
mkdir -p "$fake/cosign" "$fake/gh" "$fake/curl"
cat >"$fake/cosign/cosign" <<'EOF'
#!/bin/sh
echo "$@" >>"$FAKE_LOG"
signed="https://github.com/Attention-Span-AI/Tego/.github/workflows/release.yml@refs/tags/${FAKE_SIGNED_TAG:-$TEGO_VERSION}"
prev=""
for a in "$@"; do
	if [ "$prev" = "--certificate-identity" ] && [ "$a" != "$signed" ]; then
		echo "fake-cosign: none of the expected identities matched what was in the certificate, got subjects [$signed]" >&2
		exit 1
	fi
	prev=$a
done
[ "${FAKE_COSIGN_EXIT:-0}" = 0 ] || echo "fake-cosign: error verifying bundle: the stand-in was told to say no" >&2
exit "${FAKE_COSIGN_EXIT:-0}"
EOF
cat >"$fake/gh/gh" <<'EOF'
#!/bin/sh
echo "$@" >>"$FAKE_LOG"
case "$1" in auth) exit "${FAKE_GH_AUTH_EXIT:-0}" ;; esac
# FAKE_GH_REFUSE: a file name whose attestation the stand-in does not find (one binary of the release unattested).
case "$*" in *"${FAKE_GH_REFUSE:-//none//}"*) echo "fake-gh: no attestations found for $FAKE_GH_REFUSE" >&2; exit 1 ;; esac
ref="refs/tags/${FAKE_SIGNED_TAG:-$TEGO_VERSION}"
workflow="Attention-Span-AI/Tego/.github/workflows/release.yml"
prev=""
for a in "$@"; do
	case "$prev" in
		--cert-identity) [ "$a" = "https://github.com/${workflow}@${ref}" ] || { echo "fake-gh: SAN does not match $a" >&2; exit 1; } ;;
		--source-ref) [ "$a" = "$ref" ] || { echo "fake-gh: source ref $ref does not match $a" >&2; exit 1; } ;;
		--signer-workflow) [ "$a" = "$workflow" ] || { echo "fake-gh: signer workflow does not match $a" >&2; exit 1; } ;;
	esac
	prev=$a
done
[ "${FAKE_GH_EXIT:-0}" = 0 ] || echo "fake-gh: verification failed: the stand-in was told to say no" >&2
exit "${FAKE_GH_EXIT:-0}"
EOF
# curl, in front of the real one, fails one download the way the case says: FAKE_CURL_ARCHIVE, _CONTROL, _SUMS,
# _BUNDLE and _API name the answer for the archive, the tego-control binary, the checksums file, the signature
# bundle and the "latest" lookup. net is a connection that never happened; a number is the server's HTTP status, which curl
# -f reports as exit 22 and, like the real one, prints only when -w asks for it. Everything else is the real
# curl.
cat >"$fake/curl/curl" <<'EOF'
#!/bin/sh
w=0
[ -z "${FAKE_CURL_LOG:-}" ] || echo "$@" >>"$FAKE_CURL_LOG"
for a in "$@"; do
	[ "$a" = -w ] && w=1
	last=$a
done
case "$last" in
	*.sigstore.json) answer=${FAKE_CURL_BUNDLE:-} ;;
	*_checksums.txt) answer=${FAKE_CURL_SUMS:-} ;;
	*/releases/latest) answer=${FAKE_CURL_API:-} ;;
	*/tego-control_*) answer=${FAKE_CURL_CONTROL:-} ;;
	*) answer=${FAKE_CURL_ARCHIVE:-} ;;
esac
case "$answer" in
	"") exec "$REAL_CURL" "$@" ;;
	net) [ "$w" = 0 ] || printf '000'; echo "curl: (7) Failed to connect" >&2; exit 7 ;;
	*) [ "$w" = 0 ] || printf '%s' "$answer"; echo "curl: (22) The requested URL returned error: $answer" >&2; exit 22 ;;
esac
EOF
chmod +x "$fake/cosign/cosign" "$fake/gh/gh" "$fake/curl/curl"

# run PATH_EXTRA [VAR=VALUE...]: install.sh with a fresh prefix and log; its exit code is returned.
run() {
	extra=$1
	shift
	rm -rf "$tmp/prefix" "$tmp/log" && : >"$tmp/log"
	set +e
	env -i HOME="$tmp" TMPDIR="$tmp" PATH="${extra:+$extra:}$sysbin" FAKE_LOG="$tmp/log" \
		TEGO_VERSION="$version" TEGO_BASE_URL="file://$tmp/releases" TEGO_PREFIX="$tmp/prefix" \
		"$@" "$sysbin/sh" "$installer" >"$tmp/out" 2>&1
	code=$?
	set -e
	return "$code"
}
installed() { [ -x "$tmp/prefix/tego" ]; }
installed_any() { [ -e "$tmp/prefix/tego" ] || [ -e "$tmp/prefix/tego-control" ]; }
# run_into [VAR=VALUE...]: install.sh in sha256 mode into the prefix as the case left it.
run_into() {
	set +e
	env -i HOME="$tmp" TMPDIR="$tmp" PATH="$sysbin" FAKE_LOG="$tmp/log" TEGO_VERSION="$version" \
		TEGO_BASE_URL="file://$tmp/releases" TEGO_PREFIX="$tmp/prefix" TEGO_VERIFY=sha256 \
		"$@" "$sysbin/sh" "$installer" >"$tmp/out" 2>&1
	code=$?
	set -e
	return "$code"
}

run "" TEGO_VERIFY=sha256 && code=0 || code=$?
check "sha256 mode installs on the checksum alone" 0 "$code"
installed || { echo "FAIL sha256 mode: nothing installed" >&2; fail=1; }

# A digest carried from a verified Mac release binds the guest's checksums before installation.
checksums_digest=$(sha256sum "$rel/$sums" | awk '{print $1}')
run "" TEGO_VERIFY=sha256 TEGO_CHECKSUMS_SHA256="$checksums_digest" && code=0 || code=$?
check "a matching supplied checksums digest installs without a verifier" 0 "$code"
printf '# changed after Mac verification\n' >>"$rel/$sums"
run "" TEGO_VERIFY=sha256 TEGO_CHECKSUMS_SHA256="$checksums_digest" && code=0 || code=$?
check "changed checksums are refused before installation" 7 "$code"
expect "the supplied checksums mismatch explains the refusal" "checksum mismatch for the pinned checksums file" "$tmp/out"
if [ -e "$tmp/prefix" ]; then echo "FAIL changed pinned checksums reached installation" >&2; fail=1; fi
release

run "" && code=0 || code=$?
check "auto mode with no verifier installs, and says the checksum is all it checked" 0 "$code"
expect "auto mode with no verifier" "not who published it" "$tmp/out"
# The note says how to get a verifier: it named cosign and not where it comes from (FIRST-TEN-MINUTES, stumble 12).
expect "auto mode with no verifier says where cosign comes from" "https://docs.sigstore.dev/cosign/system_config/installation/" "$tmp/out"
expect "auto mode with no verifier names gh's login" "gh auth login" "$tmp/out"

run "$fake/cosign" && code=0 || code=$?
check "auto mode picks cosign and installs when the bundle verifies" 0 "$code"
expect "cosign is asked about the checksums file" "verify-blob --bundle .*${sums}.sigstore.json" "$tmp/log"
expect "cosign is asked for the release workflow at this tag" \
	"--certificate-identity https://github.com/Attention-Span-AI/Tego/.github/workflows/release.yml@refs/tags/${version}" "$tmp/log"
expect "cosign is asked for GitHub's OIDC issuer" "--certificate-oidc-issuer https://token.actions.githubusercontent.com" "$tmp/log"

run "$fake/cosign" FAKE_COSIGN_EXIT=1 && code=0 || code=$?
check "auto mode with a cosign that says no refuses, without falling back" 9 "$code"
if installed; then echo "FAIL a release cosign rejected was installed" >&2; fail=1; fi

run "$fake/cosign" TEGO_VERIFY=cosign FAKE_COSIGN_EXIT=1 && code=0 || code=$?
check "cosign mode refuses a signature that does not verify" 9 "$code"

run "" TEGO_VERIFY=cosign && code=0 || code=$?
check "cosign mode without cosign is a missing dependency" 2 "$code"

run "$fake/cosign" FAKE_COSIGN_EXIT=1 && code=0 || code=$?
expect "a cosign that says no has its own words shown" "cosign: fake-cosign: error verifying bundle" "$tmp/out"

run "$fake/cosign" FAKE_SIGNED_TAG=v0.0.0 && code=0 || code=$?
check "cosign refuses a checksums file signed by the release workflow at another tag" 9 "$code"
if installed; then echo "FAIL a release signed at another tag was installed" >&2; fail=1; fi

mv "$rel/$sums.sigstore.json" "$tmp/bundle.away"
run "$fake/cosign" && code=0 || code=$?
check "a release without its signature bundle is refused when cosign is there to check it" 9 "$code"
expect "a missing bundle is named as missing" "has no signature bundle" "$tmp/out"
if grep -q 'TEGO_VERIFY=sha256' "$tmp/out"; then
	echo "FAIL a missing bundle suggests installing on the checksum alone, the bypass a stripped release wants" >&2
	fail=1
fi
mv "$tmp/bundle.away" "$rel/$sums.sigstore.json"

run "$fake/curl:$fake/cosign" REAL_CURL="$sysbin/curl" FAKE_CURL_BUNDLE=404 && code=0 || code=$?
check "a bundle the server answers 404 for is missing, and refused" 9 "$code"
expect "an HTTP 404 bundle is named as missing" "has no signature bundle" "$tmp/out"

run "$fake/curl:$fake/cosign" REAL_CURL="$sysbin/curl" FAKE_CURL_BUNDLE=net && code=0 || code=$?
check "a bundle that could not be fetched is a download failure, not a verdict on the release" 6 "$code"
if installed; then echo "FAIL a release whose bundle could not be fetched was installed" >&2; fail=1; fi

run "$fake/curl:$fake/cosign" REAL_CURL="$sysbin/curl" FAKE_CURL_BUNDLE=500 && code=0 || code=$?
check "a server error on the bundle is a download failure" 6 "$code"
expect "a server error on the bundle names the status" "HTTP 500" "$tmp/out"

run "$fake/gh" && code=0 || code=$?
check "auto mode picks a logged-in gh and installs when the attestation verifies" 0 "$code"
expect "gh is asked about the downloaded binary" "attestation verify .*${archive} --repo Attention-Span-AI/Tego" "$tmp/log"
expect "gh is asked for the release workflow at this tag" \
	"--cert-identity https://github.com/Attention-Span-AI/Tego/.github/workflows/release.yml@refs/tags/${version}" "$tmp/log"
expect "gh is asked for this tag as the source ref" "--source-ref refs/tags/${version}" "$tmp/log"

run "$fake/gh" FAKE_SIGNED_TAG=v0.0.0 && code=0 || code=$?
check "gh refuses a binary the release workflow attested at another tag" 9 "$code"
if installed; then echo "FAIL a binary attested at another tag was installed" >&2; fail=1; fi

run "$fake/gh" FAKE_GH_EXIT=1 && code=0 || code=$?
check "auto mode with a gh that says no refuses" 9 "$code"
expect "a gh that says no has its own words shown" "gh: fake-gh: verification failed" "$tmp/out"

run "$fake/gh" FAKE_GH_AUTH_EXIT=1 && code=0 || code=$?
check "a gh that is not logged in is not a verifier: auto falls back to the checksum" 0 "$code"

run "" TEGO_VERIFY=bogus && code=0 || code=$?
check "an unknown TEGO_VERIFY is a usage error" 2 "$code"

# The release's own assets: only an asset that is not there says the tag may be wrong.
run "$fake/curl" REAL_CURL="$sysbin/curl" FAKE_CURL_ARCHIVE=500 && code=0 || code=$?
check "a server error on the archive is a download failure, not a missing release" 6 "$code"
expect "a server error on the archive names the status" "HTTP 500 for the linux/${arch} archive" "$tmp/out"
if grep -q 'real tego release' "$tmp/out"; then
	echo "FAIL a server error on the archive was reported as a tag that does not exist" >&2
	fail=1
fi
if installed; then echo "FAIL a release whose archive could not be fetched was installed" >&2; fail=1; fi

run "$fake/curl" REAL_CURL="$sysbin/curl" FAKE_CURL_ARCHIVE=404 && code=0 || code=$?
check "an archive the server answers 404 for is a missing release" 5 "$code"
expect "an HTTP 404 archive asks whether the tag is real" "is '${version}' a real tego release" "$tmp/out"

run "$fake/curl" REAL_CURL="$sysbin/curl" FAKE_CURL_SUMS=503 && code=0 || code=$?
check "a server error on the checksums file is a download failure" 6 "$code"
expect "a server error on the checksums file names the status" "HTTP 503 for the checksums file" "$tmp/out"

run "$fake/curl" REAL_CURL="$sysbin/curl" FAKE_CURL_ARCHIVE=net && code=0 || code=$?
check "an archive that could not be fetched is a download failure" 6 "$code"

run "" TEGO_VERIFY=sha256 TEGO_VERSION=v9.9.9 && code=0 || code=$?
check "a tag the mirror has no files for is a missing release" 5 "$code"

# "latest", looked up through TEGO_API_URL when TEGO_VERSION is empty.
printf '{"url":"x","tag_name":"%s","name":"x"}\n' "$version" >"$tmp/latest"
run "" TEGO_VERIFY=sha256 TEGO_VERSION= TEGO_API_URL="file://$tmp/latest" && code=0 || code=$?
check "an empty TEGO_VERSION installs the tag the latest lookup names" 0 "$code"
expect "the latest lookup's tag is the one installed" "installed tego ${version}" "$tmp/out"
expect "the install says where the licence notices are" "licence notices: .*_licenses.tar.gz" "$tmp/out"
expect "the install says a service account needs its own copy, because sudo does not search ~/.local/bin" "install both binaries in that account's ~/.local/bin" "$tmp/out"

run "$fake/curl" REAL_CURL="$sysbin/curl" TEGO_VERIFY=sha256 TEGO_VERSION= \
	TEGO_API_URL="https://api.github.invalid/repos/Attention-Span-AI/Tego/releases/latest" FAKE_CURL_API=403 && code=0 || code=$?
check "a rate-limited latest lookup is a download failure, not a repository without releases" 6 "$code"
expect "a rate-limited latest lookup names the status" "answered HTTP 403" "$tmp/out"

run "$fake/curl" REAL_CURL="$sysbin/curl" TEGO_VERIFY=sha256 TEGO_VERSION= \
	TEGO_API_URL="https://api.github.invalid/repos/Attention-Span-AI/Tego/releases/latest" FAKE_CURL_API=404 && code=0 || code=$?
check "a latest lookup the API answers 404 for means no release yet" 5 "$code"
expect "a 404 latest lookup says there is no release" "has no published release yet" "$tmp/out"

# The repository install.sh names is the one the release is built in (release.yml runs this check first).
"$here/check-installer-repo.sh" Attention-Span-AI/Tego >/dev/null && code=0 || code=$?
check "check-installer-repo accepts the repository install.sh names" 0 "$code"
# A release built in a repository other than the one install.sh names is refused.
"$here/check-installer-repo.sh" example-org/other-repo >"$tmp/out" 2>&1 && code=0 || code=$?
check "check-installer-repo refuses a release built in another repository" 1 "$code"
expect "check-installer-repo names both" "Attention-Span-AI/Tego, but this release is built in example-org/other-repo" "$tmp/out"

# A server that accepts the connection and then sends nothing ends at TEGO_MAX_TIME as a network failure,
# for the archive and for the "latest" lookup, instead of hanging the install.
if command -v python3 >/dev/null 2>&1; then
	python3 - "$tmp/stall.port" <<'PY' &
import socket, sys, time
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(8)
open(sys.argv[1], "w").write(str(s.getsockname()[1]))
conns = []
while True:
    conns.append(s.accept()[0])
PY
	stall_pid=$!
	n=0
	while [ ! -s "$tmp/stall.port" ] && [ "$n" -lt 100 ]; do sleep 0.1; n=$((n + 1)); done
	port=$(cat "$tmp/stall.port")
	run "" TEGO_VERIFY=sha256 TEGO_MAX_TIME=10 TEGO_BASE_URL="http://127.0.0.1:$port" && code=0 || code=$?
	check "a stalled archive download ends as a network failure" 6 "$code"
	run "" TEGO_VERIFY=sha256 TEGO_MAX_TIME=10 TEGO_VERSION= TEGO_API_URL="http://127.0.0.1:$port/latest" && code=0 || code=$?
	check "a stalled latest lookup ends as a network failure" 6 "$code"
	kill "$stall_pid" 2>/dev/null || true
	wait "$stall_pid" 2>/dev/null || true
else
	echo "skip a stalled server: no python3"
fi

# TERM ends the install: the trap cleaned up and let the shell carry on to the next step with its temporary
# directory gone. A curl stand-in holds the archive download until the test has sent
# TERM; the installer must then exit 143 with nothing installed and no temporary directory left. INT gets
# the same trap, exit 130, but cannot be sent this way: a background job of a non-interactive shell starts
# with SIGINT ignored, and a signal ignored on entry cannot be trapped.
mkdir -p "$fake/hang"
cat >"$fake/hang/curl" <<'EOF'
#!/bin/sh
for a in "$@"; do last=$a; done
case "$last" in
	*_checksums.txt | *.sigstore.json | */releases/latest) exec "$REAL_CURL" "$@" ;;
esac
echo $$ >"$FAKE_HANG_PID"
while :; do "$FAKE_SLEEP" 1; done
EOF
chmod +x "$fake/hang/curl"
rm -rf "$tmp/prefix" "$tmp/hang.pid"
env -i HOME="$tmp" TMPDIR="$tmp" PATH="$fake/hang:$sysbin" REAL_CURL="$sysbin/curl" FAKE_HANG_PID="$tmp/hang.pid" \
	FAKE_SLEEP="$(command -v sleep)" \
	TEGO_VERSION="$version" TEGO_BASE_URL="file://$tmp/releases" TEGO_PREFIX="$tmp/prefix" TEGO_VERIFY=sha256 \
	"$sysbin/sh" "$installer" >"$tmp/out" 2>&1 &
pid=$!
i=0
while [ ! -s "$tmp/hang.pid" ] && [ "$i" -lt 100 ]; do
	sleep 0.1
	i=$((i + 1))
done
kill -TERM "$pid"
[ -s "$tmp/hang.pid" ] && kill -KILL "$(cat "$tmp/hang.pid")" 2>/dev/null
set +e
wait "$pid"
code=$?
set -e
check "TERM ends the install with 143" 143 "$code"
if installed; then echo "FAIL an install sent TERM installed tego" >&2; fail=1; fi
for d in "$tmp"/tego-install.*; do
	[ -e "$d" ] && { echo "FAIL an install sent TERM left $d behind" >&2; fail=1; }
done

# A verified download that will not run leaves the installed binary alone.
printf '#!/nonexistent/interpreter\n' >"$rel/$archive"
resum
rm -rf "$tmp/prefix" "$tmp/log" && mkdir -p "$tmp/prefix"
printf '#!/bin/sh\necho old\n' >"$tmp/prefix/tego"
chmod 755 "$tmp/prefix/tego"
set +e
env -i HOME="$tmp" TMPDIR="$tmp" PATH="$sysbin" FAKE_LOG="$tmp/log" TEGO_VERSION="$version" \
	TEGO_BASE_URL="file://$tmp/releases" TEGO_PREFIX="$tmp/prefix" TEGO_VERIFY=sha256 \
	"$sysbin/sh" "$installer" >"$tmp/out" 2>&1
code=$?
set -e
check "a download that will not run is refused" 8 "$code"
grep -q old "$tmp/prefix/tego" || { echo "FAIL a download that would not run replaced the working tego" >&2; fail=1; }
for f in "$tmp"/prefix/.tego.tmp.*; do
	[ -e "$f" ] && { echo "FAIL a refused download left $f behind" >&2; fail=1; }
done
release

# A directory where the binary belongs is refused, not installed into.
rm -rf "$tmp/prefix" "$tmp/log" && mkdir -p "$tmp/prefix/tego"
set +e
env -i HOME="$tmp" TMPDIR="$tmp" PATH="$sysbin" FAKE_LOG="$tmp/log" TEGO_VERSION="$version" \
	TEGO_BASE_URL="file://$tmp/releases" TEGO_PREFIX="$tmp/prefix" TEGO_VERIFY=sha256 \
	"$sysbin/sh" "$installer" >"$tmp/out" 2>&1
code=$?
set -e
check "a directory at the install path is refused" 8 "$code"
if grep -q '^installed tego' "$tmp/out"; then echo "FAIL a directory at the install path was reported installed" >&2; fail=1; fi
for f in "$tmp"/prefix/tego/.tego.tmp.* "$tmp"/prefix/.tego.tmp.*; do
	[ -e "$f" ] && { echo "FAIL a refused install left $f behind" >&2; fail=1; }
done
rm -rf "$tmp/prefix"

# The checksum is still checked after a signature verified: a binary that no longer matches is refused.
printf 'tampered\n' >>"$rel/$archive"
run "$fake/cosign" && code=0 || code=$?
check "a verified checksums file still refuses a binary that does not match it" 7 "$code"

# Every download is held to https (plus file:// for this test's mirror), redirects included, so a redirect to
# plain http cannot swap in a binary and checksums together; a plain-http mirror is refused as a download failure.
release
: >"$tmp/curl.log"
run "$fake/curl" REAL_CURL="$sysbin/curl" FAKE_CURL_LOG="$tmp/curl.log" TEGO_VERIFY=sha256 && code=0 || code=$?
check "the install still succeeds with the protocol limits" 0 "$code"
if ! grep -q -- "--proto =https,file" "$tmp/curl.log" || ! grep -q -- "--proto-redir =https" "$tmp/curl.log"; then
	echo "FAIL curl was run without --proto/--proto-redir limits: $(cat "$tmp/curl.log")" >&2
	fail=1
fi
run "" TEGO_VERIFY=sha256 TEGO_BASE_URL="http://127.0.0.1:9/releases" && code=0 || code=$?
check "a plain-http base URL is refused" 6 "$code"
expect "a plain-http base URL" "download of" "$tmp/out"

# tego-control (ADR 0100 (1b)): installed beside tego when the release lists one, held to the checksum, to gh's
# provenance and to tego's pin, and moved in by rename.
run "" TEGO_VERIFY=sha256 && code=0 || code=$?
check "a release with tego-control installs both" 0 "$code"
if ! [ -x "$tmp/prefix/tego-control" ] || ! cmp -s "$tmp/prefix/tego-control" "$rel/$control"; then
	echo "FAIL tego-control was not installed beside tego" >&2
	fail=1
fi
mode=$(stat -c %a "$tmp/prefix/tego-control" 2>/dev/null || echo none)
[ "$mode" = 755 ] || { echo "FAIL tego-control installed with mode $mode, want 755 (no group or world write)" >&2; fail=1; }
expect "the install names tego-control" "and tego-control beside it" "$tmp/out"
for f in "$tmp"/prefix/.tego-control.tmp.* "$tmp"/prefix/.tego.tmp.*; do
	[ -e "$f" ] && { echo "FAIL an install left $f behind" >&2; fail=1; }
done

run "$fake/gh" && code=0 || code=$?
check "gh mode installs both when both are attested" 0 "$code"
expect "gh is asked about tego-control too" "attestation verify .*${control} --repo Attention-Span-AI/Tego" "$tmp/log"

run "$fake/gh" FAKE_GH_REFUSE="$control" && code=0 || code=$?
check "gh mode refuses a release whose tego-control has no attestation" 9 "$code"
if installed_any; then echo "FAIL a release with an unattested tego-control installed something" >&2; fail=1; fi

printf 'tampered\n' >>"$rel/$control"
run "" TEGO_VERIFY=sha256 && code=0 || code=$?
check "a tego-control that does not match its checksum is refused" 7 "$code"
expect "the mismatch names tego-control" "checksum mismatch for ${control}" "$tmp/out"
if installed_any; then echo "FAIL a release with a tampered tego-control installed something" >&2; fail=1; fi
release

release 0000000000000000000000000000000000000000000000000000000000000000
run "" TEGO_VERIFY=sha256 && code=0 || code=$?
check "a tego pinned to another tego-control is refused, the pair it would install refused at every handoff" 7 "$code"
expect "the pin mismatch names both hashes" "built for tego-control 0000" "$tmp/out"
if installed_any; then echo "FAIL a mismatched pair was installed" >&2; fail=1; fi
release

(cd "$rel" && sha256sum "$archive" >"$sums")
run "" TEGO_VERIFY=sha256 && code=0 || code=$?
check "a pinned tego whose release lists no tego-control is an incomplete release" 7 "$code"
expect "an incomplete release names the missing tego-control" "lists no ${control}" "$tmp/out"
if installed_any; then echo "FAIL an incomplete release installed something" >&2; fail=1; fi

release none
(cd "$rel" && sha256sum "$archive" >"$sums")
run "" TEGO_VERIFY=sha256 && code=0 || code=$?
check "a release from before tego-control installs tego alone" 0 "$code"
installed || { echo "FAIL a release without tego-control installed no tego" >&2; fail=1; }
[ -e "$tmp/prefix/tego-control" ] && { echo "FAIL a release without tego-control installed one" >&2; fail=1; }
expect "a release without tego-control says what is missing" "has no tego-control" "$tmp/out"
release

run "$fake/curl" REAL_CURL="$sysbin/curl" FAKE_CURL_CONTROL=500 && code=0 || code=$?
check "a server error on tego-control is a download failure" 6 "$code"
expect "a server error on tego-control names it" "HTTP 500 for the linux/${arch} tego-control" "$tmp/out"
if installed_any; then echo "FAIL a release whose tego-control could not be fetched installed something" >&2; fail=1; fi

# A tego that cannot be moved into place after tego-control was is a failed install that names the pair it left:
# the old tego refuses the new tego-control ([control-mismatch]) until the install is run again. A release with no
# tego-control moved none, so its failure leaves the existing install untouched and says that, not the mismatch.
mkdir -p "$fake/mv"
cat >"$fake/mv/mv" <<'EOF'
#!/bin/sh
# mv, in front of the real one, fails a move onto tego (its last argument) as a full disk would.
for a in "$@"; do last=$a; done
case "$last" in */tego) echo "mv: cannot move to '$last': No space left on device" >&2; exit 1 ;; esac
exec "$REAL_MV" "$@"
EOF
chmod +x "$fake/mv/mv"
run "$fake/mv" REAL_MV="$sysbin/mv" TEGO_VERIFY=sha256 && code=0 || code=$?
check "a tego that cannot be moved in after tego-control is a failed install" 8 "$code"
expect "a failed tego move after tego-control names the mismatched pair" "already ${version}'s, so the old tego refuses its control commands (\[control-mismatch\])" "$tmp/out"
release none
(cd "$rel" && sha256sum "$archive" >"$sums")
run "$fake/mv" REAL_MV="$sysbin/mv" TEGO_VERIFY=sha256 && code=0 || code=$?
check "a tego that cannot be moved in from a release without tego-control is a failed install" 8 "$code"
expect "a failed tego move with no tego-control leaves the install untouched" "could not install .*/tego (existing install untouched)" "$tmp/out"
if grep -q "control-mismatch" "$tmp/out"; then
	echo "FAIL a failed tego move from a release without tego-control says tego-control was replaced:" >&2
	sed 's/^/     /' "$tmp/out" >&2
	fail=1
fi
[ -e "$tmp/prefix/tego-control" ] && { echo "FAIL a release without tego-control installed one" >&2; fail=1; }
release

# An existing pair is replaced by rename (a running tego-control keeps its inode), and a directory where
# tego-control belongs is refused with the old tego untouched.
rm -rf "$tmp/prefix" "$tmp/log" && mkdir -p "$tmp/prefix" && : >"$tmp/log"
printf '#!/bin/sh\necho old\n' >"$tmp/prefix/tego"
printf '#!/bin/sh\necho old-control\n' >"$tmp/prefix/tego-control"
chmod 755 "$tmp/prefix/tego" "$tmp/prefix/tego-control"
old_inode=$(stat -c %i "$tmp/prefix/tego-control")
run_into && code=0 || code=$?
check "an upgrade replaces both" 0 "$code"
if [ "$(stat -c %i "$tmp/prefix/tego-control")" = "$old_inode" ] || ! cmp -s "$tmp/prefix/tego-control" "$rel/$control"; then
	echo "FAIL tego-control was not replaced by a rename" >&2
	fail=1
fi
rm -rf "$tmp/prefix" && mkdir -p "$tmp/prefix/tego-control"
printf '#!/bin/sh\necho old\n' >"$tmp/prefix/tego"
chmod 755 "$tmp/prefix/tego"
run_into && code=0 || code=$?
check "a directory at the tego-control path is refused" 8 "$code"
grep -q old "$tmp/prefix/tego" || { echo "FAIL a refused install replaced the working tego" >&2; fail=1; }
rm -rf "$tmp/prefix"


# The one-line install, `curl -fsSL .../scripts/install.sh | sh`: the script arrives on the shell's stdin through a
# pipe. piped SCRIPT [VAR=VALUE...] feeds SCRIPT to sh (or to $pipe_sh) that way, in sha256 mode, with a fresh prefix.
piped() {
	script=$1
	shift
	rm -rf "$tmp/prefix" "$tmp/log" && : >"$tmp/log"
	set +e
	# shellcheck disable=SC2002 # the pipe is the point: it is how curl ... | sh hands the shell its script
	cat "$script" | env -i HOME="$tmp" TMPDIR="$tmp" PATH="$sysbin" FAKE_LOG="$tmp/log" \
		TEGO_VERSION="$version" TEGO_BASE_URL="file://$tmp/releases" TEGO_PREFIX="$tmp/prefix" TEGO_VERIFY=sha256 \
		"$@" "${pipe_sh:-$sysbin/sh}" >"$tmp/out" 2>&1
	code=$?
	set -e
	return "$code"
}

piped "$installer" TEGO_VERSION= TEGO_API_URL="file://$tmp/latest" && code=0 || code=$?
check "piped into sh with no TEGO_VERSION, the script installs the latest release" 0 "$code"
installed || { echo "FAIL a piped install installed no tego" >&2; fail=1; }
expect "a piped install installs the tag the latest lookup names" "installed tego ${version}" "$tmp/out"
expect "the install names the Quickstart" "Quickstart: https://attention-span.ai/docs/getting-started/" "$tmp/out"
# It ends with tego's hint block: "next: " and the one command on the line after it, indented two spaces.
ending=$(tail -n 2 "$tmp/out")
# The prefix is not on this shell's PATH, and the installer cannot change that: the command names tego by its full path,
# so it works in the shell the person is in before any export line is typed.
want_ending=$(printf 'next: check this machine:\n  %s/tego %s' "$tmp/prefix" doctor)
check "the install ends with the one next command, tego doctor, by its full path while the prefix is off PATH" "$want_ending" "$ending"
expect "a prefix that is not on PATH says the command below uses the full path" "^Until you do, the command below names tego by its full path.$" "$tmp/out"
if grep -Eq '^ +sudo +tego( |$)|sudo +tego +(setup|doctor|run|status|stop|gc|adopt)' "$tmp/out"; then
	echo "FAIL the install printed a bare sudo tego line, which sudo's secure_path does not find" >&2
	fail=1
fi
expect "a prefix that is not on PATH says so and names the profile" "is not on your PATH. Run this line, and add it to your shell's profile (~/.profile) too:" "$tmp/out"
expect "a prefix that is not on PATH gets its export line" "^  export PATH=\"$tmp/prefix:\$PATH\"$" "$tmp/out"
if grep -q 'Next steps:\|serve --open' "$tmp/out"; then echo "FAIL the install still lists the old five next steps" >&2; fail=1; fi
if grep -q 'systemd-run' "$tmp/out"; then echo "FAIL an install outside SSH printed the SSH scope line" >&2; fail=1; fi

piped "$installer" TEGO_VERIFY=bogus && code=0 || code=$?
check "a piped install still refuses an unknown TEGO_VERIFY" 2 "$code"
expect "a piped install's messages name the script, not the shell" "^install.sh: TEGO_VERIFY must be" "$tmp/out"

# A command the script starts gets no part of the script as its stdin: here the release's tego reads all of its
# stdin when asked its version. Run before the shell had read the rest of the script, it would eat it, and the
# install would stop there with nothing installed. How far a shell reads ahead of a pipe is its own: dash reads
# blocks, bash reads a pipe a line at a time, so bash is the shell that would show it.
pin=$(sha256sum "$rel/$control" | cut -d' ' -f1)
printf '#!/bin/sh\ncat >/dev/null\necho "tego %s"\necho "control_sha256=%s"\n' "$version" "$pin" >"$rel/$archive"
resum
stdin_case() { # stdin_case SHELL
	pipe_sh=$1
	piped "$installer" && code=0 || code=$?
	check "a piped install whose tego reads stdin still installs ($(basename "$pipe_sh"))" 0 "$code"
	installed || { echo "FAIL a tego that reads stdin cut the piped install short under $pipe_sh" >&2; fail=1; }
	expect "a piped install whose tego reads stdin ends with its next step ($pipe_sh)" "^next: check this machine:$" "$tmp/out"
	pipe_sh=""
}
stdin_case "$sysbin/sh"
if bash_path=$(command -v bash); then
	stdin_case "$bash_path"
else
	echo "skip a piped install under bash: no bash"
fi
release

# A download cut short is a script with no end, and the shell must run none of it: here the connection drops just
# after the line that moves tego into place, so a script run line by line would have installed both binaries.
cut=$(grep -n 'tmp_bin="" # moved' "$installer" | cut -d: -f1)
head -n "$cut" "$installer" >"$tmp/install-cut.sh"
piped "$tmp/install-cut.sh" && code=0 || code=$?
if installed_any || grep -q 'installed tego' "$tmp/out"; then
	echo "FAIL an install script cut short, piped into sh, installed something (exit $code)" >&2
	sed 's/^/     /' "$tmp/out" >&2
	fail=1
else
	echo "ok   an install script cut short, piped into sh, installs nothing (exit $code)"
fi

# Public issue 87. The folders the installer itself makes on the way to its prefix are never group- or other-writable,
# whatever the login umask (Ubuntu's is 0002, so a plain mkdir -p made ~/.local and ~/.local/bin mode 775, and tego's
# check of the path it prints a sudo line for then withheld the line). A folder that was already there is left as it is,
# and the installer says nothing about it. mode_of prints the symbolic mode ls shows, which is the same on every system.
# shellcheck disable=SC2012 # the symbolic mode ls prints reads the same on every system; find has no portable way to print it
mode_of() { ls -ld -- "$1" | cut -c1-10; }
want_mode() { # want_mode NAME FOLDER MODE
	if [ "$(mode_of "$2")" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: $2 is $(mode_of "$2"), want $3" >&2; fail=1; fi
}
fresh="$tmp/fresh home/.local/bin"
rm -rf "$tmp/fresh home"
(umask 0002; run "" TEGO_VERIFY=sha256 TEGO_PREFIX="$fresh") && code=0 || code=$?
check "an install into folders that do not exist yet, under umask 0002, installs" 0 "$code"
want_mode "under umask 0002 the folder the installer made above the prefix is 755" "$tmp/fresh home/.local" drwxr-xr-x
want_mode "under umask 0002 the prefix the installer made is 755" "$fresh" drwxr-xr-x
if grep -Eq 'chmod|permission|mode' "$tmp/out"; then echo "FAIL an install that made folders talked about their modes" >&2; sed 's/^/     /' "$tmp/out" >&2; fail=1; fi
rm -rf "$tmp/fresh home"
(umask 0077; run "" TEGO_VERIFY=sha256 TEGO_PREFIX="$fresh") && code=0 || code=$?
check "an install into folders that do not exist yet, under umask 0077, installs" 0 "$code"
want_mode "a stricter umask is kept for the folder above the prefix" "$tmp/fresh home/.local" drwx------
want_mode "a stricter umask is kept for the prefix" "$fresh" drwx------
rm -rf "$tmp/fresh home"
mkdir -p "$tmp/fresh home/.local/bin"
chmod 775 "$tmp/fresh home/.local" "$fresh"
(umask 0002; run_into TEGO_PREFIX="$fresh") && code=0 || code=$?
check "an install into folders that already exist at 775 installs" 0 "$code"
want_mode "an existing folder above the prefix keeps its mode" "$tmp/fresh home/.local" drwxrwxr-x
want_mode "an existing prefix keeps its mode" "$fresh" drwxrwxr-x
if grep -Eq 'chmod|permission|mode' "$tmp/out"; then echo "FAIL an install into existing folders talked about their modes" >&2; sed 's/^/     /' "$tmp/out" >&2; fail=1; fi
rm -rf "$tmp/fresh home"
mkdir -p "$tmp/fresh home/.local"
chmod 775 "$tmp/fresh home/.local"
(umask 0002; run_into TEGO_PREFIX="$fresh") && code=0 || code=$?
check "an install that makes only the prefix under an existing 775 folder installs" 0 "$code"
want_mode "the existing folder keeps 775 while the prefix under it is made 755" "$tmp/fresh home/.local" drwxrwxr-x
want_mode "the prefix made under an existing 775 folder is 755" "$fresh" drwxr-xr-x
rm -rf "$tmp/fresh home"

# The export line only when the prefix is not on PATH, and the scope line only over SSH.
run "$tmp/prefix" TEGO_VERIFY=sha256 SSH_CONNECTION="192.0.2.1 50000 192.0.2.2 22" && code=0 || code=$?
check "an install over SSH into a prefix on PATH installs" 0 "$code"
if grep -q 'export PATH' "$tmp/out"; then echo "FAIL a prefix already on PATH got an export line" >&2; fail=1; fi
# A tego whose commands the installer cannot read (it lists none) is told nothing about a user scope: the line is no
# longer printed for every SSH login (Public issue 88).
if grep -q 'systemd-run\|user scope' "$tmp/out"; then echo "FAIL an install over SSH of a tego with no command list printed a scope line" >&2; fail=1; fi
# Over SSH tego watch fails too: the line never says such a shell can record.
if grep -q 'can only record' "$tmp/out"; then echo "FAIL an install over SSH says the shell can only record" >&2; fail=1; fi

# A release whose tego lists setup in its help ends with tego setup; the releases above, which list none, keep
# tego doctor, so the line never names a command the installed tego lacks.
pin=$(sha256sum "$rel/$control" | cut -d' ' -f1)
# shellcheck disable=SC2016 # $1 is the fake tego's own argument, expanded when it runs.
printf '#!/bin/sh\ncase "$1" in help) printf "commands:\\n  doctor  check\\n  setup   where this machine is\\n" ;;\n*) echo "tego %s"; echo "control_sha256=%s" ;; esac\n' \
	"$version" "$pin" >"$rel/$archive"
resum
piped "$installer" && code=0 || code=$?
check "a release with tego setup installs" 0 "$code"
ending=$(tail -n 2 "$tmp/out")
want_ending=$(printf 'next: see where this machine is, step by step, and what to type next:\n  %s/tego %s' "$tmp/prefix" setup)
check "the install of a tego with setup ends with tego setup, by its full path while the prefix is off PATH" "$want_ending" "$ending"
# With the prefix on PATH the bare name works in this shell, and the line keeps it.
run "$tmp/prefix" TEGO_VERIFY=sha256 && code=0 || code=$?
check "an install into a prefix on PATH installs" 0 "$code"
ending=$(tail -n 2 "$tmp/out")
want_ending=$(printf 'next: see where this machine is, step by step, and what to type next:\n  tego %s' setup)
check "with the prefix on PATH the next command is the bare name, not the full path" "$want_ending" "$ending"
if grep -q 'by its full path' "$tmp/out"; then echo "FAIL a prefix already on PATH got the full-path note" >&2; fail=1; fi
# A prefix whose name a shell would split or expand is quoted in the command, so pasting it runs it.
# shellcheck disable=SC2016 # the dollar sign is part of the folder name
odd="$tmp/odd \$x"
run "" TEGO_VERIFY=sha256 TEGO_PREFIX="$odd" && code=0 || code=$?
check "an install into a prefix with a space and a dollar sign installs" 0 "$code"
ending=$(tail -n 1 "$tmp/out")
# shellcheck disable=SC2016 # the backslash before the dollar sign is what the line must print
want_ending=$(printf '  "%s/odd \\$x/tego" setup' "$tmp")
check "an odd prefix is quoted in the next command" "$want_ending" "$ending"
# A tego that opens a user scope itself (its help says so, as an older build's run line did): over SSH the installer says
# nothing about a shell in the user manager when a manager runs, and no longer tells a person to open one first.
# shellcheck disable=SC2016 # The fake binary reads its own $1.
printf '#!/bin/sh\ncase "$1" in help) printf "commands:\n  run     run a command (opens a user scope when needed)\n  setup   where this machine is\n" ;;\n*) echo "tego %s"; echo "control_sha256=%s" ;; esac\n' \
    "$version" "$pin" >"$rel/$archive"
resum
mkdir -p "$tmp/xdg" "$tmp/sysroot-systemd/run/systemd/system" "$tmp/sysroot-systemd/etc"
printf 'NAME="Debian"\nID=debian\n' >"$tmp/sysroot-systemd/etc/os-release"
# The same build on a login with no user manager (no runtime folder): the one line that is true there, and still no scope advice.
run "$tmp/prefix" TEGO_VERIFY=sha256 TEGO_TEST_SYSROOT="$tmp/sysroot-systemd" XDG_RUNTIME_DIR="$tmp/xdg-absent" SSH_CONNECTION="192.0.2.1 50000 192.0.2.2 22" && code=0 || code=$?
check "automatic scope build installs over SSH with no user manager" 0 "$code"
expect "automatic scope build says when there is no user service manager" "this login has no user service manager (there is no $tmp/xdg-absent)" "$tmp/out"
if grep -q 'systemd-run\|outside your user manager' "$tmp/out"; then echo "FAIL a login with no user manager was told to open a shell in it" >&2; sed 's/^/     /' "$tmp/out" >&2; fail=1; fi
run "$tmp/prefix" TEGO_VERIFY=sha256 TEGO_TEST_SYSROOT="$tmp/sysroot-systemd" XDG_RUNTIME_DIR="$tmp/xdg" SSH_CONNECTION="192.0.2.1 50000 192.0.2.2 22" && code=0 || code=$?
check "automatic scope build installs over SSH" 0 "$code"
if grep -q 'no user service manager' "$tmp/out"; then echo "FAIL a login whose user manager runs was told it has none" >&2; sed 's/^/     /' "$tmp/out" >&2; fail=1; fi
expect "automatic scope build retains the account copy advice" "install both binaries in that account's ~/.local/bin" "$tmp/out"
if grep -q 'systemd-run\|outside your user manager' "$tmp/out"; then echo "FAIL a tego that opens its own scope was told to open a shell first" >&2; sed 's/^/     /' "$tmp/out" >&2; fail=1; fi

# A release whose tego lists start ends with tego start, the guide, by the same name as the other next commands: the
# full path while the prefix is off PATH, the bare name when it is on PATH.
# shellcheck disable=SC2016 # $1 is the fake tego's own argument, expanded when it runs.
printf '#!/bin/sh\ncase "$1" in help) printf "commands:\\n   start            set up\\n   setup   where this machine is\\n" ;;\n*) echo "tego %s"; echo "control_sha256=%s" ;; esac\n' \
	"$version" "$pin" >"$rel/$archive"
resum
piped "$installer" && code=0 || code=$?
check "a release with tego start installs" 0 "$code"
ending=$(tail -n 2 "$tmp/out")
want_ending=$(printf 'next: set up Tego and connect your first agent:\n  %s/tego %s' "$tmp/prefix" start)
check "the install of a tego with start ends with tego start, by its full path while the prefix is off PATH" "$want_ending" "$ending"
run "$tmp/prefix" TEGO_VERIFY=sha256 && code=0 || code=$?
check "an install of a tego with start into a prefix on PATH installs" 0 "$code"
ending=$(tail -n 2 "$tmp/out")
want_ending=$(printf 'next: set up Tego and connect your first agent:\n  tego %s' start)
check "with the prefix on PATH the start line is the bare name" "$want_ending" "$ending"

# Public issue 88: the closing lines about this login's user service manager. A tego that lists start enters a user
# scope by itself (tego run, watch and test do; start, setup and doctor rehearse it), so no line tells a person to open
# a shell in the manager first, over SSH or anywhere else. The installer says something in two cases it can see
# cheaply and surely, the ones tego start and tego doctor word too: this login has no user service manager (no runtime
# folder), and a manager with no message bus on a Debian or Ubuntu with apt (the dashboard cannot start). TEGO_TEST_SYSROOT
# stands in for the root of /run/systemd/system and /etc/os-release; XDG_RUNTIME_DIR names the runtime folder, as it
# does for tego.
# shellcheck disable=SC2016 # $1 is the fake tego's own argument, expanded when it runs.
printf '#!/bin/sh\ncase "$1" in help) printf "commands:\\n   start            set up\\n   run              run\\n   setup   where this machine is\\n" ;;\n*) echo "tego %s"; echo "control_sha256=%s" ;; esac\n' \
	"$version" "$pin" >"$rel/$archive"
resum
# sysroot_with NAME ID [ID_LIKE]: a root with systemd as init and an os-release of that distribution.
sysroot_with() {
	mkdir -p "$tmp/sysroot-$1/run/systemd/system" "$tmp/sysroot-$1/etc"
	printf 'NAME="%s"\nID=%s\n' "$1" "$2" >"$tmp/sysroot-$1/etc/os-release"
	[ -z "${3:-}" ] || printf 'ID_LIKE="%s"\n' "$3" >>"$tmp/sysroot-$1/etc/os-release"
}
sysroot_with debian debian
sysroot_with ubuntu ubuntu debian
sysroot_with fedora fedora
mkdir -p "$tmp/sysroot-initd/etc"
cp "$tmp/sysroot-debian/etc/os-release" "$tmp/sysroot-initd/etc/os-release"
mkdir -p "$fake/apt"
printf '#!/bin/sh\nexit 0\n' >"$fake/apt/apt-get"
chmod +x "$fake/apt/apt-get"
# A runtime folder with a bus socket (python3 binds it and leaves the file), and one without.
mkdir -p "$tmp/rt-bus" "$tmp/rt-nobus"
chmod 700 "$tmp/rt-bus" "$tmp/rt-nobus"
have_socket=0
if command -v python3 >/dev/null 2>&1 && python3 -c 'import socket,sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$tmp/rt-bus/bus" 2>/dev/null; then have_socket=1; fi
ssh_env="192.0.2.1 50000 192.0.2.2 22"
bus_line="The dashboard cannot start: your user service manager has no message bus (D-Bus), and Tego's dashboard runs in it; Debian and Ubuntu cloud images leave out the package that gives it one."
quiet_about_session() { # quiet_about_session NAME: nothing about a user manager, a scope or a bus in the output
	if grep -q 'systemd-run\|user scope\|user service manager\|D-Bus\|dbus-user-session' "$tmp/out"; then
		echo "FAIL $1: the output speaks of a user manager, a scope or a bus" >&2
		sed 's/^/     /' "$tmp/out" >&2
		fail=1
	else
		echo "ok   $1"
	fi
}
if [ "$(id -u)" = 0 ]; then
	echo "skip the closing lines about the user manager and its bus: the installer says nothing to root, and this runs as root"
else
	if [ "$have_socket" = 1 ]; then
		run "$fake/apt" TEGO_VERIFY=sha256 TEGO_TEST_SYSROOT="$tmp/sysroot-debian" XDG_RUNTIME_DIR="$tmp/rt-bus" SSH_CONNECTION="$ssh_env" && code=0 || code=$?
		check "SSH with a user manager and a bus installs" 0 "$code"
		quiet_about_session "SSH with a user manager and a bus: no scope line, no bus line"
		ending=$(tail -n 2 "$tmp/out")
		check "SSH with a user manager and a bus ends with tego start" "$(printf 'next: set up Tego and connect your first agent:\n  %s/tego start' "$tmp/prefix")" "$ending"
		run "$fake/apt" TEGO_VERIFY=sha256 TEGO_TEST_SYSROOT="$tmp/sysroot-debian" XDG_RUNTIME_DIR="$tmp/rt-bus" && code=0 || code=$?
		check "a desktop session installs" 0 "$code"
		quiet_about_session "a desktop session (no SSH, a manager and a bus): nothing about the manager"
		run "$fake/apt" TEGO_VERIFY=sha256 TEGO_TEST_SYSROOT="$tmp/sysroot-debian" XDG_RUNTIME_DIR="$tmp/rt-nobus" DBUS_SESSION_BUS_ADDRESS="unix:path=$tmp/rt-bus/bus,guid=x" && code=0 || code=$?
		check "a bus named by DBUS_SESSION_BUS_ADDRESS installs" 0 "$code"
		quiet_about_session "a bus socket named by DBUS_SESSION_BUS_ADDRESS counts as there"
	else
		echo "skip the cases with a bus socket: python3 cannot make one here"
	fi

	# SSH without a user manager: the one line that is true, once, before the next step.
	run "$fake/apt" TEGO_VERIFY=sha256 TEGO_TEST_SYSROOT="$tmp/sysroot-debian" XDG_RUNTIME_DIR="$tmp/rt-absent" SSH_CONNECTION="$ssh_env" && code=0 || code=$?
	check "SSH without a user manager installs" 0 "$code"
	want="this login has no user service manager (there is no $tmp/rt-absent), so Tego cannot open a user scope for a run from here; the step below says what to do."
	if [ "$(grep -cF -- "$want" "$tmp/out")" != 1 ]; then echo "FAIL SSH without a user manager: the line is not printed once" >&2; sed 's/^/     /' "$tmp/out" >&2; fail=1; else echo "ok   SSH without a user manager says so once"; fi
	if grep -q 'systemd-run\|D-Bus' "$tmp/out"; then echo "FAIL SSH without a user manager: a scope shell or a bus was named" >&2; fail=1; fi
	ending=$(tail -n 2 "$tmp/out")
	check "SSH without a user manager still ends with tego start" "$(printf 'next: set up Tego and connect your first agent:\n  %s/tego start' "$tmp/prefix")" "$ending"
	# systemd is not this machine's init: there is no user manager to speak of, and the installer says nothing.
	run "$fake/apt" TEGO_VERIFY=sha256 TEGO_TEST_SYSROOT="$tmp/sysroot-initd" XDG_RUNTIME_DIR="$tmp/rt-absent" SSH_CONNECTION="$ssh_env" && code=0 || code=$?
	check "a machine whose init is not systemd installs" 0 "$code"
	quiet_about_session "no systemd as init: nothing about a manager"

	# A manager with no bus, on Debian or Ubuntu with apt: tego start's own words and package line, before the next step.
	for distro in debian ubuntu; do
		run "$fake/apt" TEGO_VERIFY=sha256 TEGO_TEST_SYSROOT="$tmp/sysroot-$distro" XDG_RUNTIME_DIR="$tmp/rt-nobus" SSH_CONNECTION="$ssh_env" && code=0 || code=$?
		check "a $distro login with no bus installs" 0 "$code"
		expect "a $distro login with no bus gets tego start's sentence" "^$bus_line\$" "$tmp/out"
		expect "a $distro login with no bus gets the package line" "^  sudo apt install dbus-user-session\$" "$tmp/out"
		expect "a $distro login with no bus is told to log in again" "^then log out and log in again\$" "$tmp/out"
		if grep -q 'systemd-run' "$tmp/out"; then echo "FAIL a $distro login with no bus was told to open a scope shell" >&2; fail=1; fi
		ending=$(tail -n 2 "$tmp/out")
		check "a $distro login with no bus still ends with tego start" "$(printf 'next: set up Tego and connect your first agent:\n  %s/tego start' "$tmp/prefix")" "$ending"
	done
	run "$fake/apt" TEGO_VERIFY=sha256 TEGO_TEST_SYSROOT="$tmp/sysroot-debian" XDG_RUNTIME_DIR="$tmp/rt-nobus" && code=0 || code=$?
	expect "a desktop session with no bus gets the same lines (SSH does not matter)" "^  sudo apt install dbus-user-session\$" "$tmp/out"
	# Where the installer cannot be sure it says nothing.
	run "$fake/apt" TEGO_VERIFY=sha256 TEGO_TEST_SYSROOT="$tmp/sysroot-fedora" XDG_RUNTIME_DIR="$tmp/rt-nobus" SSH_CONNECTION="$ssh_env" && code=0 || code=$?
	quiet_about_session "no bus on another family: nothing (the guide names the package by what it does)"
	run "" TEGO_VERIFY=sha256 TEGO_TEST_SYSROOT="$tmp/sysroot-debian" XDG_RUNTIME_DIR="$tmp/rt-nobus" SSH_CONNECTION="$ssh_env" && code=0 || code=$?
	quiet_about_session "no bus on a Debian without apt: nothing"
	run "$fake/apt" TEGO_VERIFY=sha256 TEGO_TEST_SYSROOT="$tmp/sysroot-debian" XDG_RUNTIME_DIR="$tmp/rt-nobus" DBUS_SESSION_BUS_ADDRESS="unix:abstract=/tmp/dbus-x" && code=0 || code=$?
	quiet_about_session "a bus address of another kind cannot be checked by a file: nothing"
	run "$fake/apt" TEGO_VERIFY=sha256 TEGO_TEST_SYSROOT="$tmp/sysroot-debian" XDG_RUNTIME_DIR="relative/rt" SSH_CONNECTION="$ssh_env" HOME="$tmp" && code=0 || code=$?
	check "a relative XDG_RUNTIME_DIR installs" 0 "$code"
	# A tego older than start (it lists setup only) is told nothing about a manager or a bus.
	# shellcheck disable=SC2016 # $1 is the fake tego's own argument, expanded when it runs.
	printf '#!/bin/sh\ncase "$1" in help) printf "commands:\\n  doctor  check\\n  setup   where this machine is\\n" ;; *) echo "tego %s"; echo "control_sha256=%s" ;; esac\n' \
		"$version" "$pin" >"$rel/$archive"
	resum
	run "$fake/apt" TEGO_VERIFY=sha256 TEGO_TEST_SYSROOT="$tmp/sysroot-debian" XDG_RUNTIME_DIR="$tmp/rt-absent" SSH_CONNECTION="$ssh_env" && code=0 || code=$?
	quiet_about_session "a tego with no start (no manager line) and no scope line over SSH"
	run "$fake/apt" TEGO_VERIFY=sha256 TEGO_TEST_SYSROOT="$tmp/sysroot-debian" XDG_RUNTIME_DIR="$tmp/rt-nobus" SSH_CONNECTION="$ssh_env" && code=0 || code=$?
	quiet_about_session "a tego with no start has no dashboard line either"
fi
release

exit "$fail"
