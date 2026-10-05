# SPDX-License-Identifier: Apache-2.0
"""Publisher verification for the kernel matrix. Trust lives in this checkout, never in its cache."""
import base64
import hashlib
import os
import re
import shutil
import struct
import subprocess
import tempfile


class AuthError(Exception):
    """The environment cannot provide an authenticated kernel; no guest may boot it."""


KEYS = {
    "ubuntu-2018": "F6ECB3762474EDA9D21B7022871920D1991BC93C",
    "debian-13-archive": "04B54C3CDCA79751B16BC6B5225629DF75B188BD",
    "debian-13-release": "41587F7DB8C774BCCF131416762F67A0B2C39DE4",
    "almalinux-9": "BF18AC2876178908D6E71267D36CB86CB86B3716",
    "amazonlinux-2023": "B21C50FA44A99720EAA72F7FE951904AD832C631",
    "fedora-44": "36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6",
    "fedora-45": "4F50A6114CD5C6976A7F1179655A4B02F577861E",
    "fedora-46": "D924B10D3E810DABDD8B56B596E7E91491211FCE",
}
KEY_DIR = os.path.join(os.path.dirname(__file__), "keys")


def signature_packets(raw):
    """Require detached OpenPGP signature packets only; embedded literal messages are not signatures."""
    raw = bytes(raw)
    if raw.startswith(b"-----"):
        lines = raw.strip().splitlines()
        begin, end = b"-----BEGIN PGP SIGNATURE-----", b"-----END PGP SIGNATURE-----"
        if not lines or lines[0] != begin or lines[-1] != end or lines.count(begin) != 1 or lines.count(end) != 1:
            raise AuthError("expected one detached signature armor block")
        try:
            separator = lines.index(b"", 1)
            encoded = lines[separator + 1:-1]
            if encoded and encoded[-1].startswith(b"="):
                encoded = encoded[:-1] # GnuPG checks the armor CRC when present
            raw = base64.b64decode(b"".join(encoded), validate=True)
        except ValueError as e:
            raise AuthError("invalid detached signature armor") from e
    if not raw or len(raw) > 65536:
        raise AuthError("invalid detached signature size")
    pos = 0
    while pos < len(raw):
        tag = raw[pos]
        pos += 1
        if not tag & 0x80 or pos == len(raw):
            raise AuthError("invalid OpenPGP packet")
        if tag & 0x40:
            kind, length = tag & 0x3f, raw[pos]
            pos += 1
            if 192 <= length < 224:
                if pos == len(raw):
                    raise AuthError("truncated OpenPGP length")
                length = ((length - 192) << 8) + raw[pos] + 192
                pos += 1
            elif length == 255:
                if pos + 4 > len(raw):
                    raise AuthError("truncated OpenPGP length")
                length = int.from_bytes(raw[pos:pos + 4], "big")
                pos += 4
            elif length >= 224:
                raise AuthError("partial-length signature packets are unsupported")
        else:
            kind, size = (tag >> 2) & 15, tag & 3
            if size == 3:
                raise AuthError("indeterminate-length signature packets are unsupported")
            size = 1 << size
            if pos + size > len(raw):
                raise AuthError("truncated OpenPGP length")
            length = int.from_bytes(raw[pos:pos + size], "big")
            pos += size
        if kind != 2 or length < 1 or pos + length > len(raw):
            raise AuthError("OpenPGP input is not detached signature packets")
        pos += length


def signed_bytes(signature, data, keys):
    """Verify a detached signature, or extract a clearsigned body (data=None), in an isolated keyring.

    A valid signature must name a pinned primary key and use SHA256 or stronger. A multi-signature Debian
    Release may also have signatures by keys outside this row's keyring; a known valid signature still
    authenticates the exact body. GnuPG never sees the user's home/keyrings and never retrieves keys.
    """
    if not keys or any(k not in KEYS for k in keys):
        raise AuthError("no pinned publisher key for this row")
    if data is None:
        # gpgv can emit several concatenated cleartext messages. One valid signature must not authorize
        # an additional message signed by an unknown key (or unverified plaintext appended after it).
        normalized = bytes(signature).replace(b"\r\n", b"\n")
        start = b"-----BEGIN PGP SIGNED MESSAGE-----\n"
        sigstart = b"\n-----BEGIN PGP SIGNATURE-----\n"
        sigend = b"-----END PGP SIGNATURE-----"
        if (not normalized.startswith(start) or normalized.count(start) != 1 or
                normalized.count(sigstart) != 1 or normalized.count(sigend) != 1 or
                not normalized.rstrip().endswith(sigend)):
            raise AuthError("expected exactly one clearsigned metadata envelope")
        signature_packets(normalized[normalized.index(sigstart) + 1:])
    else:
        signature_packets(signature)
    for tool in ("gpg", "gpgv"):
        if not shutil.which(tool):
            raise AuthError(f"publisher verification requires {tool} on PATH")
    with tempfile.TemporaryDirectory(prefix="tego-kernel-gpg-") as home:
        args = ["gpg", "--homedir", home, "--no-options", "--batch"]
        paths = [os.path.join(KEY_DIR, k + ".asc") for k in keys]
        imp = subprocess.run(args + ["--import-options", "import-minimal", "--import"] + paths,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if imp.returncode:
            raise AuthError("cannot load shipped publisher keys: " + imp.stderr.decode(errors="replace"))
        listed = subprocess.run(args + ["--with-colons", "--fingerprint"], check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode()
        primary, want_primary = set(), False
        for line in listed.splitlines():
            fields = line.split(":")
            if fields[0] == "pub":
                want_primary = True
            elif fields[0] == "fpr" and want_primary:
                primary.add(fields[9])
                want_primary = False
        if primary != {KEYS[k] for k in keys}:
            raise AuthError("shipped publisher key fingerprints do not match the pinned trust anchors")
        ring = os.path.join(home, "trusted.gpg")
        with open(ring, "wb") as f:
            subprocess.run(args + ["--export"], check=True, stdout=f, stderr=subprocess.PIPE)
        sig = os.path.join(home, "signature")
        with open(sig, "wb") as f:
            f.write(signature)
        cmd = ["gpgv", "--homedir", home, "--keyring", ring, "--status-fd", "1"]
        plain = os.path.join(home, "verified")
        if data is None:
            cmd += ["--output", plain, sig]
        else:
            body = os.path.join(home, "body")
            with open(body, "wb") as f:
                f.write(data)
            cmd += [sig, body]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        valid = []
        unusable = False
        for line in result.stdout.decode(errors="replace").splitlines():
            fields = line.split()
            if len(fields) > 1 and fields[1] in ("EXPKEYSIG", "REVKEYSIG", "KEYREVOKED", "EXPSIG"):
                unusable = True
            if len(fields) >= 11 and fields[:2] == ["[GNUPG:]", "VALIDSIG"]:
                signer = fields[11] if len(fields) > 11 else fields[2]
                if signer in primary and fields[9] in ("8", "9", "10"):
                    valid.append(signer)
        if not valid or unusable:
            raise AuthError("publisher signature verification failed: " + result.stderr.decode(errors="replace").strip())
        if data is None:
            with open(plain, "rb") as f:
                data = f.read()
        return data, sorted(set(valid))


def rpm_header(f, offset):
    """Read a bounded on-disk RPM header. Reject duplicates, dribbles and partial immutable regions.

    Format: https://rpm-software-management.github.io/rpm/manual/format_header.html
    Signed packages from Koji have one complete immutable region, unlike installed RPM database headers.
    """
    f.seek(offset)
    intro = f.read(16)
    if len(intro) != 16 or intro[:8] != b"\x8e\xad\xe8\x01\0\0\0\0":
        raise AuthError("invalid RPM header")
    count, size = struct.unpack(">II", intro[8:])
    if not 1 <= count <= 65536 or size > 16 << 20:
        raise AuthError("RPM header exceeds verification limits")
    index, data = f.read(count * 16), f.read(size)
    if len(index) != count * 16 or len(data) != size:
        raise AuthError("truncated RPM header")
    tags, total_strings = {}, 0
    for i in range(count):
        tag, kind, pos, n = struct.unpack(">IIiI", index[i * 16:(i + 1) * 16])
        if tag in tags or not 0 <= pos < size or n < 1:
            raise AuthError("ambiguous RPM header entry")
        if kind in (4, 7):
            end = pos + n * (4 if kind == 4 else 1)
            if end > size:
                raise AuthError("RPM entry exceeds header")
            value = data[pos:end]
        elif kind in (6, 8, 9):
            total_strings += n
            if total_strings > 1 << 20:
                raise AuthError("RPM string entries exceed verification limits")
            if n > size - pos:
                raise AuthError("invalid RPM string count")
            end = pos
            for _ in range(n):
                end = data.find(b"\0", end)
                if end < 0:
                    raise AuthError("unterminated RPM header string")
                end += 1
            value = data[pos:end]
        else:
            value = b"" # irrelevant types are never used as authentication evidence
        tags[tag] = (kind, n, value)
    region, kind, pos, n = struct.unpack(">IIiI", index[:16])
    if region not in (62, 63) or kind != 7 or n != 16 or pos + 16 != size:
        raise AuthError("RPM has no complete immutable header region")
    if struct.unpack(">IIiI", data[pos:pos + 16]) != (region, 7, -count * 16, 16):
        raise AuthError("RPM immutable region does not cover its header")
    return intro + index + data, tags


def rpm_signed_package(path, keys, package):
    """Authenticate the RPM header and its SHA256 compressed-payload digest before extraction.

    RPM v4 RSA/DSA header signatures and v6 OpenPGP signatures both sign the immutable header. The
    authenticated PAYLOADDIGEST/PAYLOADSHA256 tag covers every compressed payload byte, including a
    substituted cpio archive. This deliberately rejects unsigned Koji build artifacts and old weak digests.
    """
    with open(path, "rb") as f:
        if f.read(4) != b"\xed\xab\xee\xdb":
            raise AuthError("not an RPM")
        sigraw, signatures = rpm_header(f, 96)
        offset = (96 + len(sigraw) + 7) & ~7
        header, tags = rpm_header(f, offset)
        candidates = []
        for tag in (267, 268):
            if tag in signatures and signatures[tag][0] == 7:
                candidates.append(signatures[tag][2])
        if 278 in signatures and signatures[278][0] == 8:
            try:
                candidates += [base64.b64decode(s, validate=True) for s in signatures[278][2].split(b"\0")[:-1]]
            except ValueError as e:
                raise AuthError("invalid RPM OpenPGP signature encoding") from e
        signers = None
        for sig in candidates:
            try:
                _, signers = signed_bytes(sig, header, keys)
                break
            except AuthError:
                continue
        if not signers:
            raise AuthError("RPM has no valid signature from this row's pinned publisher keys")
        def string(tag):
            kind, n, value = tags.get(tag, (0, 0, b""))
            if kind not in (6, 8) or n != 1:
                raise AuthError(f"RPM authenticated header lacks string tag {tag}")
            return value[:-1].decode("ascii")
        if string(1000) != package or string(1022) != "x86_64":
            raise AuthError("signed RPM has the wrong package name or architecture")
        digest = string(5092)
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise AuthError("signed RPM has no SHA256 payload digest")
        if 5093 in tags and tags[5093] != (4, 1, struct.pack(">I", 8)):
            raise AuthError("signed RPM uses an unsupported payload digest")
        f.seek(offset + len(header))
        payload_hash = hashlib.sha256()
        for chunk in iter(lambda: f.read(1 << 20), b""):
            payload_hash.update(chunk)
        actual = payload_hash.hexdigest()
        if actual != digest:
            raise AuthError("RPM payload differs from its signed SHA256 digest")
        return {"method": "publisher-rpm-signature", "primary_fingerprints": signers,
                "publisher_signature_checked": True, "payload_sha256": digest}, string(1001) + "-" + string(1002)
