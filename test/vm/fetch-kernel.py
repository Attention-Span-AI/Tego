#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# fetch-kernel.py — one kernel-matrix row's stock kernel image, without root (P0-DESIGN §10 "Kernel matrix
# (`test/vm`): Ubuntu 24.04 6.8, Debian 13 6.12, RHEL 9 5.14, AL2023 6.1 and 6.12, Fedora 7.0", and its 2026-10-05
# amendment: Ubuntu 25.10 6.17, Fedora 7.2 and the doctor-only Ubuntu 22.04 5.15).
#
# Why it exists: test/vm/kvm-run.sh boots whatever vmlinuz sits in $TEGO_VM_CACHE/kernel/<name>/, so a
# matrix row needs nothing but that file: the guest's root is an initramfs of this host's userland, and
# the console is the built-in 8250 UART every one of these distro kernels carries, so no module is loaded.
# Each distro publishes its kernel as a package on an anonymous mirror, and the package formats are simple
# enough to open here with the standard library plus the xz/zstd tools: a .deb is an ar archive around a
# tar, an .rpm is a lead and two headers in front of a compressed newc cpio. Nothing is installed, nothing
# needs root, and the package's own name and version are recorded next to the image so a matrix result
# names exactly which build it booted. Publisher authentication is mandatory: pinned OpenPGP keys verify
# InRelease -> Packages -> DEB, repomd.xml.asc -> primary.xml -> RPM, or Fedora's signed RPM header ->
# SHA256 payload. Every cache hit reverifies retained signing evidence and re-extracts the authenticated
# image. source.json is provenance, never a trust anchor. GnuPG uses a private temporary keyring.
# TEGO_VM_KERNEL_MANIFEST optionally adds independently authenticated package/image digest constraints;
# it never disables publisher-signature verification. See keys/README.md for fingerprints and key rotation.
#
# RHEL 9 is AlmaLinux 9's BaseOS kernel-core: RHEL's own packages sit behind a subscription, and AlmaLinux
# rebuilds the same 5.14 sources and configuration. Fedora's rows are pinned to the 7.0 and 7.2 series through
# koji, because a Fedora release's own repositories move to whichever kernel series is newest; 7.2 is the row
# with Landlock ABI 10 (pathname unix sockets are ABI 9, 7.1; UDP port rules are ABI 10, 7.2), so the paths
# enforce/landlock builds for those ABIs run against a kernel that has them. Ubuntu 25.10's row is its GA
# kernel, 6.17 (Landlock ABI 7), the series this project is developed on. Ubuntu 22.04's row is its GA kernel,
# 5.15, where Landlock is ABI 1 and no tier is offered: it is the one doctor-only row (DOCTOR_ONLY below).
#
# Usage: fetch-kernel.py <row>            print the path of the row's vmlinuz, fetching it once
#        fetch-kernel.py --list           the rows: name, series, source kind, body (full or doctor-only), label
#        fetch-kernel.py --refresh <row>  fetch again even when an image is cached
#        fetch-kernel.py --name <row>     the TEGO_VM_KERNEL name kvm-run.sh boots it under
#        fetch-kernel.py --body <row>     what the row's guest runs: full, or doctor-only (see DOCTOR_ONLY)
# Exit code: 0 with the path on stdout; 97 when the row cannot be fetched here (no network, the mirror no
# longer carries the package), with a message naming what failed; 2 on a usage error. 97 is kvm-run.sh's
# own "this box cannot do it" code, so a matrix row that could not start is never mistaken for a test fail.
import fcntl
import datetime
import email.utils
import hashlib
import io
import json
import lzma
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kernel_auth import AuthError as EnvError, KEYS, signed_bytes, rpm_signed_package

EXIT_ENV = 97
EXIT_USAGE = 2

ALMA9 = "https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/"
AL2023_MIRRORLIST = "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list"
KOJI = "https://kojipkgs.fedoraproject.org/packages/kernel/"

# name: (series, label, fetcher kind, parameters). The series is what the row is meant to test; the image
# actually booted reports its own release through uname(2), which the matrix prints beside it.
ROWS = {
    "ubuntu-24.04": ("6.8", "Ubuntu 24.04 LTS, GA kernel", "deb",
                     {"base": "https://archive.ubuntu.com/ubuntu", "suite": "noble-updates", "meta": "linux-image-generic", "keys": ["ubuntu-2018"]}),
    "debian-13": ("6.12", "Debian 13 (trixie)", "deb",
                  {"base": "https://deb.debian.org/debian", "suite": "trixie", "meta": "linux-image-amd64", "keys": ["debian-13-archive", "debian-13-release"]}),
    "rhel-9": ("5.14", "RHEL 9 (AlmaLinux 9 BaseOS rebuild)", "rpm",
               {"repo": ALMA9, "package": "kernel-core", "keys": ["almalinux-9"]}),
    "al2023": ("6.1", "Amazon Linux 2023, default kernel", "rpm",
               {"mirrorlist": AL2023_MIRRORLIST, "package": "kernel", "keys": ["amazonlinux-2023"]}),
    "al2023-6.12": ("6.12", "Amazon Linux 2023, kernel6.12", "rpm",
                    {"mirrorlist": AL2023_MIRRORLIST, "package": "kernel6.12", "keys": ["amazonlinux-2023"]}),
    "fedora-7.0": ("7.0", "Fedora, kernel 7.0 series (koji)", "koji",
                   {"series": "7.0", "package": "kernel-core"}),
    "ubuntu-25.10": ("6.17", "Ubuntu 25.10, GA kernel", "deb",
                     {"base": "https://archive.ubuntu.com/ubuntu", "suite": "questing-updates", "meta": "linux-image-generic", "keys": ["ubuntu-2018"]}),
    "fedora-7.2": ("7.2", "Fedora, kernel 7.2 series (koji)", "koji",
                   {"series": "7.2", "package": "kernel-core"}),
    "ubuntu-22.04": ("5.15", "Ubuntu 22.04 LTS, GA kernel", "deb",
                     {"base": "https://archive.ubuntu.com/ubuntu", "suite": "jammy-updates", "meta": "linux-image-generic", "keys": ["ubuntu-2018"]}),
}

# What a row's guest is asked to do. "full" runs the whole of run-matrix-row.sh. "doctor-only" runs one check, that
# this machine is refused with doctor's fix (run-matrix-row.sh --only doctor-refusal, test/vm/doctor-refusal.sh):
# Ubuntu 22.04's 5.15 has Landlock ABI 1, below doctor.MinLandlockABI = 2, so no tier is offered there, tier 2 never
# runs, and no kill test has a tier to run at (nor is 5.15 the natural row of ADR 0021's fanotify fallback: where no
# tier runs, no plane is selected). A row leaves this set, and runs in full, when its kernel gains a tier; the
# refusal check fails the row when it has.
DOCTOR_ONLY = frozenset({"ubuntu-22.04"})


def body_of(row):
    return "doctor-only" if row in DOCTOR_ONLY else "full"


def cache_root():
    return os.environ.get("TEGO_VM_CACHE") or os.path.join(os.path.expanduser("~"), ".cache", "tego-vm")


def kernel_name(row):
    # kvm-run.sh looks for $TEGO_VM_CACHE/kernel/$TEGO_VM_KERNEL/vmlinuz before it tries apt, so this name is
    # the whole interface between the two scripts.
    return "matrix-" + row


def trusted_pin(row):
    """Independent digest constraints in addition to publisher signatures. The manifest is never fetched
    from the package mirror; its operator establishes its provenance independently (README.md)."""
    path = os.environ.get("TEGO_VM_KERNEL_MANIFEST")
    if not path:
        return None
    try:
        with open(path, "rb") as f:
            raw = f.read((1 << 20) + 1)
        if len(raw) > 1 << 20:
            raise ValueError("manifest exceeds 1 MiB")
        doc = json.loads(raw)
        if not isinstance(doc, dict) or type(doc.get("version")) is not int or doc["version"] != 1:
            raise ValueError("expected manifest version 1")
        rows = doc.get("rows")
        if not isinstance(rows, dict) or not isinstance(rows.get(row), dict):
            raise ValueError(f"no pin for {row}")
        pin = dict(rows[row])
        if set(pin) - {"package_sha256", "image_sha256", "provenance"}:
            raise ValueError(f"unknown fields in {row}'s pin")
        if not isinstance(pin.get("provenance"), str) or not pin["provenance"].strip():
            raise ValueError(f"{row} needs independent digest provenance")
        if not any(key in pin for key in ("package_sha256", "image_sha256")):
            raise ValueError(f"{row} needs a package_sha256 or image_sha256")
        for key in ("package_sha256", "image_sha256"):
            if key in pin:
                if not isinstance(pin[key], str) or not re.fullmatch(r"[a-fA-F0-9]{64}", pin[key]):
                    raise ValueError(f"{row} has an invalid {key}")
                pin[key] = pin[key].lower()
        pin["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
        return pin
    except (OSError, ValueError) as e:
        raise EnvError(f"trusted kernel manifest {path}: {e}") from e


def verify_package_pin(path, params):
    pin = params.get("_trusted_pin")
    if pin and pin.get("package_sha256"):
        verify_sha256(path, pin["package_sha256"], "trusted manifest package pin")


def verify_image_pin(pin, info, image_sha256):
    """Check independent digests against the authenticated package and extracted image, never cache metadata."""
    if not pin:
        return
    for key, got in (("package_sha256", (info.get("sha256") or "").lower()), ("image_sha256", image_sha256)):
        if key in pin and pin[key] != got:
            raise EnvError(f"trusted kernel manifest: {key} {got or 'missing'} does not match {pin[key]}; "
                           "use --refresh after checking the pin's independent provenance")
    info["trusted_manifest"] = {"manifest_sha256": pin["manifest_sha256"],
                                "provenance": pin["provenance"]}


def get(url, timeout=120):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read()
    except Exception as e:  # any network failure is an environment failure, not a finding
        raise EnvError(f"GET {url}: {e}") from e


def artifact(p, work, name, url):
    """Fixed local proof names never come from a mirror. Offline reads authenticate the retained evidence."""
    path = os.path.join(work, name)
    if not p.get("_offline"):
        download(url, path)
    if not os.path.isfile(path):
        raise EnvError(f"cached authentication proof lacks {name}; use --refresh")
    return path


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def download(url, dest):
    tmp = dest + ".part"
    try:
        with urllib.request.urlopen(url, timeout=600) as r, open(tmp, "wb") as f:
            shutil.copyfileobj(r, f, 1 << 20)
    except Exception as e:
        raise EnvError(f"GET {url}: {e}") from e
    os.replace(tmp, dest)


def verify_sha256(path, want, what):
    """The file is the one the index lists: a package index carries a SHA256 for each Filename, and a download
    that does not match it (a swapped mirror, a truncated transfer) is refused before anything reads it. An
    index that lists no digest is refused too, so the check cannot be skipped by omission."""
    if not want:
        raise EnvError(f"{what}: the index lists no SHA256 to check the download against")
    got = file_sha256(path)
    if got != want.lower():
        os.unlink(path)
        raise EnvError(f"{what}: SHA256 {got} does not match the index's {want}")


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def xml_sha256(el, ns, what):
    """The sha256 an RPM repository's XML carries in a <checksum> child, or an EnvError when it carries none
    or another algorithm: a digest this script cannot check is refused, not skipped."""
    c = el.find(ns + "checksum")
    if c is None or (c.get("type") or "").lower() not in ("sha256", "sha"):
        raise EnvError(f"{what}: the repository lists no sha256 checksum for it")
    return (c.text or "").strip()


def vkey(v):
    """A version sort key good enough to pick the newest of one package's builds: numeric runs compare as
    numbers, everything else as text."""
    return [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in re.findall(r"\d+|[A-Za-z]+", v)]


# ---- .deb ------------------------------------------------------------------------------------------

def deb_index(base, suite, p, work):
    """The suite's main/binary-amd64 Packages stanzas for linux-image-* packages, newest version of each, as
    dicts. Only those are kept: a whole Debian index is tens of thousands of stanzas."""
    release_path = artifact(p, work, "InRelease", f"{base}/dists/{suite}/InRelease")
    release, signers = signed_bytes(read_bytes(release_path), None, p["keys"])
    section, fields, checksums = "", {}, {}
    for line in release.decode("utf-8").splitlines():
        if line.startswith(" ") and section == "SHA256":
            digest, size, name = line.split()
            if name in checksums or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
                raise EnvError("ambiguous signed Release SHA256 entry")
            checksums[name] = (digest, int(size))
        elif line and not line[0].isspace():
            section, _, value = line.partition(":")
            fields[section] = value.strip()
    if suite not in (fields.get("Suite"), fields.get("Codename")):
        raise EnvError("signed Release is for a different suite")
    # Cached proofs attest historical artifacts, not repository freshness. New downloads must satisfy the
    # publisher's expiry when present; --refresh asks for current metadata instead of the retained snapshot.
    if not p.get("_offline"):
        now = datetime.datetime.now(datetime.timezone.utc)
        date = email.utils.parsedate_to_datetime(fields["Date"])
        if date > now + datetime.timedelta(days=1):
            raise EnvError("signed Release is dated in the future")
        if "Valid-Until" in fields and email.utils.parsedate_to_datetime(fields["Valid-Until"]) < now:
            raise EnvError("signed Release has expired")
    index_name = "main/binary-amd64/Packages.xz"
    if index_name not in checksums:
        raise EnvError("signed Release does not authenticate Packages.xz")
    digest, size = checksums[index_name]
    index = artifact(p, work, "Packages.xz", f"{base}/dists/{suite}/{index_name}")
    if os.path.getsize(index) != size:
        raise EnvError("Packages.xz size differs from signed Release")
    verify_sha256(index, digest, "signed Release Packages.xz")
    p["_verification"] = {"method": "publisher-inrelease", "primary_fingerprints": signers,
                          "publisher_signature_checked": True,
                          "signed_metadata_sha256": file_sha256(release_path)}
    compressed = io.BytesIO(read_bytes(index))
    out = {}
    fields, key = {}, None

    def done():
        name = fields.get("Package", "")
        if name.startswith("linux-image-") and (
                name not in out or vkey(fields.get("Version", "")) > vkey(out[name].get("Version", ""))):
            out[name] = dict(fields)

    with lzma.open(compressed, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                done()
                fields, key = {}, None
            elif line.startswith((" ", "\t")) and key:
                fields[key] += "\n" + line.strip()
            elif ":" in line:
                key, _, val = line.partition(":")
                fields[key] = val.strip()
    done()
    return out


def deb_vmlinuz(path):
    """The kernel image inside a .deb: an ar archive whose data.tar.* member is read as a stream, because
    Debian's image package carries every module too and is hundreds of megabytes unpacked."""
    with open(path, "rb", buffering=0) as f:
        if f.read(8) != b"!<arch>\n":
            raise EnvError(f"{os.path.basename(path)} is not an ar archive (.deb)")
        off = 8
        while True:
            f.seek(off)
            hdr = f.read(60)
            if len(hdr) < 60:
                break
            name = hdr[:16].decode().strip().rstrip("/")
            size = int(hdr[48:58].decode().strip())
            if name.startswith("data.tar"):
                f.seek(off + 60)
                cmd = decompressor(f.read(6))
                f.seek(off + 60)
                proc = subprocess.Popen(cmd, stdin=f, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                try:
                    with tarfile.open(fileobj=proc.stdout, mode="r|") as tar:
                        for m in tar:
                            if re.fullmatch(r"\.?/?boot/vmlinuz-.*", m.name) and m.isfile():
                                return tar.extractfile(m).read(), m.name.rsplit("vmlinuz-", 1)[1]
                finally:
                    proc.stdout.close()
                    proc.kill()
                    proc.wait()
            off += 60 + size + (size & 1)
    raise EnvError(f"{os.path.basename(path)} holds no boot/vmlinuz-*")


def fetch_deb(p, work):
    idx = deb_index(p["base"], p["suite"], p, work)
    meta = idx.get(p["meta"])
    if not meta:
        raise EnvError(f"{p['meta']} is not in {p['base']} {p['suite']}")
    # The metapackage names the image package the distro installs today; its first versioned
    # linux-image-* dependency is the kernel itself (the rest are firmware and microcode).
    deps = [d.strip().split(" ")[0] for d in meta.get("Depends", "").replace("|", ",").split(",")]
    image = next((d for d in deps if re.match(r"linux-image-\d", d)), None)
    if not image or image not in idx:
        raise EnvError(f"{p['meta']} {meta.get('Version')} depends on no linux-image-<version> in the index")
    pkg = idx[image]
    url = f"{p['base']}/{pkg['Filename']}"
    deb = artifact(p, work, "package", url)
    verify_sha256(deb, pkg.get("SHA256"), url)
    verify_package_pin(deb, p)
    img, release = deb_vmlinuz(deb)
    return img, {"package": image, "version": pkg.get("Version"), "release": release, "url": url,
                 "sha256": pkg["SHA256"], "verification": p["_verification"]}


# ---- .rpm ------------------------------------------------------------------------------------------

def rpm_payload_offset(f):
    """Where an RPM's compressed payload starts: after the 96-byte lead, the signature header (padded to 8)
    and the main header. Header layout: magic(3) version(1) reserved(4) count(4) size(4), then 16 bytes per
    index entry and `size` bytes of data."""
    if f.read(4) != b"\xed\xab\xee\xdb":
        raise EnvError("not an RPM")
    off = 96
    for pad in (True, False):
        f.seek(off)
        hdr = f.read(16)
        if hdr[:3] != b"\x8e\xad\xe8":
            raise EnvError(f"bad RPM header magic at {off}")
        count, size = struct.unpack(">II", hdr[8:16])
        off += 16 + 16 * count + size
        if pad:
            off += (8 - off % 8) % 8
    return off


def decompressor(magic):
    """The command that decompresses a payload starting with these bytes to stdout. A kernel package's
    payload is larger than this box's free memory wants to hold twice, so it streams through a pipe."""
    if magic[:6] == b"\xfd7zXZ\x00":
        return ["xz", "-dc"]
    if magic[:4] == b"\x28\xb5\x2f\xfd":
        return ["zstd", "-dc"]
    if magic[:2] == b"\x1f\x8b":
        return ["gzip", "-dc"]
    raise EnvError(f"unknown RPM payload compression (magic {magic[:6].hex()})")


def read_exact(r, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = r.read(n - len(buf))
        if not chunk:
            raise EnvError("the cpio payload ended early")
        buf += chunk
    return bytes(buf)


def skip(r, n):
    while n > 0:
        chunk = r.read(min(n, 1 << 20))
        if not chunk:
            raise EnvError("the cpio payload ended early")
        n -= len(chunk)


def cpio_first(r, want):
    """The first newc member of stream r whose name matches `want`, as (name, bytes); members before it
    are skipped without being held in memory."""
    while True:
        hdr = read_exact(r, 110)
        if hdr[:6] not in (b"070701", b"070702"):
            raise EnvError(f"unexpected cpio header {hdr[:6]!r}")
        f = [int(hdr[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
        filesize, namesize = f[6], f[11]
        name = read_exact(r, namesize)[:-1].decode("utf-8", "replace")
        skip(r, (4 - (110 + namesize) % 4) % 4)
        if name == "TRAILER!!!":
            return None
        pad = (4 - filesize % 4) % 4
        if want.fullmatch(name) and filesize:
            body = read_exact(r, filesize)
            return name, body
        skip(r, filesize + pad)


def rpm_vmlinuz(path):
    want = re.compile(r"\.?/?(lib/modules/[^/]+/vmlinuz|boot/vmlinuz-[^/]+)")
    # Unbuffered: the decompressor reads the descriptor itself, from wherever its offset is, and a buffered
    # reader's seek back into its own buffer would not move that offset.
    with open(path, "rb", buffering=0) as f:
        off = rpm_payload_offset(f)
        f.seek(off)
        cmd = decompressor(f.read(6))
        f.seek(off)
        if not shutil.which(cmd[0]):
            raise EnvError(f"the payload needs {cmd[0]}, which is not on PATH")
        proc = subprocess.Popen(cmd, stdin=f, stdout=subprocess.PIPE)
        try:
            found = cpio_first(proc.stdout, want)
        finally:
            proc.stdout.close()
            proc.kill()
            proc.wait()
    if not found:
        raise EnvError(f"{os.path.basename(path)} holds no vmlinuz")
    name, body = found
    m = re.search(r"lib/modules/([^/]+)/vmlinuz", name) or re.search(r"boot/vmlinuz-(.+)", name)
    return body, m.group(1)


def repo_base(p):
    if "repo" in p:
        return p["repo"]
    # Amazon Linux publishes its repository under a per-release GUID; the mirror list names the current one.
    return get(p["mirrorlist"]).decode().split()[0].rstrip("/") + "/"


def newest_in_repo(base, name, work, p):
    repomd_path = artifact(p, work, "repomd.xml", base + "repodata/repomd.xml")
    signature = artifact(p, work, "repomd.xml.asc", base + "repodata/repomd.xml.asc")
    raw, signers = signed_bytes(read_bytes(signature), read_bytes(repomd_path), p["keys"])
    repomd = ET.fromstring(raw)
    p["_verification"] = {"method": "publisher-repomd", "primary_fingerprints": signers,
                          "publisher_signature_checked": True,
                          "signed_metadata_sha256": file_sha256(repomd_path)}
    ns = {"r": "http://linux.duke.edu/metadata/repo"}
    loc = None
    for d in repomd.findall("r:data", ns):
        if d.get("type") == "primary":
            loc = d.find("r:location", ns).get("href")
            primary_sum = xml_sha256(d, "{http://linux.duke.edu/metadata/repo}", f"{base}repodata/repomd.xml primary")
    if not loc:
        raise EnvError(f"{base}repodata/repomd.xml names no primary metadata")
    compressed = artifact(p, work, "primary", base + loc)
    verify_sha256(compressed, primary_sum, base + loc)
    with open(compressed, "rb") as f:
        cmd = decompressor(f.read(6))
    # The package list of a whole distro repository is hundreds of megabytes of XML once decompressed, so it
    # is read as a stream and each <package> is dropped as soon as it has been looked at.
    common = "{http://linux.duke.edu/metadata/common}"
    best = None
    with open(compressed, "rb") as f:
        proc = subprocess.Popen(cmd, stdin=f, stdout=subprocess.PIPE)
        try:
            for _, el in ET.iterparse(proc.stdout, events=("end",)):
                if el.tag != common + "package":
                    continue
                if el.findtext(common + "name") == name and el.findtext(common + "arch") == "x86_64":
                    v = el.find(common + "version")
                    ver = f"{v.get('ver')}-{v.get('rel')}"
                    if best is None or vkey(ver) > vkey(best[0]):
                        best = (ver, el.find(common + "location").get("href"),
                                xml_sha256(el, common, f"{name} {ver} in {base}"))
                el.clear()
        finally:
            proc.stdout.close()
            proc.wait()
    if not best:
        raise EnvError(f"no x86_64 {name} in {base}")
    return best


def fetch_rpm(p, work):
    basefile = os.path.join(work, "repository.txt")
    if p.get("_offline"):
        base = read_bytes(basefile).decode("utf-8")
    else:
        base = repo_base(p)
        with open(basefile, "w") as f:
            f.write(base)
    ver, href, want = newest_in_repo(base, p["package"], work, p)
    # Amazon Linux's hrefs climb out of the repository into a shared blob store ("../../../../blobstore/..."),
    # and its CDN refuses the unnormalized path.
    url = urllib.parse.urljoin(base, href)
    rpm = artifact(p, work, "package", url)
    verify_sha256(rpm, want, url)
    verify_package_pin(rpm, p)
    img, release = rpm_vmlinuz(rpm)
    return img, {"package": p["package"], "version": ver, "release": release, "url": url, "sha256": want,
                 "verification": p["_verification"]}


def listing(url):
    return re.findall(r'href="([^"?/][^"]*)"', get(url).decode("utf-8", "replace"))


def fetch_koji(p, work):
    if p.get("_offline"):
        rpm = artifact(p, work, "package", "")
        keys = [k for k in KEYS if k.startswith("fedora-")]
        verification, version = rpm_signed_package(rpm, keys, p["package"])
        verify_package_pin(rpm, p)
        img, release = rpm_vmlinuz(rpm)
        return img, {"package": p["package"], "version": version, "release": release,
                     "url": "https://kojipkgs.fedoraproject.org/ (authenticated retained RPM)",
                     "sha256": file_sha256(rpm), "verification": verification}
    series = p["series"]
    versions = sorted({h.rstrip("/") for h in listing(KOJI) if re.fullmatch(re.escape(series) + r"\.\d+/", h)},
                      key=vkey, reverse=True)
    if not versions:
        raise EnvError(f"koji lists no kernel {series}.x builds")
    for ver in versions:
        # A release directory per Fedora branch; the newest Fedora's build of the newest point release wins.
        rels = sorted((h.rstrip("/") for h in listing(KOJI + ver + "/") if re.fullmatch(r"\d+\.fc\d+/", h)),
                      key=lambda r: vkey(r.split(".fc")[1] + "." + r.split(".")[0]), reverse=True)
        for rel in rels:
            key = "fedora-" + rel.split(".fc")[1]
            if key not in KEYS:
                continue # a new Fedora signing key requires a reviewed trust-anchor update
            name = f"{p['package']}-{ver}-{rel}.x86_64.rpm"
            # Koji's build artifact can be unsigned. Only its publisher-signed copy is acceptable.
            url = f"{KOJI}{ver}/{rel}/data/signed/{KEYS[key][-8:].lower()}/x86_64/{name}"
            rpm = os.path.join(work, "package")
            try:
                download(url, rpm)
            except EnvError:
                continue  # koji garbage-collects old builds' RPMs; try the next one
            verification, version = rpm_signed_package(rpm, [key], p["package"])
            if version != f"{ver}-{rel}":
                raise EnvError("signed Koji RPM version differs from the selected build")
            verify_package_pin(rpm, p)
            img, release = rpm_vmlinuz(rpm)
            return img, {"package": p["package"], "version": f"{ver}-{rel}", "release": release, "url": url,
                         "sha256": file_sha256(rpm), "verification": verification}
    raise EnvError(f"no downloadable {p['package']} for kernel {series}.x on koji")


FETCHERS = {"deb": fetch_deb, "rpm": fetch_rpm, "koji": fetch_koji}


def release_series(release):
    """The major.minor of a kernel release string ("6.12.43+deb13-amd64" -> "6.12"), or None. The series is
    compared whole: a prefix test lets "6.12.103-..." pass for the 6.1 row, which is the move of AL2023's
    default kernel from 6.1 to 6.12 the check exists to catch."""
    m = re.match(r"(\d+\.\d+)(?:[.+~-]|$)", release or "")
    return m.group(1) if m else None


def check_series(row, series, info):
    got = release_series(info.get("release"))
    if got != series:
        raise EnvError(f"{row} is meant to test the {series} series, but {info.get('package')} {info.get('version')} "
                       f"is kernel {info.get('release')} (series {got}); --refresh fetches the row again")


def fetch(row, refresh=False):
    """The cached image of a row, fetched first when it is missing. The cache is shared by every checkout and
    matrix run on the box, so the whole call runs under an flock on the row's directory: a second caller waits,
    then finds the finished pair the first wrote (or repairs it) instead of reading a half-refreshed one."""
    pin = trusted_pin(row) # a configured but invalid/missing pin fails before any network or cache mutation
    dest_dir = os.path.join(cache_root(), "kernel", kernel_name(row))
    os.makedirs(dest_dir, exist_ok=True)
    with open(os.path.join(dest_dir, ".lock"), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _fetch_locked(row, refresh, dest_dir, pin)


def _fetch_locked(row, refresh, dest_dir, pin=None):
    series, label, kind, params = ROWS[row]
    params = dict(params)
    if pin:
        params["_trusted_pin"] = pin
    image = os.path.join(dest_dir, "vmlinuz")
    src = os.path.join(dest_dir, "source.json")
    proof = os.path.join(dest_dir, "proof")

    def finish_info(img, info):
        check_series(row, series, info)
        if not info.get("verification", {}).get("publisher_signature_checked"):
            raise EnvError(f"{row}: fetcher supplied no publisher authentication evidence")
        info.update({"row": row, "series": series, "label": label,
                     "image_sha256": hashlib.sha256(img).hexdigest()})
        verify_image_pin(pin, info, info["image_sha256"])
        return info

    if os.path.isfile(image) and os.path.isdir(proof) and not refresh:
        # Neither source.json nor its self-hash is authority. Reverify the retained signed metadata/package,
        # re-extract its image, and compare those authenticated bytes with what KVM would boot.
        img, info = FETCHERS[kind](dict(params, _offline=True), proof)
        finish_info(img, info)
        if file_sha256(image) != info["image_sha256"]:
            raise EnvError(f"{row}: cached image differs from the authenticated package; use --refresh")
        with tempfile.NamedTemporaryFile(mode="w", dir=dest_dir, delete=False) as f:
            tmp_src = f.name
            json.dump(info, f, indent=1)
            f.write("\n")
        try:
            os.replace(tmp_src, src)
        finally:
            if os.path.exists(tmp_src):
                os.unlink(tmp_src)
        return image

    # Legacy image/source.json pairs lack a signing proof and are always fetched again. Publish the proof,
    # source and image in that order; interruption cannot leave an image that bypasses fresh verification.
    for stale in (image, src):
        if os.path.lexists(stale):
            os.unlink(stale)
    if os.path.lexists(proof):
        if os.path.islink(proof):
            os.unlink(proof)
        else:
            shutil.rmtree(proof)
    with tempfile.TemporaryDirectory(dir=dest_dir) as work:
        img, info = FETCHERS[kind](params, work)
        finish_info(img, info)
        with open(os.path.join(work, "source.json"), "w") as f:
            json.dump(info, f, indent=1)
            f.write("\n")
        with open(os.path.join(work, "vmlinuz"), "wb") as f:
            f.write(img)
        os.replace(work, proof)
        os.replace(os.path.join(proof, "source.json"), src)
        os.replace(os.path.join(proof, "vmlinuz"), image)
    return image


def main(argv):
    refresh = False
    args = [a for a in argv if a != "--refresh"]
    refresh = len(args) != len(argv)
    if args == ["--list"]:
        for row, (series, label, kind, _) in ROWS.items():
            print(f"{row:<14} {series:<6} {kind:<5} {body_of(row):<11} {label}")
        return 0
    if len(args) == 2 and args[0] == "--name" and args[1] in ROWS:
        print(kernel_name(args[1]))
        return 0
    if len(args) == 2 and args[0] == "--body" and args[1] in ROWS:
        print(body_of(args[1]))
        return 0
    if len(args) != 1 or args[0] not in ROWS:
        print("usage: fetch-kernel.py [--refresh] <row> | --list | --name <row> | --body <row>", file=sys.stderr)
        print("rows: " + " ".join(ROWS), file=sys.stderr)
        return EXIT_USAGE
    try:
        print(fetch(args[0], refresh))
    except EnvError as e:
        print(f"fetch-kernel: {args[0]}: {e}", file=sys.stderr)
        return EXIT_ENV
    except Exception as e:
        # A reply that is not what the parser expects (a captive portal's HTML, a truncated index, a corrupt
        # archive) or a full disk is this box failing to fetch the row, not a test that failed.
        print(f"fetch-kernel: {args[0]}: {type(e).__name__}: {e}", file=sys.stderr)
        return EXIT_ENV
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
