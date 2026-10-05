#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real cryptographic verification with disposable signing keys; no network or host keyring changes."""
import gzip
import hashlib
import importlib.util
import json
import lzma
import os
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import kernel_auth as auth

spec = importlib.util.spec_from_file_location("fetch_kernel", os.path.join(os.path.dirname(__file__), "fetch-kernel.py"))
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)


def header(region, entries):
    data, index = bytearray(), []
    for tag, kind, value, count in sorted(entries):
        if kind == 4:
            data.extend(b"\0" * (-len(data) % 4))
        index.append(struct.pack(">IIiI", tag, kind, len(data), count))
        data.extend(value)
    n = len(index) + 1
    first = struct.pack(">IIiI", region, 7, len(data), 16)
    data.extend(struct.pack(">IIiI", region, 7, -n * 16, 16))
    return b"\x8e\xad\xe8\x01\0\0\0\0" + struct.pack(">II", n, len(data)) + first + b"".join(index) + data


class AuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="tego-kernel-auth-test-")
        cls.home = os.path.join(cls.temp.name, "gpg")
        cls.keys = os.path.join(cls.temp.name, "keys")
        os.mkdir(cls.home, 0o700)
        os.mkdir(cls.keys)
        cls.gpg = ["gpg", "--homedir", cls.home, "--no-options", "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
        cls.fingerprints = {}
        for name in ("publisher", "attacker"):
            subprocess.run(cls.gpg + ["--quick-generate-key", name + " <" + name + "@invalid>", "rsa2048", "sign", "0"],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            listing = subprocess.check_output(cls.gpg + ["--with-colons", "--fingerprint", name], stderr=subprocess.DEVNULL).decode()
            cls.fingerprints[name] = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
            with open(os.path.join(cls.keys, name + ".asc"), "wb") as f:
                subprocess.run(cls.gpg + ["--armor", "--export", cls.fingerprints[name]], check=True, stdout=f)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.keypatch = patch.multiple(auth, KEYS=self.fingerprints, KEY_DIR=self.keys)
        self.keypatch.start()
        self.addCleanup(self.keypatch.stop)
        self.work = tempfile.TemporaryDirectory(dir=self.temp.name)
        self.addCleanup(self.work.cleanup)

    def sign(self, data, who="publisher", clear=False, digest="SHA256"):
        with tempfile.TemporaryDirectory(dir=self.temp.name) as work:
            path = os.path.join(work, "data")
            with open(path, "wb") as f:
                f.write(data)
            out = path + ".sig"
            subprocess.run(self.gpg + ["--local-user", self.fingerprints[who], "--digest-algo", digest,
                                       "--output", out, "--clearsign" if clear else "--detach-sign", path],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return fetch.read_bytes(out)

    def test_detached_and_clearsigned(self):
        body = b"publisher metadata\n"
        self.assertEqual(auth.signed_bytes(self.sign(body), body, ["publisher"])[0], body)
        self.assertEqual(auth.signed_bytes(self.sign(body, clear=True), None, ["publisher"])[0], body)
        broken_signature = bytearray(self.sign(body))
        broken_signature[-3] ^= 1
        for signature, data in ((self.sign(body), body + b"tampered"),
                                (self.sign(body, "attacker"), body), (b"unsigned", body),
                                (broken_signature, body)):
            with self.assertRaises(auth.AuthError):
                auth.signed_bytes(signature, data, ["publisher"])
        with patch.dict(auth.KEYS, publisher=self.fingerprints["attacker"]):
            with self.assertRaisesRegex(auth.AuthError, "fingerprints"):
                auth.signed_bytes(self.sign(body), body, ["publisher"])

    def test_weak_signature_digest_refused(self):
        body = b"publisher metadata\n"
        with self.assertRaises(auth.AuthError):
            auth.signed_bytes(self.sign(body, digest="SHA1"), body, ["publisher"])

    def test_signatures_cannot_authenticate_another_embedded_body(self):
        first, other = b"trusted metadata\n", b"substituted metadata\n"
        with self.assertRaises(auth.AuthError):
            auth.signed_bytes(self.sign(first, clear=True), other, ["publisher"])
        with self.assertRaises(auth.AuthError):
            auth.signed_bytes(self.sign(first, clear=True) + self.sign(other, "attacker", clear=True), None, ["publisher"])

    def rpm(self, payload=b"compressed kernel payload", who="publisher", signed=True):
        entries = [(tag, 6, value.encode() + b"\0", 1) for tag, value in
                   ((1000, "kernel-core"), (1001, "7.0.1"), (1002, "1.fc44"), (1022, "x86_64"))]
        entries += [(5092, 8, hashlib.sha256(payload).hexdigest().encode() + b"\0", 1),
                    (5093, 4, struct.pack(">I", 8), 1)]
        main = header(63, entries)
        sig = self.sign(main, who)
        signatures = header(62, [(268, 7, sig, len(sig))] if signed else [])
        lead = b"\xed\xab\xee\xdb" + b"\0" * 92
        return lead + signatures + b"\0" * (-len(signatures) % 8) + main + payload

    def test_rpm_header_and_payload_authentication(self):
        path = os.path.join(self.work.name, "package")
        raw = self.rpm()
        with open(path, "wb") as f:
            f.write(raw)
        proof, version = auth.rpm_signed_package(path, ["publisher"], "kernel-core")
        self.assertTrue(proof["publisher_signature_checked"])
        self.assertEqual(version, "7.0.1-1.fc44")
        for bad in (raw[:-1] + b"X", raw.replace(b"kernel-core", b"kernel-evil"),
                    self.rpm(who="attacker"), self.rpm(signed=False), raw[:180]):
            with open(path, "wb") as f:
                f.write(bad)
            with self.assertRaises(auth.AuthError):
                auth.rpm_signed_package(path, ["publisher"], "kernel-core")

    def repo(self):
        base = "https://publisher.invalid/"
        package = b"authenticated kernel package"
        primary = ('<metadata xmlns="http://linux.duke.edu/metadata/common"><package><name>kernel-core</name>'
                   '<arch>x86_64</arch><version ver="5.14.1" rel="1"/><checksum type="sha256">' +
                   hashlib.sha256(package).hexdigest() + '</checksum><location href="kernel.rpm"/></package></metadata>').encode()
        primary = gzip.compress(primary)
        repomd = ('<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary"><checksum type="sha256">' +
                  hashlib.sha256(primary).hexdigest() + '</checksum><location href="primary.gz"/></data></repomd>').encode()
        files = {base + "repodata/repomd.xml": repomd, base + "repodata/repomd.xml.asc": self.sign(repomd),
                 base + "primary.gz": primary, base + "kernel.rpm": package}
        p = {"repo": base, "package": "kernel-core", "keys": ["publisher"]}
        return p, files

    def install_repo(self, p, files):
        def download(url, path):
            with open(path, "wb") as f:
                f.write(files[url])
        def extract(path):
            return b"IMAGE:" + fetch.read_bytes(path), "5.14.1"
        for target, value in (("download", download), ("rpm_vmlinuz", extract), ("cache_root", lambda: self.work.name)):
            patcher = patch.object(fetch, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        rows = patch.dict(fetch.ROWS, {"rhel-9": ("5.14", "fixture", "rpm", p)})
        rows.start()
        self.addCleanup(rows.stop)

    def test_signed_repository_chain_and_cache_substitution(self):
        p, files = self.repo()
        self.install_repo(p, files)
        image = fetch.fetch("rhel-9")
        self.assertEqual(fetch.fetch("rhel-9"), image)
        directory = os.path.dirname(image)
        source = os.path.join(directory, "source.json")
        info = json.loads(fetch.read_bytes(source))
        with open(image, "wb") as f:
            f.write(b"SUBSTITUTED")
        info["image_sha256"] = hashlib.sha256(b"SUBSTITUTED").hexdigest()
        with open(source, "w") as f:
            json.dump(info, f)
        with self.assertRaisesRegex(auth.AuthError, "authenticated package"):
            fetch.fetch("rhel-9")
        fetch.fetch("rhel-9", refresh=True)
        with open(os.path.join(directory, "proof", "package"), "wb") as f:
            f.write(b"SUBSTITUTED PACKAGE")
        with self.assertRaises(auth.AuthError):
            fetch.fetch("rhel-9")

    def test_bad_repository_signature_stops_before_extraction(self):
        p, files = self.repo()
        self.install_repo(p, files)
        files[p["repo"] + "repodata/repomd.xml"] += b"<!-- attacker -->"
        with patch.object(fetch, "rpm_vmlinuz", side_effect=AssertionError("unverified extraction")):
            with self.assertRaises(auth.AuthError):
                fetch.fetch("rhel-9")

    def test_cached_proof_reverified_even_when_source_claims_success(self):
        p, files = self.repo()
        self.install_repo(p, files)
        image = fetch.fetch("rhel-9")
        proof = os.path.join(os.path.dirname(image), "proof", "repomd.xml")
        with open(proof, "ab") as f:
            f.write(b"<!-- changed after download -->")
        with patch.object(fetch, "rpm_vmlinuz", side_effect=AssertionError("unverified extraction")):
            with self.assertRaises(auth.AuthError):
                fetch.fetch("rhel-9")

    def test_inrelease_authenticates_exact_packages_bytes(self):
        index = lzma.compress(b"Package: linux-image-fixture\nVersion: 6.12.1\n\n")
        release = ("Suite: trixie\nCodename: trixie\nDate: Thu, 01 Jan 2026 00:00:00 UTC\nSHA256:\n " +
                   hashlib.sha256(index).hexdigest() + " " + str(len(index)) + " main/binary-amd64/Packages.xz\n").encode()
        for name, body in (("InRelease", self.sign(release, clear=True)), ("Packages.xz", index)):
            with open(os.path.join(self.work.name, name), "wb") as f:
                f.write(body)
        p = {"keys": ["publisher"], "_offline": True}
        self.assertIn("linux-image-fixture", fetch.deb_index("https://publisher.invalid", "trixie", p, self.work.name))
        with open(os.path.join(self.work.name, "Packages.xz"), "wb") as f:
            f.write(index[:-1] + bytes([index[-1] ^ 1]))
        with self.assertRaises(auth.AuthError):
            fetch.deb_index("https://publisher.invalid", "trixie", p, self.work.name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
