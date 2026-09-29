#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Tests what fetch-kernel.py holds a downloaded kernel package to, without a network: no row names a plain-http
# source (the Ubuntu row once read its index and .deb over http://archive.ubuntu.com), and a .deb is refused when
# its SHA256 differs from the index's, or when the index lists none.
set -eu
unset TEGO_VM_KERNEL_MANIFEST

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
python3 - "$here/fetch-kernel.py" <<'PY'
import importlib.util, os, re, sys, tempfile, hashlib, shutil

spec = importlib.util.spec_from_file_location("fetch_kernel", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

fail = 0

def check(name, ok):
    global fail
    print(("ok   " if ok else "FAIL ") + name)
    if not ok:
        fail = 1

check("no row reads its packages over plain http",
      not any(str(v).startswith("http://") for _, _, _, params in m.ROWS.values() for v in params.values()))

# The rows (ADR 0017's 2026-10-05 note on the matrix's rows): Ubuntu 25.10's 6.17 and Fedora 7.2's Landlock ABI 10 are rows, each named for the
# series it tests, each authenticated by keys kernel_auth pins and a fetcher that exists. A series typed wrong
# ("7.20", "6.7") would make check_series refuse the very kernel the row is for, or accept another one.
for row, series, kind in (("ubuntu-25.10", "6.17", "deb"), ("fedora-7.2", "7.2", "koji")):
    got = m.ROWS.get(row)
    check(f"{row} is a {kind} row of the {series} series", got is not None and got[0] == series and got[2] == kind)
# Ubuntu 22.04's 5.15 has Landlock ABI 1, below doctor's floor of 2, so no tier is offered there (ADR 0017's
# note): its row is the one doctor-only row, which matrix.sh boots for run-matrix-row.sh --only doctor-refusal and nothing
# else. Which rows are doctor-only is fetch-kernel.py's to say, through --list's fourth column and --body, so
# matrix.sh and the nightly workflow never hold a row name of their own.
got = m.ROWS.get("ubuntu-22.04")
check("ubuntu-22.04 is a deb row of the 5.15 series", got is not None and got[0] == "5.15" and got[2] == "deb")
check("ubuntu-22.04 is the only doctor-only row, and every doctor-only row is a row",
      getattr(m, "DOCTOR_ONLY", None) == {"ubuntu-22.04"} and m.DOCTOR_ONLY <= set(m.ROWS))
import subprocess
def cli(*args):
    p = subprocess.run([sys.executable, sys.argv[1], *args], capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr
rc, out, _ = cli("--list")
listed = [line.split(None, 4) for line in out.splitlines()]
check("--list names every row once, with its series, kind, body and label",
      rc == 0 and [r[0] for r in listed] == list(m.ROWS) and all(len(r) == 5 for r in listed)
      and [(r[1], r[2]) for r in listed] == [(s, k) for s, _, k, _ in m.ROWS.values()])
check("--list says doctor-only for ubuntu-22.04 and full for every other row",
      {r[0]: r[3] for r in listed if len(r) == 5} == {row: ("doctor-only" if row == "ubuntu-22.04" else "full") for row in m.ROWS})
for row, want in (("ubuntu-22.04", "doctor-only"), ("rhel-9", "full"), ("fedora-7.2", "full")):
    rc, out, _ = cli("--body", row)
    check(f"--body {row} prints {want}", rc == 0 and out.strip() == want)
rc, out, err = cli("--body", "no-such-row")
check("--body of an unknown row is a usage error and prints nothing", rc == 2 and out == "")

# The nightly runs every row, and runs the suites that need a tier only on the rows that have one, by asking --body
# rather than by naming rows. A row added to fetch-kernel.py and left out of the workflow, or a step that names the
# doctor-only row, is a row nothing exercises or one that fails for want of a tier.
wf = open(os.path.join(os.path.dirname(sys.argv[1]), "..", "..", ".github", "workflows", "vm-matrix.yml")).read()
in_matrix = re.findall(r"^ {10}- ([a-z0-9][a-z0-9.-]*)$", wf.split("    steps:")[0].split("kernel:", 1)[1], re.M)
check("the nightly's matrix is every row of fetch-kernel.py, in its order", in_matrix == list(m.ROWS))
check("the nightly asks fetch-kernel.py which body a row has", "fetch-kernel.py --body" in wf)
check("the nightly names no doctor-only row in a step condition",
      not any(f"'{row}'" in wf for row in m.DOCTOR_ONLY))

# The body step fails closed. Its run block, taken from the workflow as written, runs under the shell GitHub gives
# `shell: bash` (bash --noprofile --norc -eo pipefail): it writes body=full or body=doctor-only for a row, and when
# fetch-kernel.py fails, prints nothing, or prints a body it does not know, the step fails and writes no body. It
# once ran `echo "body=$(...)"`, which exits 0 with an empty body whatever the script did, and the steps gated on
# `== 'full'` were then skipped and the row went green. Those steps are gated on `!= 'doctor-only'` now, so an
# empty body runs them.
step = re.search(r"\n      - name: the body of [^\n]*\n        id: body\n((?:        [^\n]*\n)+)", wf)
check("the nightly has the body step", step is not None)
fields = step.group(1) if step else ""
check("the body step runs under shell: bash, which is bash -eo pipefail", "\n        shell: bash\n" in "\n" + fields)
run = re.search(r"^        run: \|\n((?:(?: {10}[^\n]*)?\n)+)", fields, re.M)
script = re.sub(r"^ {10}", "", run.group(1), flags=re.M) if run else ""
check("the body step's run block is found", "fetch-kernel.py --body" in script)
repo = os.path.join(os.path.dirname(sys.argv[1]), "..", "..")
with tempfile.TemporaryDirectory() as td:
    open(os.path.join(td, "python3"), "w").write("#!/bin/sh\nprintf %s \"$FAKE_OUT\"\nexit \"$FAKE_RC\"\n")
    os.chmod(os.path.join(td, "python3"), 0o755)
    def body_step(row, fake=None):
        out = os.path.join(td, "output")
        open(out, "w").close()
        env = dict(os.environ, KERNEL=row, GITHUB_OUTPUT=out)
        if fake is not None:
            env.update(PATH=td + os.pathsep + os.environ["PATH"], FAKE_OUT=fake[0], FAKE_RC=str(fake[1]))
        p = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
                           cwd=repo, env=env, capture_output=True, text=True)
        return p.returncode, open(out).read(), p.stdout
    for row, want in (("ubuntu-22.04", "doctor-only"), ("rhel-9", "full"), ("fedora-7.2", "full")):
        rc, out, _ = body_step(row)
        check(f"the body step writes body={want} for {row}", rc == 0 and out == f"body={want}\n")
    rc, out, _ = body_step("no-such-row")
    check("the body step fails, and writes no body, for a row fetch-kernel.py does not know", rc != 0 and out == "")
    for name, fake in (("fetch-kernel.py fails after printing full", ("full", 1)),
                       ("fetch-kernel.py fails and prints nothing", ("", 1)),
                       ("fetch-kernel.py exits 0 and prints nothing", ("", 0)),
                       ("fetch-kernel.py prints a body it does not know", ("partial", 0))):
        rc, out, stdout = body_step("rhel-9", fake)
        check(f"the body step fails, and writes no body, when {name}",
              rc != 0 and out == "" and (fake[1] != 0 or "::error::" in stdout))
gates = re.findall(r"^        if: (.*steps\.body\.outputs\.body.*)$", wf, re.M)
check("the steps gated on the body run unless it is doctor-only, so an empty body cannot skip them",
      len(gates) >= 4 and all("steps.body.outputs.body != 'doctor-only'" in g for g in gates)
      and "steps.body.outputs.body ==" not in wf)

# enforce/landlock's integration tests hold a row to the Landlock ABI it is meant to have (rowABIFloor, read from
# TEGO_VM_ROW, which root-suites.sh forwards): its keys are rows of this file, and the nightly runs those tests on each.
src = open(os.path.join(os.path.dirname(sys.argv[1]), "..", "..", "internal", "runtime", "enforce", "landlock", "integration_abi_test.go")).read()
floor_rows = re.findall(r'"([a-z0-9.-]+)":\s*\d+', re.search(r"var rowABIFloor = map\[string\]int\{([^}]*)\}", src).group(1))
check("rowABIFloor names fedora-7.2, and only rows of this file", floor_rows == ["fedora-7.2"] and all(r in m.ROWS for r in floor_rows))
check("the nightly runs the Landlock ABI tests on each row rowABIFloor names",
      all(f"matrix.kernel == '{r}'" in wf and "TestIntegrationUnixConnect" in wf for r in floor_rows))

# internal/platform/peer's tests hold a row below Linux 6.5 to the pidfd_open fallback (rowsWithoutPeerPidfd, read
# from TEGO_VM_ROW): its keys are full rows of this file below 6.5, and the nightly's row job runs that package and
# internal/runscope as root on every row with a body, so on each of them. ADR 0100's Tests section names this gate,
# which a review found no suite ran.
src = open(os.path.join(os.path.dirname(sys.argv[1]), "..", "..", "internal", "platform", "peer", "peer_test.go")).read()
fallback_rows = re.findall(r'"([a-z0-9.-]+)":\s*true', re.search(r"var rowsWithoutPeerPidfd = map\[string\]bool\{([^}]*)\}", src).group(1))
check("rowsWithoutPeerPidfd names rhel-9 and al2023, full rows of this file below Linux 6.5",
      fallback_rows == ["rhel-9", "al2023"]
      and all(r in m.ROWS and r not in m.DOCTOR_ONLY and tuple(int(x) for x in m.ROWS[r][0].split(".")) < (6, 5)
              for r in fallback_rows))
peer_steps = [st for st in re.split(r"\n(?=      - )", wf) if "test/vm/root-suites.sh internal/platform/peer internal/runscope" in st]
check("the nightly runs the peer check and runscope as root on every row with a body, so on each rowsWithoutPeerPidfd names",
      len(peer_steps) == 1
      and re.search(r"^        if: matrix\.part == 'row' && steps\.body\.outputs\.body != 'doctor-only'$", peer_steps[0], re.M) is not None
      and 'TEGO_VM_ROW="$KERNEL"' in peer_steps[0])

check("every row's signing keys are keys kernel_auth pins",
      all(k in m.KEYS for _, _, _, params in m.ROWS.values() for k in params.get("keys", [])))
check("every row has a fetcher", all(kind in m.FETCHERS for _, _, kind, _ in m.ROWS.values()))
check("every row's series is the major.minor of a kernel release",
      all(m.release_series(series + ".1") == series for series, _, _, _ in m.ROWS.values()))
for row, (series, _, _, _) in m.ROWS.items():
    info = {"package": "p", "version": "v", "release": series + ".3-1.x86_64"}
    other = {"package": "p", "version": "v", "release": "9.99.3-1.x86_64"}
    try:
        m.check_series(row, series, info)
        ok = True
    except m.EnvError:
        ok = False
    try:
        m.check_series(row, series, other)
        ok = False
    except m.EnvError:
        pass
    check(f"{row} takes a {series} kernel and refuses another series", ok)

d = tempfile.mkdtemp()
f = os.path.join(d, "a.deb")
open(f, "wb").write(b"kernel")
good = hashlib.sha256(b"kernel").hexdigest()

m.verify_sha256(f, good, "x")
check("a download that matches the index passes", os.path.exists(f))
for label, want in (("a mismatching digest", "0" * 64), ("an index with no digest", None)):
    try:
        m.verify_sha256(f, want, "x")
        check(label + " is refused", False)
    except m.EnvError:
        check(label + " is refused", True)
    if not os.path.exists(f):
        open(f, "wb").write(b"kernel")

# The RPM rows: a repository whose primary.xml or package differs from the digest its metadata lists is refused,
# and one that lists none is too. A fake repository stands in for the network (m.get and m.download).
import gzip, json

base = "https://repo.invalid/x/"
pkgbytes = b"rpm-bytes"

def repo(primary_sum, pkg_sum, pkg_sum_type="sha256"):
    primary = ('<metadata xmlns="http://linux.duke.edu/metadata/common"><package type="rpm"><name>kernel-core</name>'
               '<arch>x86_64</arch><version epoch="0" ver="5.14" rel="1"/>'
               + (f'<checksum type="{pkg_sum_type}" pkgid="YES">{pkg_sum}</checksum>' if pkg_sum else "") +
               '<location href="Packages/k.rpm"/></package></metadata>').encode()
    gz = gzip.compress(primary)
    if primary_sum == "auto":
        primary_sum = hashlib.sha256(gz).hexdigest()
    sumx = f'<checksum type="sha256">{primary_sum}</checksum>' if primary_sum else ""
    repomd = ('<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary">' + sumx +
              '<location href="repodata/primary.xml.gz"/></data></repomd>').encode()
    files = {base + "repodata/repomd.xml.asc": b"signature fixture", base + "repodata/repomd.xml": repomd, base + "repodata/primary.xml.gz": gz, base + "Packages/k.rpm": pkgbytes}
    def get(url, timeout=120):
        return files[url]
    def download(url, dest):
        open(dest, "wb").write(files[url])
    m.get, m.download = get, download

def refused(fn):
    try:
        fn()
        return False
    except m.EnvError:
        return True

m.signed_bytes = lambda signature, body, keys: (body, ["fixture"])
p = {"repo": base, "package": "kernel-core", "keys": ["fixture"]}
work = tempfile.mkdtemp()
good_pkg = hashlib.sha256(pkgbytes).hexdigest()
repo("0" * 64, good_pkg)
check("a primary.xml that differs from repomd.xml's checksum is refused", refused(lambda: m.newest_in_repo(base, "kernel-core", work, p)))
repo(None, good_pkg)
check("repomd.xml with no primary checksum is refused", refused(lambda: m.newest_in_repo(base, "kernel-core", work, p)))
repo("auto", None)
check("a package with no checksum in primary.xml is refused", refused(lambda: m.newest_in_repo(base, "kernel-core", work, p)))
repo("auto", "0" * 64)
ver, href, want = m.newest_in_repo(base, "kernel-core", work, p)
check("a good primary.xml yields the package's checksum", want == "0" * 64)
m.rpm_vmlinuz = lambda path: (b"IMG", "5.14.0")
check("an RPM that differs from its listed checksum is refused", refused(lambda: m.fetch_rpm(p, work)))
repo("auto", good_pkg)
img, info = m.fetch_rpm(p, work)
check("an RPM that matches is accepted and its sha256 recorded", img == b"IMG" and info.get("sha256") == good_pkg)

# The koji rows (Fedora 7.0 and 7.2): the newest point release of the row's own series wins, numerically (7.2.10
# over 7.2.9, and never 7.20.1, 7.3.0 or a release candidate), a build whose signed RPM koji no longer serves hands
# over to the next Fedora's, and a release no pinned Fedora key signs is passed over without a request. A fake koji
# stands in for the network (m.listing, m.download) and for the RPM reading (m.rpm_signed_package, m.rpm_vmlinuz).
import re
koji_dirs = {
    m.KOJI: ["6.19.14/", "7.0.14/", "7.2.0/", "7.2.9/", "7.2.10/", "7.2.9-rc1/", "7.20.1/", "7.3.0/", "?C=N;O=D"],
    m.KOJI + "7.2.10/": ["0.rc1.1.fc46/", "300.fc45/", "200.fc44/", "100.fc43/", "900.fc99/"],
}
koji_asked = []
def koji_nvr():
    return re.search(r"kernel-core-(.+)\.x86_64\.rpm$", koji_asked[-1]).group(1)
def koji_download(url, dest):
    koji_asked.append(url)
    if "/300.fc45/" in url:
        raise m.EnvError("koji no longer serves it")
    open(dest, "wb").write(b"rpm")
saved = (m.listing, m.download, m.rpm_signed_package, m.rpm_vmlinuz)
m.listing = lambda url: koji_dirs[url]
m.download = koji_download
m.rpm_signed_package = lambda rpm, keys, package: ({"method": "stub", "publisher_signature_checked": True, "keys": keys}, koji_nvr())
m.rpm_vmlinuz = lambda path: (b"IMG", koji_nvr() + ".x86_64")
try:
    img, info = m.fetch_koji({"series": "7.2", "package": "kernel-core"}, tempfile.mkdtemp())
    check("a koji row takes the newest point release of its series, from the newest Fedora whose RPM is served",
          img == b"IMG" and info["version"] == "7.2.10-200.fc44" and info["release"] == "7.2.10-200.fc44.x86_64")
    check("it asks only for the signed copy of that series' build, newest Fedora first, and never for a release no pinned key signs",
          len(koji_asked) == 2 and all(u.startswith(m.KOJI + "7.2.10/") for u in koji_asked)
          and "/300.fc45/" in koji_asked[0] and "/200.fc44/" in koji_asked[1]
          and all("/data/signed/" + m.KEYS["fedora-" + u.split(".fc")[1].split("/")[0]][-8:].lower() + "/x86_64/" in u for u in koji_asked))
    check("the build it took tests the 7.2 series", m.check_series("fedora-7.2", "7.2", info) is None)
    koji_dirs[m.KOJI] = ["7.0.14/", "7.20.1/", "7.3.0/"]
    check("a koji row whose series has no build is refused, with the series named",
          refused(lambda: m.fetch_koji({"series": "7.2", "package": "kernel-core"}, tempfile.mkdtemp())))
finally:
    m.listing, m.download, m.rpm_signed_package, m.rpm_vmlinuz = saved

# Cache mechanics below use extraction stand-ins; kernel-auth_test.py exercises real signatures/proofs.
class VerifiedFixtures(dict):
    def __setitem__(self, kind, fetcher):
        def wrapped(*args):
            image, info = fetcher(*args)
            info["verification"] = {"method": "signature-fixture", "publisher_signature_checked": True}
            return image, info
        super().__setitem__(kind, wrapped)
m.FETCHERS = VerifiedFixtures(m.FETCHERS)
# The image's digest is recorded and a changed cached image is refused.
cache = tempfile.mkdtemp()
m.cache_root = lambda: cache
m.FETCHERS["rpm"] = lambda params, w: (b"IMG", {"package": "kernel-core", "version": "5.14-1", "release": "5.14.0"})
image = m.fetch("rhel-9")
check("a fetched image has its sha256 recorded", json.load(open(os.path.join(os.path.dirname(image), "source.json")))["image_sha256"] == hashlib.sha256(b"IMG").hexdigest())
check("an unchanged cached image is reused", m.fetch("rhel-9") == image)
open(image, "wb").write(b"SWAPPED")
check("a cached image that changed is refused", refused(lambda: m.fetch("rhel-9")))

# Removing a self-hash cannot authorize an image that differs from the authenticated package.
srcp = os.path.join(os.path.dirname(image), "source.json")
info = json.load(open(srcp)); del info["image_sha256"]; json.dump(info, open(srcp, "w"))
open(image, "wb").write(b"OLD")
check("deleting source metadata cannot authorize a changed cached image", refused(lambda: m.fetch("rhel-9")))
m.fetch("rhel-9", refresh=True)
shutil.rmtree(os.path.join(os.path.dirname(image), "proof"))
check("a legacy cache with no signing proof is fetched again", m.fetch("rhel-9") == image and os.path.isdir(os.path.join(os.path.dirname(image), "proof")))

# A refresh that dies between its writes leaves a cache the next plain call repairs, not an EnvError.
class Crash(Exception):
    pass

def crash_then_recover(label, mod, attr, target):
    orig = getattr(mod, attr)
    def boom(*a, **k):
        if target(*a):
            raise Crash()
        return orig(*a, **k)
    setattr(mod, attr, boom)
    try:
        m.fetch("rhel-9", refresh=True)
        check(label + ": the crash happened", False)
    except Crash:
        pass
    finally:
        setattr(mod, attr, orig)
    m.FETCHERS["rpm"] = lambda params, w: (b"IMG2", {"package": "kernel-core", "version": "5.14-2", "release": "5.14.0"})
    try:
        ok = m.fetch("rhel-9") == image and open(image, "rb").read() == b"IMG2"
    except m.EnvError:
        ok = False
    check(label + ": the next plain fetch recovers", ok)
    m.FETCHERS["rpm"] = lambda params, w: (b"IMG", {"package": "kernel-core", "version": "5.14-1", "release": "5.14.0"})

crash_then_recover("a crash writing source.json", m.json, "dump", lambda *a: True)
crash_then_recover("a crash renaming the image in", m.os, "replace", lambda a, b: b == image)
# The cache is shared by concurrent matrix runs: a fetch waits while another holds the row's lock, and then
# finds the pair that one wrote instead of reading a half-refreshed cache.
import fcntl, threading, time
ddir = os.path.join(cache, "kernel", m.kernel_name("rhel-9"))
ran = []
m.FETCHERS["rpm"] = lambda params, w: (ran.append(1), (b"IMG3", {"package": "kernel-core", "version": "5.14-3", "release": "5.14.0"}))[1]
lockf = open(os.path.join(ddir, ".lock"), "a")
fcntl.flock(lockf, fcntl.LOCK_EX)
done = []
t = threading.Thread(target=lambda: done.append(m.fetch("rhel-9", refresh=True)))
t.start()
time.sleep(0.5)
check("a fetch waits while another holds the row's lock", not done and not ran)
fcntl.flock(lockf, fcntl.LOCK_UN)
t.join(10)
check("a fetch proceeds once the lock is released", done == [image] and ran == [1])

# An independently trusted manifest is an optional stronger root than the mirror's own index. Its absence
# retains mandatory publisher verification; a missing/bad pin cannot silently remove the additional constraint.
manifest = os.path.join(cache, "trusted.json")
os.environ["TEGO_VM_KERNEL_MANIFEST"] = manifest
pin = {"image_sha256": hashlib.sha256(b"PINNED").hexdigest(), "package_sha256": good_pkg,
       "provenance": "fixture: publisher signature verified against a separately pinned key"}
def write_manifest(entry=pin, row="rhel-9"):
    with open(manifest, "w") as f:
        json.dump({"version": 1, "rows": {row: entry}}, f)

check("a missing configured manifest is refused", refused(lambda: m.fetch("rhel-9")))
write_manifest(row="ubuntu-24.04")
check("a row missing from a configured manifest is refused", refused(lambda: m.fetch("rhel-9")))
for row in ("ubuntu-25.10", "fedora-7.2"):
    write_manifest(row=row)
    check(f"{row} has its own slot in a trusted manifest",
          (m.trusted_pin(row) or {}).get("image_sha256") == pin["image_sha256"] and refused(lambda: m.trusted_pin("rhel-9")))
for bad in ({"image_sha256": "bad", "provenance": "fixture"}, {"image_sha256": pin["image_sha256"]},
            {"provenance": "fixture"}, dict(pin, image_sh256=pin["image_sha256"])):
    write_manifest(bad)
    check("a malformed pin is refused", refused(lambda: m.fetch("rhel-9")))
write_manifest()
m.FETCHERS["rpm"] = lambda params, w: (b"PINNED", {"package": "kernel-core", "version": "5.14-1",
                                                 "release": "5.14.0", "sha256": good_pkg})
image = m.fetch("rhel-9", refresh=True)
info = json.load(open(os.path.join(os.path.dirname(image), "source.json")))
check("a pinned image records the trust anchor and provenance", info["verification"]["publisher_signature_checked"]
      and info["trusted_manifest"]["provenance"] == pin["provenance"]
      and info["trusted_manifest"]["manifest_sha256"] == m.file_sha256(manifest))
check("the pinned cached image is accepted", m.fetch("rhel-9") == image)

# Even an image and source.json whose self-hashes agree must match the independent image pin.
open(image, "wb").write(b"SUBSTITUTED")
srcp = os.path.join(os.path.dirname(image), "source.json")
info["image_sha256"] = hashlib.sha256(b"SUBSTITUTED").hexdigest()
json.dump(info, open(srcp, "w"))
check("a substituted cache and matching source.json are refused by the pin", refused(lambda: m.fetch("rhel-9")))

# A package-only pin cannot establish that a cached image was extracted from that package. Its recorded
# package hash can stay unchanged while both the image and its self-hash are replaced. Such a cache must
# be independently reverified and the authenticated package extracted again, even without --refresh.
write_manifest({"package_sha256": good_pkg, "provenance": pin["provenance"]})
refetched = []
def pinned_package(params, work):
    refetched.append(params["_trusted_pin"]["package_sha256"])
    return b"PINNED", {"package": "kernel-core", "version": "5.14-1", "release": "5.14.0", "sha256": good_pkg}
m.FETCHERS["rpm"] = pinned_package
check("a substituted cache with a package-only pin is refused after reverification",
      refused(lambda: m.fetch("rhel-9")) and refetched == [good_pkg])
m.fetch("rhel-9", refresh=True)
check("even an unchanged package-only cache is reverified through the package",
      m.fetch("rhel-9") == image and refetched == [good_pkg, good_pkg, good_pkg])
write_manifest()
m.FETCHERS["rpm"] = lambda params, w: (b"SUBSTITUTED", {"package": "kernel-core", "version": "5.14-1",
                                                      "release": "5.14.0", "sha256": good_pkg})
check("a newly fetched wrong image is refused", refused(lambda: m.fetch("rhel-9", refresh=True)))

repo("auto", good_pkg)
called = []
m.rpm_vmlinuz = lambda path: (called.append(True), (b"IMG", "5.14.0"))[1]
check("a wrong trusted package pin is refused before extraction",
      refused(lambda: m.fetch_rpm(dict(p, _trusted_pin={"package_sha256": "0" * 64}), work)) and not called)
os.environ.pop("TEGO_VM_KERNEL_MANIFEST")

# A reply the parsers do not expect, or a full disk, is this box unable to fetch the row (EXIT_ENV), not a fail.
for exc in (ValueError("not xml"), KeyError("Filename"), OSError(28, "No space left on device")):
    def boom(row, refresh=False, exc=exc):
        raise exc
    m.fetch = boom
    check("main maps " + type(exc).__name__ + " to EXIT_ENV", m.main(["rhel-9"]) == m.EXIT_ENV)
sys.exit(fail)
PY

python3 "$here/kernel-auth_test.py"
