# Kernel publisher trust anchors

These public keys are shipped with the verifier. `kernel_auth.py` pins their full
primary fingerprints and checks them in an isolated GnuPG keyring on every use.
Downloading a replacement key from the same mirror as a kernel never establishes
trust. The files contain public keys only, with third-party certifications removed
using GnuPG's `export-minimal`.

| File | Pinned primary fingerprint | Publisher reference |
|---|---|---|
| `ubuntu-2018.asc` | `F6ECB3762474EDA9D21B7022871920D1991BC93C` | [Ubuntu archive keys](https://wiki.ubuntu.com/Security/FAQ) |
| `debian-13-archive.asc` | `04B54C3CDCA79751B16BC6B5225629DF75B188BD` | [Debian archive keys](https://ftp-master.debian.org/keys.html) |
| `debian-13-release.asc` | `41587F7DB8C774BCCF131416762F67A0B2C39DE4` | [Debian release keys](https://ftp-master.debian.org/keys.html) |
| `almalinux-9.asc` | `BF18AC2876178908D6E71267D36CB86CB86B3716` | [AlmaLinux verification guide](https://wiki.almalinux.org/documentation/installation-guide) |
| `amazonlinux-2023.asc` | `B21C50FA44A99720EAA72F7FE951904AD832C631` | [Amazon Linux repository signing](https://docs.aws.amazon.com/linux/al2023/ug/repo-metadata-signing.html) |
| `fedora-44.asc` | `36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6` | [Fedora signing keys](https://fedoraproject.org/security/) |
| `fedora-45.asc` | `4F50A6114CD5C6976A7F1179655A4B02F577861E` | [Fedora signing keys](https://fedoraproject.org/security/) |
| `fedora-46.asc` | `D924B10D3E810DABDD8B56B596E7E91491211FCE` | [Fedora Rawhide signing key](https://fedoraproject.org/security/) |

Fingerprints were checked against those publisher references on 2026-10-01.
Debian and AlmaLinux key bytes came from their linked official key downloads.
Ubuntu and Fedora key bytes came from `keyserver.ubuntu.com`, selected by the
independently checked full fingerprint. Amazon's key came from the publisher's
`system-release-2023.0.20230206-0.amzn2023.noarch.rpm`; that bootstrap package was
used only to obtain the public key, whose fingerprint was checked against Amazon's
documentation before it was accepted. Bootstrap transport is not the trust anchor.

For rotation, independently verify the new fingerprint through the publisher's
security documentation and release announcements; add the key and its fingerprint
in a reviewed change, then run `fetch-kernel_test.sh` and a real refreshed fetch.
Remove revoked keys and update these references in the same change. The fetcher
does not auto-import keys announced by an untrusted repository or Koji listing.

Fedora uses Koji's [signed RPM copies](https://koji.readthedocs.io/en/latest/signing.html), not
the unsigned build artifacts. The verifier checks the signed immutable header and
the compressed payload's SHA256 from that header, following RPM's
[signature coverage](https://rpm-software-management.github.io/rpm/manual/signatures_digests.html)
and [header format](https://rpm-software-management.github.io/rpm/manual/format_header.html).
Unsupported or ambiguous formats fail closed.
