# Measured distribution layouts

The JSON inventories describe synthetic unit trees shaped from public
installation images. The `content/` trees separately retain original unit
contents. Tests read only committed fixtures, never host settings or unit folders. The inventory files retain paths,
entry types, alias destinations and each physical line's length. They contain no
unit file values. `TestMeasuredStockUnitLayouts` reconstructs those line lengths
as comments, adds harmless service and timer directives, and uses the production
four-root ordering with fixture equivalents of the two machine roots. It also
includes a quote in the middle of a word and thirteen harmless arguments.

The acceptance test checks every selected main source, including aliases, has a
read row; every reported E source was read; no agent was found; verbose output
contains no "could not be read"; and `--check` is `none-observed`, exit 0. Shadowed
main files and drop-ins for unit types other than service and timer are outside
that selected-source claim. The inventories include these names for accurate
root listing and directory budget pressure.

The shape fixtures test measured layout capacity and the listed parser cases.
`TestStockUnitContentCompatibility` separately parses every original file and
collects the three image trees and the host distribution tree. IBus shell
wrappers and environment expansion, and some Fedora Podman commands, receive
an unresolved classification. Live systemd behavior is owed in a guest.

## Provenance

Measured on 2026-11-12 from these public x86-64 image files, using HTTP byte ranges
and read-only image tools. No image was mounted or booted and no image program
was run. Sparse scratch copies contained only the requested metadata and file
blocks. The measurements cover `/usr/lib/systemd/user` and `/etc/systemd/user`.

- [Ubuntu 24.04.4 desktop](https://releases.ubuntu.com/24.04/ubuntu-24.04.4-desktop-amd64.iso):
  the `casper/minimal.squashfs` layer used by the default desktop installation.
  ISO extent starts at byte 96,190,464; SquashFS inode metadata starts at image
  byte 1,803,316,021. Requested 2,500,994 bytes in total. Optional installation
  layers and packages are outside this measurement.
- [Fedora 44 Workstation 1.7](https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Workstation/x86_64/iso/Fedora-Workstation-Live-44-1.7.x86_64.iso):
  `LiveOS/squashfs.img` is EROFS despite its filename. ISO extent starts at byte
  332,634,112. Requested 23,928,832 bytes of inode, directory and unit data blocks.
- [Debian 13.7 GNOME live](https://cdimage.debian.org/debian-cd/13.7.0-live/amd64/iso-hybrid/debian-live-13.7.0-amd64-gnome.iso):
  `live/filesystem.squashfs`. ISO extent starts at byte 134,283,264; SquashFS inode
  metadata starts at image byte 3,031,956,410. Requested 4,971,936 bytes in total.

The image metadata was read with ISO9660 directory records, `unsquashfs
-processors 1`, and `dump.erofs --ls/--cat`. Counts were computed with `os.walk`,
`lstat`, line splitting and byte lengths over those two extracted public roots.
The files store the measurement so the acceptance test is fully offline. The
full ISO files were not downloaded or their complete checksums verified.

| Distribution | root | names | service/timer names | aliases | drop-in folders | folders incl. root | all entries |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Ubuntu 24.04.4 | `/usr/lib` | 167 | 89 | 0 | 5 | 13 | 183 |
| Ubuntu 24.04.4 | `/etc` | 11 | 5 | 1 | 0 | 7 | 35 |
| Fedora 44 | `/usr/lib` | 221 | 109 | 3 | 41 | 48 | 272 |
| Fedora 44 | `/etc` | 8 | 3 | 3 | 0 | 6 | 16 |
| Debian 13.7 | `/usr/lib` | 159 | 85 | 1 | 5 | 12 | 172 |
| Debian 13.7 | `/etc` | 6 | 1 | 1 | 0 | 6 | 30 |

Service/timer names include aliases and shadowed names across roots. All entries
include root listings and their child directory entries. Root-level alias chains
have at most one hop. Wants links are metadata only, as in the collector.

| Distribution | longest physical/logical line | largest file | largest lines plus ExecStart words per file | most ExecStart words | most ExecStart lines | root file bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Ubuntu 24.04.4 | 162 | 1,545 | 42 | 14 | 1 | 68,137 |
| Fedora 44 | 136 | 1,826 | 63 | 14 | 1 | 77,247 |
| Debian 13.7 | 200 | 1,545 | 42 | 14 | 1 | 65,826 |

The word count uses whitespace splitting as a conservative upper bound on
systemd words. Thirteen is therefore an upper bound on arguments in these files.

## Bounds

Each unit input cap has at least tenfold headroom over the largest measured
corresponding value. The fixture test checks the relationship to its inventories.
The command retains its existing aggregate output budgets and deadline.

| Input | measured maximum | cap |
| --- | ---: | ---: |
| names in a unit directory | 221 | 4,096 |
| directories across the selected machine roots | 54 | 1,024 |
| entries across those roots | 288 | 4,096 |
| D/E read attempts: units, all drop-in files and six settings | 159 | 2,048 |
| alias chain | 1 | 16 hops |
| physical/logical line bytes | 200 | 8,192 (B2-3 system content headroom) |
| lines plus command words per file | 63 | 4,096 |
| arguments in one command | 13 | 256 |
| ExecStart directives per file | 1 | 128 |
| bytes in one file | 1,826 | 1 MiB |
| unit root file bytes | 77,247 | 6 MiB shared D/E bytes |

Only directories present in a root's pinned listing are opened for drop-ins.
Missing directory probes consume no directory or entry allowance. The aggregate
4,096 entry cap includes overflow lookahead and raw names from failed or
rejected listings. Each listing attempt spends at least one slot; no enumeration
starts after exhaustion. A directory that fills the remaining allowance is
refused, so at most 4,095 names can be accepted from one directory. The 4,096
combined physical-line/ExecStart-word cap applies to every line, including
comments after the last command. The shared
D/E read cap includes the six fixed MCP configuration sources and, conservatively, every measured
drop-in file, leaving over tenfold headroom. The largest conservative count is
112 unit names plus 41 drop-in files plus six settings, or 159 attempts.
Logical line lengths were also measured across original files by joining odd
trailing-backslash continuations and ignoring comment lines during continuation;
the largest logical and physical lengths are equal in each inventory.

Alias handling follows [systemd.unit](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html):
an alias destination within the selected load path contributes its basename;
that name is resolved again through root precedence. The destination path may
be dangling. Links leaving those roots are reported and never followed. Alias
names must have compatible types and instance names. As in systemd v257 and
v260 `unit_ids_map_get` (`FOLLOW_MAX = 8`), a loadable name can have at most
seven alias links before its final regular file. Longer chains are unresolved;
this semantic rule is separate from the sixteen-hop resource allowance.
Links and root listings
are checked again before any unit evidence is accepted.

Drop-in ordering follows `unit_file_find_dropin_paths` and `unit_file_find_dirs`
in systemd [v257](https://github.com/systemd/systemd/blob/v257/src/shared/dropin.c#L246)
and [v260](https://github.com/systemd/systemd/blob/v260/src/shared/dropin.c#L240):
within each root, exact, template and dash-prefix directories precede the next
root; type-wide `service.d` and `timer.d` follow all unit-name directories.
Canonical-name drop-ins precede alias-name drop-ins. Different filenames merge
lexically. Same-name alias drop-ins are visited in sorted alias-name order by
this scanner; live parity for competing aliases is owed in a guest.


## Original content compatibility

`content/ubuntu-24.04.4-desktop`, `content/fedora-44-workstation` and
`content/debian-13.7-gnome` retain the complete regular files from the same
public-image extraction described above. They are not reconstructed from line
lengths. Their original bytes, including every `ExecStart=`, other `Exec*=`
directive, comment and continuation, are unchanged. No directive was replaced. The scoped `content/.gitattributes` whitespace
exceptions preserve original trailing spaces and final blank lines in copied
units and licence texts; manifests and repository code keep ordinary checks.
Each manifest records file SHA-256 values and the original directory and
symlink metadata. Tests recreate links inside a temporary tree and rebase
absolute distribution-root targets there. No fixture link is followed into the
host. The regular-file counts are 164, 212 and 152 respectively.

`content/ubuntu-25.10-host` adds 172 unchanged regular files copied on
2026-11-12 from this host's distribution roots `/usr/lib/systemd/user` and
`/etc/systemd/user`. `/etc/os-release` identifies Ubuntu 25.10 (Questing
Quokka). These are distribution files, including distribution-installed Snap
unit files. No unit or settings file beneath a person's home was read.
The source machine is not the Ubuntu 24.04.4 image and the fixture makes no
claim that the installations are equivalent.

`TestStockUnitContentCompatibility` verifies every regular-file hash and
parses every original file, including shadowed files and unit types the
collector does not select. It permits only a successful parse or the explicit
`unresolved` classification. It then runs collection using the production
four-root ordering. Every reported E source must be read or explicitly
unresolved; both normal and verbose output must contain no "could not be read"
warning. Each unresolved source must remain named, the snapshot must be
partial, and no negative summary may appear. The process-only check must remain
`none-observed`, exit 0. The original files contain no catalog agent match.
The shape fixtures remain in place to check capacity independently.

The collected unresolved-source counts are two for each Ubuntu tree and Debian,
and five for Fedora. The IBus GNOME and generic units occur in all four trees.
Fedora also has unresolved `podman-restart.service`,
`podman-user-wait-network-online.service` and `podman.service` commands.

### Documented upstream examples

`content/upstream` provides independently documented upstream content for
commands present in the Debian and Fedora image trees, checked by
`TestDocumentedUpstreamUnitContent`. These examples are marked as upstream
sources, not as exact distribution package copies:

- [IBus 1.5.32 GNOME service](https://github.com/ibus/ibus/blob/1.5.32/bus/services/org.freedesktop.IBus.session.GNOME.service.in):
  configure substitution `@bindir@` is `/usr/bin`; no other text is replaced.
  Its shell command must be unresolved.
- [PipeWire 1.4.7 service](https://github.com/PipeWire/pipewire/blob/1.4.7/src/daemon/systemd/user/pipewire.service.in):
  configure substitutions are `@PW_BINARY@` = `/usr/bin/pipewire` and
  `@PW_SERVICE_REQS@` = empty. No other text is replaced.
- systemd v257 [user cleanup service](https://github.com/systemd/systemd/blob/v257/units/user/systemd-tmpfiles-clean.service)
  and [timer](https://github.com/systemd/systemd/blob/v257/units/user/systemd-tmpfiles-clean.timer):
  the upstream bytes are unchanged.

### Fixture licences and notices

These third-party configuration fixtures retain their own terms; the repository's
Apache licence does not replace them. Original licence and copyright headers are
preserved. `content/licenses/` retains the installed source-package copyright
notices for the host packages that provide the corresponding units, including
GNOME, systemd, IBus, PipeWire, Snap and the desktop portal projects. It also
contains the GNU, Apache and other common licence texts those notices reference,
and upstream notices for additional Fedora components:

- [dbus-broker v37 LICENSE](https://github.com/bus1/dbus-broker/blob/v37/LICENSE)
- [Flatpak 1.16.1 COPYING](https://github.com/flatpak/flatpak/blob/1.16.1/COPYING)
- [GSSProxy COPYING](https://github.com/gssapi/gssproxy/blob/main/COPYING)
- [p11-kit 0.25.5 COPYING](https://github.com/p11-glue/p11-kit/blob/0.25.5/COPYING)
- [Podman 5.4.2 LICENSE](https://github.com/containers/podman/blob/v5.4.2/LICENSE)
- [uresourced COPYING](https://gitlab.freedesktop.org/benzea/uresourced/-/blob/master/COPYING)
- [IBus 1.5.32 COPYING](https://github.com/ibus/ibus/blob/1.5.32/COPYING)
- [PipeWire 1.4.7 COPYING](https://github.com/PipeWire/pipewire/blob/1.4.7/COPYING)

`scripts/check-licenses.sh` checks linked Go dependencies and files embedded in
shipped binaries. These testdata files are neither linked nor embedded, so that
check does not refuse their original content or require adding them to the
binary notices. Their fixture notices are kept alongside them for source
redistribution. The copied notices describe their source packages; they are
not a claim that the host and image package versions match.
