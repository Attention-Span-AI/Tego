# Container mount tables

Captured on 2026-11-12 in an Ubuntu 24.04 guest, kernel 6.8.0-147-generic.
The 18 `<name>.mountinfo` runtime tables are in-container `/proc/self/mountinfo`.
They replace the earlier transcriptions. Mount IDs, optional fields, option
order, paths, line endings and lengths are preserved except for these public-data
substitutions (equal byte length and character class):

- `/home/tester` -> `/home/runner` in Podman native tables (plain, `-volume`,
  `-rm`), the FUSE `-volume` table and the native host-side line. This replaces
  a guest account and its home path.
- `layers-vol` -> `sample-vol` in the named-volume roots of Docker and Podman tables.

No personal or project names remain. Hex container, layer and network IDs are
runtime-generated identifiers and are retained. Other names were already neutral.

| File prefix | Runtime and storage |
| --- | --- |
| `docker-small`, `docker-many-layers` | Docker 29.1.3, forced overlay2 |
| `docker-containerd-store` | Docker 29.1.3, default containerd image store, containerd 2.2.1 overlayfs |
| `containerd-ctr` | containerd/ctr 2.2.1, overlayfs snapshotter |
| `podman-rootless-native` | Podman 4.9.3 rootless, native overlay |
| `podman-fuse-overlayfs` | Podman 4.9.3 rootless, fuse-overlayfs 1.13 (FUSE interface 7.31) |

`-volume` adds a host folder bind at `/work/out` and, except for ctr, a named
volume at `/data`. Docker many-layers has 120 RUN layers; `-70` has 70.
The containerd many-layers tables use the 120-layer image. `-rm` captures
Podman's `--rm` option tail (`fsync=volatile`). Native and FUSE stores were fresh
and separate. Docker 29 needs an explicit overlay2 configuration for those rows.

For each runtime, `.hostfull.mountinfo` is the guest's init-namespace table;
`.host.mountinfo` is its rootfs mount line. Rootless Podman's latter line was
read with `podman unshare`, since it is absent from the init namespace. Tests
use the complete init table, not an isolated line as a complete snapshot.

`synthetic-fuse-overlayfs` deliberately covers the alternate `fuse.overlayfs`
spelling, not produced by this Podman. `home-gocryptfs`, `home-ecryptfs`, `home-fuse-nonpath`, and
`overlay-mixed-relative` are synthetic; their `@HOME@`/`@HOST@` tokens are test
placeholders. Their source fields model the eCryptfs lower directory and
gocryptfs's default cipher-directory `fsname`. Podman's captured FUSE source
is `fuse-overlayfs`, a non-path name; synthetic sshfs tests also retain non-path
sources. All encrypted-home source fields remain synthetic until live capture.
Escaped storage paths remain synthetic unit-test coverage.
Tests relocate host-storage prefixes to absent temporary paths and selected
mount points to fixture directories; these are not changes to capture files.
