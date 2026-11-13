# Chroot and private-namespace mount tables

Captured on 2026-11-12 as root in an Ubuntu 24.04 guest, kernel 6.8.0-147-generic, util-linux 2.39.3, systemd 255.4
(systemd-nspawn), bubblewrap 0.9.0, busybox 1.36.1 (static, the only program in each small root tree). Each file is
`/proc/self/mountinfo` as the process inside reads it (for the two chroot-directory tables, `/proc/<pid>/mountinfo`
read from outside gave the same bytes). Bytes are kept except one public-data substitution of equal length:
`/home/tester` -> `/home/runner` (the guest account). The project folder bound into each layout is
`/home/runner/proj`; the test moves that mount point to the contract's own folder and keeps every other byte.

| File | Layout |
| --- | --- |
| `chroot-dir` | `chroot /srv/a`, where `/srv/a` is a plain folder (not a mount point), with the mounts a build chroot usually has: proc, `--rbind` of `/sys` and `/dev`, a tmpfs at `/tmp`, the project bound in. The kernel lists only mounts under the chroot, relative to it; no row is at `/`, and the top rows' parent (the host's root mount) is not listed. |
| `chroot-dir-proc-only` | the same folder with only proc mounted: one row. |
| `chroot-selfbind` | as `chroot-dir`, after `mount --bind /srv/b /srv/b`: the chroot's root is a mount point, so it is listed at `/` with root `/srv/b`. |
| `chroot-own-fs` | as `chroot-dir`, with `/srv/b2` its own ext4 filesystem (a loop image). |
| `pivot-root` | `unshare -m`, a bind of the folder onto itself, `pivot_root . old`, `umount -l /old` (as runc does). |
| `nspawn` | `systemd-nspawn -D /srv/d --as-pid2 --bind=/home/runner/proj:/home/runner/proj`. Three rows have a root field ending in `//deleted` (nspawn binds deleted files over `/proc/sys/kernel/random/boot_id` and `/proc/kmsg`): the kernel's spelling of a dentry that was unlinked. |
| `bwrap` | `bwrap --ro-bind /usr /usr` with symlinks for `/bin`, `/lib`, `/lib64`, `/sbin`, `--proc /proc --dev /dev --tmpfs /tmp --bind` of the project: a tmpfs root listed at `/` with root `/newroot`. |

A `systemd-nspawn` run on a folder that is itself a mount point gave the same shape as `nspawn`.
