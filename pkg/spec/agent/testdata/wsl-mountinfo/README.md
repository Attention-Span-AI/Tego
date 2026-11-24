# WSL mount table

`ubuntu-24.04.mountinfo` is the mount table of an ordinary shell in an Ubuntu 24.04 distribution under WSL 2
(kernel 6.18.58.1-microsoft-standard-WSL2), RECONSTRUCTED, not captured: the guest runs of 2026-11-17 to 2026-11-19
recorded `findmnt` rows, not `/proc/self/mountinfo`. The rows it keeps were measured: the distribution's root and
`/mnt/wslg/distro` are the same ext4 device `/dev/sdd` (8:48), the second one read-only, mounted with root `/`
(`findmnt -T /mnt/wslg/distro`; doctor's home alias warning "/home/probe" at "/mnt/wslg/distro/home/probe"); the
Windows drive `/mnt/c` is 9p with `aname=drvfs`; `/usr/lib/wsl/drivers` is 9p; `/run/user/1000` is tmpfs;
`/sys/fs/cgroup` is cgroup2; `/proc/sys/fs/binfmt_misc` is binfmt_misc with a tmpfs over `status`. Mount ids, parent
ids and the device numbers of the other file systems are invented. The guest row `W-E4-ALIAS` now prints the whole
table; replace this file with that capture after the next run.
