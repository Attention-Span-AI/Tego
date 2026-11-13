# Additional namespace captures

These five namespace captures complement `chroot-mountinfo`. They were captured on 2026-11-12. Bytes are kept
with the same equal-length public account substitution as the earlier fixtures: `/home/tester` to `/home/runner`.
The test replaces a project bind's namespace mount point `/home/runner/proj` with each contract's directory; its
filesystem-relative root, device, options, mount IDs and parent IDs stay intact.

| File | Capture |
| --- | --- |
| `bwrap-user-tmpfs` | The user on the host, kernel 6.17, bubblewrap tmpfs root `/newroot`, read-only `/usr`, private proc, dev and tmp, project bind. |
| `bwrap-user-wholeroot` | The user on the same host, bubblewrap `--ro-bind / /`, followed by private proc, dev and tmp. The covered original mounts remain in the capture. |
| `guest-host` | The Ubuntu 24.04 capture guest's own table, kernel 6.8.0-147-generic. It includes the remaining sys and dev binds under `/srv/b`. |
| `unshare` | `unshare -m` in that guest, without changing the process root. |
| `nspawn-selfbind` | `systemd-nspawn -D /srv/d` with `/srv/d` already a mount point, systemd 255.4. The unlinked temporary-file roots remain verbatim, including `//deleted`. |

Capture filenames were `hostbwrap-tmpfsroot-6.17.mountinfo`, `hostbwrap-wholeroot-6.17.mountinfo`,
`guest-host.mountinfo`, `e-unshare.mountinfo` and `d-nspawn-mp.mountinfo`. The guest's attempted user bubblewrap captures
were empty because user-namespace setup failed; those are not fixtures or measurements.

The modeled six-host read-denial fixtures are replayed separately by `TestCompileBuiltinDenyReadHostLayouts` using
their original `mountcompat/cases.json` and tables. That test creates each home and project at the specified relative
place in a temporary tree, retains the Atomic home symlink, places the fixture binary under `usr/local/bin`, and
copies each repository contract with its siblings into that modeled project. No extra bind changes the model's
project or home filesystem. This measures compilation separately from the read-denial startup refusals.
