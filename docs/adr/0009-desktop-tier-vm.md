# ADR 0009: macOS and Windows run the Linux engine in a VM

Status: accepted 2026-09-21; not built. No native macOS or Windows `tego` exists: the shipped path is to install Tego inside a Linux VM yourself (docs/INSTALL.md).
Decision: the engine stays Linux-only. On macOS, `tego` starts a small Linux VM (lima with the Apple Virtualization backend, an image whose kernel has `bpf` in the LSM list and BTF) with the project mounted by virtiofs; on Windows, WSL2 (unprivileged tier on the stock kernel, hardened tier with a custom kernel via `.wslconfig`). The native CLI proxies `run`, `status`, `approve`, `stop` to the engine inside; same binary, contract and ledger.
Why: it is the Docker Desktop model developers already accept; one engine to test; kernel facts stay uniform.
Consequence: agents that need macOS-native tools run outside the VM and are enforce-only via a later Seatbelt backend (I11b); inode-ancestry rules depend on the VM mount preserving stable inodes, which the verification pass checks for virtiofs.

Amended 2026-09-21: no purpose-built kernel is needed anywhere. macOS: Lima's Fedora template already lists `bpf` and `landlock` and ships BTF; Ubuntu images need one GRUB drop-in written by a `provision` script. Windows: the stock WSL2 kernel has `CONFIG_BPF_LSM=y`, Landlock and BTF; the hardened tier needs one `.wslconfig` line (`kernelCommandLine = lsm=<current list>,bpf`) and `wsl --shutdown`. `compile` and inode resolution run inside the VM, and `doctor` runs a mount-identity check on the virtiofs mount before enforcing on it.
