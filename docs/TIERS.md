# Tiers

Tego enforces a contract at one of three tiers. All three are in the binary that `make build` makes. `tego doctor` says which
one your machine gets, `tego run --tier <name>` pins one, and every run records the tier it had (`run_start.tier`).
The per-tier capability table is [spec/backend/CAPABILITIES.md](../spec/backend/CAPABILITIES.md).

| | Tier 1, `landlock` | Tier 2, `cgroup` | Tier 3, `bpflsm` |
|---|---|---|---|
| Mechanism | Landlock and a seccomp supervisor | BPF programs attached to the run's cgroup, and fanotify | The kernel decision plane in LSM mode, on top of tier 2 |
| Root | No | Yes: `sudo tego run`. The launcher is root for the whole run | Yes |
| Kernel | Landlock ABI 2 or newer (Linux 5.19 or later, or a backport such as RHEL 9's 5.14), with cgroup v2 and a subtree delegated to your user. The oldest kernels tested are 6.1 and RHEL 9's 5.14 | Landlock ABI 2 or newer, BPF, BTF and cgroup v2; no boot change | As tier 2, plus `bpf` in the boot LSM list |
| Works out of the box on | Any Linux 6.1 or later from a desktop login, Ubuntu 24.04 included, and RHEL 9. Not Ubuntu 22.04's stock 5.15, which has Landlock ABI 1. Over SSH, see [INSTALL.md](INSTALL.md#check-the-machine) | Any such host, with root | Debian 13, Fedora, RHEL 9 and 10, Amazon Linux 2023. Ubuntu after one boot line (below). Not stock WSL2 |
| Held file reads (`fs.ask_read`) | Yes | Refused when the contract is compiled | Refused when the contract is compiled |
| Record of file reads | Not recorded under `record: summary`, the default: a read that `deny_read` refuses is still refused, and leaves no line. `record: full` records reads and slows every open | Recorded by eBPF | Recorded by eBPF |
| Live Adjustable mode | No | Yes | Yes |
| On a hosted CI runner | Yes: this is the CI mode | Yes, through `sudo`, on `ubuntu-24.04` | No: a hosted runner cannot change the kernel command line |

More rule kinds need a newer kernel at tier 1: TCP port rules need Landlock ABI 4 (Linux 6.7, or Red Hat's RHEL 9
backport), and further rules arrive at ABIs 6, 7, 9 and 10 ([GAPS.md](GAPS.md) B5). `tego doctor` prints your ABI.

## Choosing

- **No root, or you are not sure:** tier 1. It enforces files, programs and network rules, some of them in Tego's supervisor and
  not in the kernel ([spec/backend/CAPABILITIES.md](../spec/backend/CAPABILITIES.md) says which), and records exec, write and
  connect, not reads.
- **You can use `sudo` and want reads recorded:** tier 2.
- **You also want the decision plane to run as LSM hooks:** tier 3.

Granting `sudo` for `tego` is granting root. The root tiers are for machines whose `sudo` users are already their
administrators ([OPERATIONS.md](OPERATIONS.md), "Privileged path"). `tego-control`, which runs the dashboard, never runs as root.

## Tier 3 on Ubuntu

`bpf` is not in the boot LSM list on Ubuntu 24.04, 25.10 or 26.04, or on the stock WSL2 kernel. On Ubuntu this is one change
to the kernel command line:

1. Run `sudo "$(command -v tego)" doctor`. Its `lsm` line prints the line to use, built from the list your machine runs now,
   so no other security module is dropped.
2. Put that `lsm=...` into `GRUB_CMDLINE_LINUX_DEFAULT` in `/etc/default/grub`, run `sudo update-grub`, and reboot.
3. Check: `cat /sys/kernel/security/lsm` lists `bpf`, and `sudo "$(command -v tego)" doctor` ends its table with `tier: bpflsm`.

On an Ubuntu cloud image step 2 has no effect: `/etc/default/grub.d/50-cloudimg-settings.cfg` sets the same variable after
`/etc/default/grub` is read. Add a file that is read later instead, with the list `doctor` printed, then run `sudo update-grub`
and reboot:

```sh
echo 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT lsm=<the list doctor printed>"' | sudo tee /etc/default/grub.d/99-tego-lsm.cfg
```

Do not copy an `lsm=` line from somewhere else: it replaces the whole list. Without `bpf` in the list, `tego run --tier bpflsm`
is refused and never runs at another tier. On Fedora and the RHEL family, `grubby --update-kernel=ALL --args="lsm=..."` does
the same job.

At tier 2 without `bpf` in the list, the decision plane loads as `fmod_ret` hooks where the kernel allows it, and the kernel
decides opens, execs and file changes. `tego doctor` says which mode you are in. [OPERATIONS.md](OPERATIONS.md) ("Tier 3 and the
decision plane") describes the residual.

## What the tiers do not change

The tier does not change what Tego cannot do: an allowed destination is an open channel, an allowed interpreter can do
anything in its own memory, and the record is tamper-evident against an agent held by a contract, not against you, and not
against an agent in a record-only run. Those are in [GAPS.md](GAPS.md) (A1, A2, C9). Tier 3 decides only what happens inside a run's cgroup and only what the contract names.
