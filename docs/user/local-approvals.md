# Require a separate root approval

An administrator can set `local_roles: owner_only` in the root-owned system file
`/etc/tego/config.yaml`. This mode needs a root launcher in the initial user
namespace and a verified non-root agent, with enforcement and recording enabled and setuid
disabled. Root/kernel qualification for this slice is **owed in a guest**.
The existing system file and placement trust checks apply.

The floor binds only runs launched after it is set. It is fixed per run at launch: a run already live, whatever its
version, keeps same-user approvals until it ends, because the broker of a personal run never reads the system file
again. Stop every live run before relying on the floor, then start them again. `tego doctor` lists the live runs of the
selected ledger root that started without the floor.

Beyond that, the mount-identity refusal (v0.1.3) is assumed for every run: each live run must have been started by
v0.1.3 or later. Stop and restart older runs first. Activation does not check live-run versions.
A known run records its launcher version in `run_start.tego_version`, but there
is no complete host-wide inventory across configurable per-user and
`TEGO_CONFIG` ledger roots. Inspecting the selected root cannot establish that
no older run remains. A mount made by host root after the run-start compile snapshot is outside
this claim; backend preparation does not independently recheck mounts. Host
root is the owner.

Compile and run start refuse write and ask grants that reach a cgroup filesystem
by mount identity, including another name supplied by a bind mount, a mount
beneath a granted folder, a v1 controller and a symlink to an alias. This
v0.1.3 release protection supplies the membership premise for the approval
floor. Its regression over synthetic mount tables passes; kernel execution is
**owed in a guest**.

User config and `TEGO_CONFIG` cannot set or unset this approval floor. The exact
system values are `owner_only` and `off`; `auto`, empty values, other spellings
and non-string values refuse every new launch until corrected. An unreadable or
invalid system file cannot enable personal approval as a fallback. An absent
setting on a personal host preserves its existing approval behavior and record
bytes.

An enabled run pins the system file's identity and exact bytes. Removing the
file, replacing its inode, making it unreadable or changing its bytes blocks
both Approve and Deny for that run. Even a comment changes the pinned bytes.
Saving the previous text on a replacement file does not restore the pinned inode.

There are two refusal paths. `tego approve` loads machine configuration strictly
before it contacts the broker. If the system file is unreadable by governed
users, such as mode `0600`, even root receives `[config-untrusted]` and the
system-readability repair instruction. The broker has not seen that approval;
the request remains pending. Repair the trusted system file and placement
first, normally with `sudo chmod 0644 /etc/tego/config.yaml` for a mode-only
mistake. Restoring readability on the original inode with the original bytes
allows another answer while the request still waits. If the repair replaces the
file or changes its bytes, follow the policy-change procedure below.

`tego deny` uses a warning configuration load, so it can report the unreadable
system file as UNKNOWN and still reach the pinned broker when it can resolve
the original ledger. The broker then refuses with "the approval policy file
changed since this run started". The dashboard also uses a warning load. A
valid replacement or byte edit can pass the strict CLI load and receive this
broker refusal too. This cause takes precedence over the root-only instruction
when the pinned policy no longer matches.

For this policy-change refusal, stop the old run as root, then relaunch with
valid configuration and the same ledger selection. For a launcher that uses
the ordinary system and user config:

```sh
sudo "$(command -v tego)" stop <run>
sudo "$(command -v tego)" run /absolute/path/agent.yaml
```

If the launcher selected a machine file with `TEGO_CONFIG`, give both commands that same absolute path in a root
shell, so they select the same ledger. Use the full path of `tego` if root's PATH does not hold it:

```sh
sudo -i
export TEGO_CONFIG=/absolute/path/machine.yaml
tego stop <run>
tego run /absolute/path/agent.yaml
```

Repeat the original launch's flags and command arguments. Run these commands
from the same invoking account, so sudo supplies the same verified non-root
agent identity. A direct root launcher must use its original verified non-root
identity setup again.

The table counts one authority check for the running run and one configuration
load for the next launch.
Each edit leaves a trusted, valid `owner_only` file and changes its bytes. An
inode change is 1 when the save replaces the file and 0 when it writes in place.
The file-operation fixtures cover these outcomes; real tool and root behavior is
**owed in a guest**.

| Save method | Inode change (0/1) | Byte change (0/1) | Running authority checks accepted | Next launch config loads accepted |
| --- | ---: | ---: | ---: | ---: |
| Editor saves by replacing the file | 1 | 1 | 0/1 | 1/1 |
| Editor writes the existing file in place | 0 | 1 | 0/1 | 1/1 |
| `sudo tee /etc/tego/config.yaml` writes in place | 0 | 1 | 0/1 | 1/1 |
| Config-management tool installs a replacement | 1 | 1 | 0/1 | 1/1 |
| Package upgrade installs a rewritten replacement | 1 | 1 | 0/1 | 1/1 |

A config-management tool or package upgrade that writes in place follows the
in-place row. A replacement with identical bytes still refuses the running
run, while an in-place write with identical bytes keeps its authority (1/1).
Restoring the exact original bytes in place also restores that byte check when
the original inode and trusted placement are intact. A next launch refuses if
the resulting file is invalid or untrusted; it uses personal authority only
when the corrected trusted file selects `off` or omits the setting.

Only root may answer once. Run the approval as root from a terminal outside any
governed run. Use the same ledger configuration as the launcher:

```sh
sudo "$(command -v tego)" ask <run>
sudo "$(command -v tego)" approve <run> <ask_id>
# Or refuse the held operation:
sudo "$(command -v tego)" deny <run> <ask_id>
```

The agent's UID cannot answer from its own run, another terminal or a valid
session in its dashboard. Both Approve and Deny need root authority. Always and
alternate answers are unavailable. A refused answer leaves the request waiting
until an authorized once answer, cancellation, shutdown or the original timeout.
Unknown process, namespace, cgroup or real UID facts refuse the answer.
The packet binds send-time identity. Authority is judged from revalidated facts
about that same process at the decision. A process that is root on the host and
outside every governed scope when the answer is decided is the host's root;
where it stood for the moment it sent is not known to the broker and is not
judged. A sender inside a governed scope or private user/cgroup namespace, or
without real UID 0 at the decision, is refused whatever it was earlier. No
change between send and decision can substitute another process. Exec retains
identity; namespaces, cgroup and real UID are re-read, and changed facts refuse.

If a sender exits or cannot be read coherently after its selection was recorded, the still-held
operation is listed under a fresh ask ID at the original deadline. Answer that
new ID. The earlier recorded selection does not establish completion. Timeout never
approves an operation.

The receipt says `local approval authority: root-only` only when the activation
record validates at its exact revision. A root answer names UID 0,
its process identity and the Owner role. It does not name the sudo caller as a
separate person. A system timeout has a system cause. Older answers have no
recorded actor or role; their `by` sentence does not establish one.

Required record validation, writes and file/directory sync must succeed before
approval is released. Failure grants nothing. A recorded approval alone does not
prove completion: cancellation, expiry or authority loss can still refuse it.

Further local roles, shared dashboard reads, protected rule publication,
author independence, amount caps and remote approvers are later slices. This restriction does not make personal contract files or completed
user-owned records tamper resistant. Root remains trusted.
