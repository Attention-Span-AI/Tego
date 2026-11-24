**Sample display. Not a GitHub run; not signed.**

The guest record is real; receipt JSON is reconstructed and compile JSON is hand-made. See testdata/README.md.

<!-- tego-receipt:b7d029a2390ae7680ba7ea557eda6a6f3de51333489804506db8fcef8eef9353 -->
### Incomplete: Tego receipt

Unsigned (`disabled: offline sample, not a GitHub run`): a report, not evidence. This receipt is not signed.

#### What this record does not cover

- A receipt on a pull request is only as honest as the workflow file that made it. On pull_request that file comes from the pull request. Its author can make the comment and summary say anything. Trust reports only from a workflow on a protected branch that you reviewed.
- The runner user, root and unconfined processes can rewrite the record and its anchor. A matching receipt and record do not establish honest execution or authorship.
- Data the agent can read can leave through any allowed host. Remote effects, in-process work and a crash tail can be missing. Coverage does not mean every action was observed.
- Tier `landlock`: `no root. The kernel (Landlock) refuses writes, deletes and program starts outside the contract. Network destinations are decided by Tego's supervisor process, outside the agent, not in the kernel. UDP, command-argument and protected-file rules are best effort. The record of programs, writes and connections is advisory against a hostile process; reads are recorded only with read recording on.`
- Reads: this tier records read activity; tracing can miss lines on kernels that preempt kernel code.
- `tokens`: `not recorded: model traffic capture was off for this run`
- `stall`: `model traffic was not captured, so time spent waiting on the model counts as quiet`

- Best effort: `builtin host ipc/datagram`

The record verified on the runner after the run: `74` lines.

| | |
|---|---|
| Event commit | `0123456789abcdef0123456789abcdef01234567` |
| Agent | `k2-worker` |
| Command | `/usr/bin/python3 -u k2-worker/worker.py` |
| Outcome | `0` |
| Tier | `landlock` |
| Compiled contract hash | `9bc51d9305575273e74713c53bc0150dcf05c630bf8e4e35e28395a110a87abd` (as tego compile prints it) |
| Contract file SHA-256 | `46a84580ed419ee06a66ee49b13305585ca47bc8313b812a8ea8eb93cad5a185` |
| Record | `r-5cd05e60-0dmrm463r69xq-kpyavw`, head `a48c6844922d6ea567be6d901561116d2b79255471b10ef3851464867443f6a8` |
| Receipt bytes | receipt.json, SHA-256 `0650b5e17d88b44edac74b7fba32e6fcec53396da4022b1002eaaf43f859cdee` |
| Tego | `v0.1.1-rc.1-pub.c9186ce` |

This text is a display. Retain receipt.json and run/events.jsonl from the artifact to compare them with the same Tego release. No files or this text carry a CI signature. Artifact retention is finite; save a copy before expiry.

#### What the agent was allowed

Write:
- `k2-worker`
- `/dev/null`
Programs: restricted
- `/usr/bin/python3`
Network: no host

Variables passed:
- `PATH`
- `HOME`
- `LANG`
Reads refused:
- `k2-secret.txt`
Built-in read refusals are in compile.json; this display does not count them.

Additional command grant (outside the compiled hash): `none recorded`.
Runtime grants added after compile:
None recorded.

#### What it did

| Programs started | Files written | Created | Deleted | Renamed | Connection tries | Asked a person |
|---|---|---|---|---|---|---|
| 1 | 1 | 0 | 0 | 0 | 0 | 0 |
- Wrote `k2-worker/result.json`



- `/usr/bin/python3` count `1`


#### Refused actions

Recorded refusals: `1`.
- `fs.deny_read[~/k2-secret.txt]` (`read-denied`) count `1`
| Time (UTC) | Operation | Target | Rule |
|---|---|---|---|
| `14:49:05` | `open` | `k2-secret.txt` | `fs.deny_read[~/k2-secret.txt]` |
Protected or secret-looking files opened or tried (at most 10):
- `k2-secret.txt` (refused `1`, allowed `0`)

Capabilities this run did not have:
- `ask`
- `capture model traffic`
- `containers adopted`
- `nested container isolation`
- `exec command argv`
- `fs deny chmod`
- `fs deny read created later`
- `fs deny read moved`
- `fs deny read nested`
- `fs protected write targets`
- `gate exec completion`
- `gate fs mutation completion`
- `gate fs open completion`
- `net host sockets refused`
- `net http rules`
- `net tcp destination kernel`
- `net udp by destination`
- `net udp by port kernel`
- `net unix abstract scope`
- `net unix destination kernel`

There is no model inside Tego. The artifact also holds compile.json and the on-runner chain check.
