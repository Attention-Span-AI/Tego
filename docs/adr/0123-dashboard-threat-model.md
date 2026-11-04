# ADR 0123: Who may change governance from the dashboard

Status: **accepted 2026-10-27**; built; the one-time open code was built later the same day (see "What this does not cover").

## Context

`tego-control serve` can now change what a running agent may do: answer its asks, stop it, place and lift live
blocks, widen or narrow its contract, undo a change. That makes it a target. Three questions had the answer "yes"
before this record:

- Can a form post widen the contract without the person seeing it? The old Rule page's `POST /rule` wrote a widening
  with no acknowledgement and on no previewed base; every other write took the acknowledgement as a boolean
  (`ackwiden=1`), so a post with a valid form token and base could carry a wider change than the one previewed.
- Can the watched agent approve its own asks? Every agent tego runs or watches is the serving user. The peer check
  (`peer.go`) refuses other uids only; the sign-in token sits in the browser opener's command line, which the
  agent can read; with it the agent signs in, reads a form token and posts.
- Can a rule from one event hand out a system folder? A write to `/dev/null` previewed `fs.write += /dev/`.

## Decision

1. **`POST /rule` is retired.** It answers 410 Gone with a link to the line's page and writes nothing. `GET /rule`
   keeps redirecting to the event page. Every rule is made on the event page or on Change rules, through the rule
   service (`internal/control/rules`).
2. **No folder-level Allow of a write outside the run's folder and home.** `internal/check/rule` refuses it with "the
   folder of X is a system folder: name the file"; Allow of the file itself stays; Block and Ask keep the folder (they
   only take away). An Allow of a read grants nothing new: it only lifts an entry the file spells at exactly that
   folder (the planner's `narrow`), which the person wrote, so it keeps its folder.
3. **The acknowledgement is bound to the preview.** The rule service holds a 32-byte key made at start that never
   leaves the process. Every plan (the event page's preview, a Change rules preview, a free edit's Check, each Undo
   History and the event page offer) carries `Ack = HMAC-SHA256(key, "tego-ack-v1" | ref | base | sha256(new text))`,
   each field length-prefixed. The ref names the change's kind and target (`line:<run>#<seq>`, `contract:<ref>`,
   `revert:<journal id>`). The checkbox posts the Ack as its value. A write that is not a narrowing plans again on the
   file as it is and writes nothing unless the posted Ack is the one that plan computes (constant-time compare):
   `ErrNeedsAck` when none was posted, `ErrAckMismatch` when another was. A narrowing needs none, so a Never
   allow is unchanged. The Ack has no nonce and no clock: two renders of one preview are byte-identical, so a live
   region's hash does not churn under the presenter's cursor. A free edit's Save appears only after a Check that
   compiled; a text changed after its Check is checked again.
4. **A governed agent cannot post.** For every POST and for the `?t=` sign-in, the dashboard asks the kernel which
   cgroup the client's socket was made in (`internal/platform/peer` `TCPSocketCgroup`: a `SOCK_DIAG_BY_FAMILY` lookup
   of the exact 4-tuple, whose answer carries `INET_DIAG_CGROUP_ID`), finds the cgroup directory with that inode by a
   walk of the whole cgroup2 hierarchy, and asks `runscope.GovernedBy` whether its path is a run's cgroup or below
   one (`tego.slice/tego-<agent>.slice/{run,adopt}-<id>.scope` at the cgroup2 root or under a user manager, Docker's
   `tego/<agent>/<id>`). A match is 403 "a governed agent cannot change its own governance (run <id>)", which tells
   the person to open the dashboard from a terminal outside any tego run. A socket that cannot be found, no cgroup2
   mount, or a cgroup id the walk does not find refuses the change (fails closed): a cgroup removed after the socket
   was made in it (a child of a run's own scope included), one outside this process's view of the hierarchy, or one
   past a part of the tree the walk could not read or passed over for its bounds (65536 cgroups, 32 deep). Only a
   cgroup found, and found outside every run, lets a change in, and that verdict is remembered by id: cgroup v2 has
   no rename and kernfs does not reuse ids, so it cannot go stale, and the browser's later requests walk nothing.
   GETs are answered: reading is not governance. A kernel that answers no TCP socket lookup at all (`inet_diag` and
   `tcp_diag` modules not loaded and not loadable on demand) answers the lookup ENOENT, as for a closed socket; an
   empty dump of the family tells the two apart, and that refusal names the modules (`peer.ErrNoTCPDiag`; *amended
   2026-10-27*: the root suites' guests, which have no modprobe, refused every sign-in "no socket for the tuple").
5. **The CLI writers refuse a caller inside a run.** `tego unblock` and a `tego rule` write that is not a narrowing
   refuse when `runscope.InRun` says this process sits inside a run's cgroup (or cannot tell: outside the initial
   cgroup namespace it fails closed, so inside a container with a private cgroup namespace, Docker's default on
   cgroup v2, both refuse), with the same sentence and `[governed]`. `tego block` and narrowings stay open:
   they only take away. `runact.SelfGoverned` (with `runact.ErrGoverned`) is the same answer for the dashboard's
   own writers; this change adds it and calls it nowhere yet: `runact.Block`'s unblock and a later resume
   are to refuse with it (`tego pause`, `tego resume` and `runact.Pause` refuse a caller inside a run
   both ways, since a pause stops a run's work and a resume restarts it; a same-uid process outside every run can
   still write the run's `cgroup.freeze` itself). `tego approve` and `tego deny` were already refused by `ask.sock`'s peer check
   (`internal/platform/peer`, `run-member`).

## Why the socket's cgroup and not its holder

The spec first asked for a scan of the run's processes' `/proc/<pid>/fd` for the client's socket inode. That misses
every non-dumpable process (`prctl(PR_SET_DUMPABLE, 0)`, which hardened agent CLIs set on themselves): `/proc`
hides their descriptors from their own uid. Failing closed on such a process would refuse every dashboard button
while such an agent runs, and skipping it would let exactly the processes that hide pass. The cgroup a socket was
made in is the kernel's record (`sk_cgrp_data`, set at creation from the creating task's cgroup and never moved), no
process can hide it, and the lookup is one hash probe with no caps to race. The id is the inode of the cgroup's
directory, checked against `stat` in `TestTCPSocketCgroupIsTheMakersCgroup`.

## What this does not cover

- **A process of the serving user outside every run is out of scope.** It can drive the person's browser or read
  the terminal that printed the sign-in link, sign in and post exactly as the person does. It can also write a run's
  `live-block.json`, a contract, or a run cgroup's `cgroup.freeze` directly. The dashboard is no boundary against the
  user who owns it; the peer check stops other users only.
- **An agent that left its run's cgroup** before it made the socket (an unconfined watched agent can start
  `systemd-run --user --scope …`, or write its pid into another cgroup of the user's delegated subtree) is outside
  this check, as it is outside every cgroup-based one. A Landlock-enforced run is held to its contract besides.
  The dashboard's walk refuses an id it cannot find, so a socket made in a cgroup that was removed afterwards (a
  child of the run's own scope included) is refused; making one needs write access to the run's cgroup subtree,
  which only an unconfined agent has, and that agent can leave the run outright.
- **The acknowledgement binds the write to the preview; it does not stop a same-user process** that can fetch the
  preview and read its Ack. It stops a post that changes the edit after the person looked.
- **The one-time open code is built.** `--open` gives the opener `?o=<32 hex>`, which signs
  in once within 60 s and is then burned (`web/opencode.go`); the reusable `?t=` link is printed on stdout only. A
  process that reads the opener's or the browser's command line finds a dead code. It does not change the line
  above: a same-user process can still drive the browser or read the terminal, and a `?t=` link the person pastes
  into a command line is readable there. A governed agent may not sign in with either (the same cgroup check).
- **A kernel without `INET_DIAG_CGROUP_ID`** (before Linux 5.10, or built without `CONFIG_SOCK_CGROUP_DATA`) refuses
  every dashboard change (fail closed); the terminal commands still work.

## Consequences

- A browser started from a terminal that is itself under `tego run` or `tego watch` can look but not press a button;
  the 403 says why.
- Every widening form posts `ack=<hex>` instead of `ackwiden=1`/`ackfree=1`; `TestNoBooleanAckInTemplates` holds the
  templates to it. A dashboard restart makes a new key, so a preview left open across a restart asks again.


Amended 2026-11-03 (dashboard correctness M3/M4/M8): a watched run may borrow a
contract reference only from the same recorded workspace and nonempty agent
identity, with the same harness and program. Missing identity preserves its warning.
Leak descriptions must associate particular successful reads with particular
successful outbound events; run-wide counts cannot establish those associations.
Time/sequence proximity remains a heuristic, not proof of transferred content.
Browser region refreshes distinguish received from rendered revisions and retry
failures with bounded backoff even while a run is quiet awaiting approval. These
read-side corrections make no change to the authority/process model in ADR 0100.

The standalone learner uses the same successful-pair condition (M8), with a bounded
recent-send fold and capped associations. A confirmed witness preserves each
withheld destination if the detailed association list fills; incomplete names are
reported. It cannot borrow the dashboard's contract reference.
