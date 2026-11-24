// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#ifndef TEGO_DECIDE_IMPORT_H
#define TEGO_DECIDE_IMPORT_H

/* ADR 0128 (amended): the descriptor-import guard of net.assurance: kernel, in the plane. A descriptor or a pidfd
 * reaches a task only through a receive's control buffer: scm_recv installs SCM_RIGHTS and SCM_PIDFD only when the
 * msghdr has one, and with none it drops the passed files and sets MSG_CTRUNC. security_socket_recvmsg runs in
 * sock_recvmsg before the protocol's receive, on the kernel's own copy of the msghdr (copy_msghdr_from_user ran
 * first), so no sibling thread can change msg_controllen between this test and the receive. A receive with no
 * control buffer is admitted exactly as recvfrom(2) and read(2) already are, which reach this hook with none.
 *
 * The run is the receiving task's, as the other plane hooks that act for the caller take it. Only a slot whose
 * header carries TEGO_SLOT_IMPORTS_DENIED (the run's net.assurance is kernel) decides; a control-bearing receive of a
 * run whose slot has no header refuses (fail closed, as socket_create does). The run's open deputy, named in the
 * header by the launcher, is passed (tego_is_deputy). The refusal is the plane's own sample,
 * rule TEGO_PLANE_RULE_SOCKET_IMPORT, which the ledger names socket-import.
 *
 * Only an AF_UNIX socket can pass a descriptor or a pidfd: SCM_RIGHTS and SCM_PIDFD exist nowhere else. A control
 * receive on any other family (an IP_PKTINFO, a timestamp, a TOS, a GRO size, a RECVERR) imports nothing, so it passes
 * with no ledger line, as it passed before this hook existed. A socket with no sk is not known to be another family
 * and is decided like a unix one. */
/* USER_HZ's nanoseconds: the unit of /proc/<pid>/stat's start time (nsec_to_clock_t of the task's start_boottime), in
 * which the launcher writes the deputy's (tego_plane_slot.deputy_start). USER_HZ is 100 on every architecture the plane
 * runs on, and its ABI. */
#define TEGO_NSEC_PER_USER_TICK 10000000ULL

/* Whether the receiving task is the run's open deputy (ADR 0128, amended 2026-11-21): its thread-group id in the
 * launcher's pid namespace (the header's pidns_dev and pidns_ino) and its thread-group leader's start time, in the
 * ticks /proc gives it, are the pair the launcher wrote before Arm. Any other task has another thread-group id: a
 * child of the agent, a program that execs the deputy's image, a thread of any other process. The deputy cannot exec
 * or fork (its own filter kills it), so its identity never runs another image or passes to a child, and its zombie is
 * kept for the run, so its pid is not reused within it. A namespace the current task cannot be named in is no match. */
static __always_inline int tego_is_deputy(const struct tego_plane_slot *hdr)
{
    struct bpf_pidns_info ns = {};
    struct task_struct *t;

    if (!hdr->deputy_tgid)
        return 0;
    if (bpf_get_ns_current_pid_tgid(hdr->pidns_dev, hdr->pidns_ino, &ns, sizeof(ns)))
        return 0;
    if (ns.tgid != hdr->deputy_tgid)
        return 0;
    t = bpf_get_current_task_btf();
    return t->group_leader->start_boottime / TEGO_NSEC_PER_USER_TICK == hdr->deputy_start;
}

TEGO_PLANE_HOOK(socket_recvmsg, socket_recvmsg, security_socket_recvmsg,
                 (struct socket *sock, struct msghdr *msg, int size, int flags), (sock, msg, size, flags))
{
    struct tego_run *run = tego_current_run(&tego_run_set);
    const struct tego_plane_slot *hdr;
    struct tego_plane_decision *sc;
    struct tego_plane_sample_args a = {};
    struct sock *sk;

    if (!run)
        return 0;
    if (run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    /* Nothing without a control buffer can install a descriptor. */
    if (!msg->msg_controllen)
        return 0;
    sk = sock->sk;
    if (sk && sk->__sk_common.skc_family != TEGO_AF_UNIX)
        return 0;
    hdr = tego_plane_slot_of(run);
    a.kind = TEGO_EV_PLANE_SOCKET;
    a.hook = TEGO_HOOK_SOCKET_RECVMSG;
    a.rule = TEGO_PLANE_RULE_SOCKET_IMPORT;
    if (sk) {
        a.family = sk->__sk_common.skc_family;
        a.type = sock->type;
        a.protocol = sk->sk_protocol;
    }
    if (!hdr) {
        tego_plane_unslotted(TEGO_HOOK_SOCKET_RECVMSG, (__u64)sock);
        a.reason = TEGO_R_PATH_UNRESOLVED;
        tego_plane_own_sample(run, &a);
        return -EACCES;
    }
    if (!(hdr->flags & TEGO_SLOT_IMPORTS_DENIED))
        return 0;
    /* The run's open deputy takes its request sockets and dirfds this way, and only it is passed. */
    if (tego_is_deputy(hdr))
        return 0;
    sc = tego_plane_scratch_get();
    if (!sc) {
        TEGO_PLANE_COUNT(run->run_idx, unresolved);
        a.reason = TEGO_R_PATH_UNRESOLVED;
        tego_plane_own_sample(run, &a);
        return -EACCES;
    }
    a.reason = TEGO_R_NET_NOT_ALLOWED;
    tego_plane_record(sc, TEGO_HOOK_SOCKET_RECVMSG, (__u64)sock, TEGO_PLANE_RULE_SOCKET_IMPORT, TEGO_R_NET_NOT_ALLOWED);
    tego_plane_own_sample(run, &a);
    return -EACCES;
}

#endif
