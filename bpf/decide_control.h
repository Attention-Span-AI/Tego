// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* E54: process-tree ptrace boundary, governed BPF commands and keyring opt-in.
 * The kernel-resolved peer task is authoritative; a userspace PID is never used
 * to locate its run. Read-mode ptrace permission checks are left to the normal
 * chain, as FEATURES E8 requires ATTACH only. */
#define TEGO_PTRACE_MODE_ATTACH 0x02

static __always_inline int tego_control_refuse(struct tego_run *run, __u16 hook,
                                               __u8 reason, __s32 target, __s32 argument)
{
    struct tego_plane_sample_args a = {};
    a.kind = TEGO_EV_PLANE_CONTROL;
    a.hook = hook;
    a.rule = TEGO_PLANE_RULE_NONE;
    a.reason = reason;
    a.family = target;
    a.type = argument;
    tego_plane_own_sample(run, &a);
    return -EACCES;
}

static __always_inline int tego_ptrace_peer(struct tego_run *run, struct task_struct *peer, __u16 hook)
{
    __u64 cg = 0;
    __s32 pid = 0;
    struct tego_run *other;

    if (!peer)
        return tego_control_refuse(run, hook, TEGO_R_PROCESS_SCOPE, 0, 0);
    /* Hook arguments and their RCU cgroup membership remain valid for the
     * program. The default unified hierarchy is the one run_set indexes. */
    cg = peer->cgroups->dfl_cgrp->kn->id;
    pid = peer->tgid;
    other = tego_run_lookup(&tego_run_set, cg);
    if (other && other->run_idx == run->run_idx && other->gen == run->gen)
        return 0;
    return tego_control_refuse(run, hook, TEGO_R_PROCESS_SCOPE, pid, 0);
}

/* ADR 0048 (3) P2, "After the check": a task whose last exec passed a guarded pin is refused to every peer of its run
 * as a ptrace target (ATTACH: PTRACE_ATTACH, SEIZE, process_vm_writev and readv, /proc/<pid>/mem), so its argv,
 * argv[0] included, cannot be rewritten between the check and its main. The sample's type is 1, the guard. */
static __always_inline int tego_ptrace_guarded(struct tego_run *run, struct task_struct *target, __u16 hook)
{
    if (!tego_pin_guarded(run, tego_plane_slot_of(run), target))
        return 0;
    return tego_control_refuse(run, hook, TEGO_R_PROCESS_SCOPE, target->tgid, 1);
}

TEGO_PLANE_HOOK(ptrace_access_check, ptrace_access_check, security_ptrace_access_check,
                 (struct task_struct *child, unsigned int access_mode), (child, access_mode))
{
    struct tego_run *run = tego_current_run(&tego_run_set);
    if (!run || run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    if (!(access_mode & TEGO_PTRACE_MODE_ATTACH))
        return 0;
    if (!tego_plane_slot_of(run))
        return tego_control_refuse(run, TEGO_HOOK_PTRACE_ACCESS_CHECK, TEGO_R_PATH_UNRESOLVED, 0, 0);
    if (tego_ptrace_peer(run, child, TEGO_HOOK_PTRACE_ACCESS_CHECK) ||
        tego_ptrace_guarded(run, child, TEGO_HOOK_PTRACE_ACCESS_CHECK))
        return -EACCES;
    return 0;
}

TEGO_PLANE_HOOK(ptrace_traceme, ptrace_traceme, security_ptrace_traceme,
                 (struct task_struct *parent), (parent))
{
    struct tego_run *run = tego_current_run(&tego_run_set);
    if (!run || run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    if (!tego_plane_slot_of(run))
        return tego_control_refuse(run, TEGO_HOOK_PTRACE_TRACEME, TEGO_R_PATH_UNRESOLVED, 0, 0);
    /* PTRACE_TRACEME makes the caller the target. */
    if (tego_ptrace_peer(run, parent, TEGO_HOOK_PTRACE_TRACEME) ||
        tego_ptrace_guarded(run, bpf_get_current_task_btf(), TEGO_HOOK_PTRACE_TRACEME))
        return -EACCES;
    return 0;
}

/* A prefix of both the 6.1 three-argument and later four-argument hook. */
TEGO_PLANE_HOOK(bpf, bpf, security_bpf, (int cmd, union bpf_attr *attr, unsigned int size), (cmd, attr, size))
{
    struct tego_run *run = tego_current_run(&tego_run_set);
    if (!run || run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    return tego_control_refuse(run, TEGO_HOOK_BPF, TEGO_R_PROCESS_SCOPE, 0, cmd);
}

TEGO_PLANE_HOOK(key_permission, key_permission, security_key_permission,
                 (key_ref_t key_ref, const struct cred *cred, enum key_need_perm need_perm),
                 (key_ref, cred, need_perm))
{
    struct tego_run *run = tego_current_run(&tego_run_set);
    const struct tego_plane_slot *hdr;
    if (!run || run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    hdr = tego_plane_slot_of(run);
    if (!hdr)
        return tego_control_refuse(run, TEGO_HOOK_KEY_PERMISSION, TEGO_R_PATH_UNRESOLVED, 0, need_perm);
    if (hdr->flags & TEGO_SLOT_KEYRING_ALLOWED)
        return 0;
    return tego_control_refuse(run, TEGO_HOOK_KEY_PERMISSION, TEGO_R_READ_DENIED, 0, need_perm);
}

/* ADR 0055 NET09: unlike a launched task, an adopted one has no Landlock
 * domain or seccomp namespace arm. Every topology-changing mount API and
 * mount-namespace install/copy requires CAP_SYS_ADMIN through security_capable,
 * including checks against a newly created user namespace's credentials.
 * Refuse the capability in every user namespace: checking only the initial
 * namespace would leave rootless mounts open. No optional userns_create hook
 * is needed; creating a user namespace alone changes no mount view.
 * This deliberately also refuses non-mount uses of CAP_SYS_ADMIN. */
TEGO_PLANE_HOOK(capable, capable, security_capable,
                 (const struct cred *cred, struct user_namespace *ns, int cap), (cred, ns, cap))
{
    struct tego_run *run = tego_current_run(&tego_run_set);
    if (!run || run->plane != TEGO_PLANE_RUN_MODE(mode))
        return 0;
    if (cap != 21) /* CAP_SYS_ADMIN, include/uapi/linux/capability.h */
        return 0;
    /* A stacking filesystem performs backing operations with its stashed
     * credentials (override_creds), after deciding the agent's merged path.
     * Those kernel-internal checks do not grant the task CAP_SYS_ADMIN.
     * A userspace credential change commits both pointers together; mount
     * APIs therefore still meet the floor, in every user namespace (ADR 0055).
     * Require both readable non-NULL pointers and the exact active override.
     * io_uring also issues under override_creds: a personality the task
     * registered (security_uring_override_creds), which userspace chose. An
     * io thread (PF_IO_WORKER: io-wq, SQPOLL) or a task with an io_uring
     * context therefore keeps the floor even under an override. */
    struct task_struct *task = bpf_get_current_task_btf();
    const struct cred *active = task->cred, *real = task->real_cred;
    int uring = (task->flags & 0x00000010) != 0; /* PF_IO_WORKER, include/linux/sched.h */
    if (bpf_core_field_exists(task->io_uring) && task->io_uring)
        uring = 1;
    if (active && real && active != real && cred == active && !uring)
        return 0;
    /* No slot-header lookup may turn the task's capability floor into an allow. */
    return tego_control_refuse(run, TEGO_HOOK_CAPABLE, TEGO_R_PROCESS_SCOPE, 0, cap);
}
