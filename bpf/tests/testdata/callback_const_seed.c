// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* A planted fixture for bpf/tests TestCallbackSeedLintCatchesAPlantedFixture: not built, never loaded. Each walk
 * seeds a field its bpf_loop callback branches on the way the lint refuses. A verifier before 6.8 verifies the
 * callback once, from its first call's state, and hard-wires a branch that state rules out, which is how the
 * plane's BOUND check and its unix name check were once lost (enforce-plane §2.7, §2.11). */

struct fixture_walk {
    __u64 d;
    __u32 steps;
    __u32 crossed;
    __u32 result;
};

static long fixture_step(__u32 i, struct fixture_walk *s)
{
    __u64 d = s->d;

    if (s->steps > 64) {
        s->result = 3;
        return 1;
    }
    if (!s->crossed && d)
        s->steps++;
    return 0;
}

/* steps is seeded from a constant, crossed from a local that holds one. */
__attribute__((noinline)) int fixture_const_seed(__u64 dentry)
{
    struct fixture_walk s = {};
    __u32 none = 0;

    s.d = dentry;
    s.steps = 0;
    s.crossed = none;
    s.result = 3;
    bpf_loop(130, fixture_step, &s, 0);
    return s.result;
}

/* crossed is left as the zero-initialised stack gave it. */
__attribute__((noinline)) int fixture_zero_seed(__u64 dentry, const struct fixture_walk *hit)
{
    struct fixture_walk s = {.d = dentry};

    s.steps = hit->steps;
    bpf_loop(130, fixture_step, &s, 0);
    return s.result;
}

/* A setup helper the state is handed to seeds it: steps and d from its arguments, crossed from a constant. */
static __always_inline void fixture_setup(struct fixture_walk *w, __u64 dentry, __u32 steps)
{
    w->d = dentry;
    w->steps = steps;
    w->crossed = 1;
}

__attribute__((noinline)) int fixture_helper_seed(__u64 dentry, __u32 steps)
{
    struct fixture_walk s = {};

    fixture_setup(&s, dentry, steps);
    bpf_loop(130, fixture_step, &s, 0);
    return s.result;
}
