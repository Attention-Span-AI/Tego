// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Fixed listener map layouts shared by every map producer and consumer. */
#ifndef TEGO_PLANE_LISTENER_H
#define TEGO_PLANE_LISTENER_H

/* Parent is obtained from the held directory descriptor in the kernel.
 * Abstract names have parent 0 and an explicit byte length, including NULs. */
struct tego_plane_listen_key {
    __u64 parent;
    __u32 name_len;
    __u32 abstract;
    char name[108];
    __u32 pad;
};
struct tego_plane_listen_row {
    __u64 parent_ino;
    __u32 parent_generation;
    __u32 s_dev;
    __u32 gen;
    __u16 rule_idx;
    __u16 pad;
};

#endif /* TEGO_PLANE_LISTENER_H */
