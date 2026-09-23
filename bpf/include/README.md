Shared headers: `common.h` (helpers, errno and address-family constants), `maps.h` (map definitions),
`plane_name.h` (the decision plane's exec-row link key and final-name compare, shared by `decide.bpf.c` and
`decide_fill.bpf.c`), `socket_allow.h` (ADR 0018's socket allowlist, shared by the plane's `socket_create` and
`cgroup_net.bpf.c`'s `cgroup/sock_create`), `exec_pin.h` (ADR 0048 P2's exec-pin MAC, SipHash-2-4 over a framed input,
the kernel half of `internal/execpin`), `events.h` (event and map-key structs shared with Go; bpf2go mirrors them), `vmlinux.h`
(generated from the host's BTF — see `../README.md` for the kernel it came from) and `libbpf/` (the libbpf headers,
vendored verbatim from `github.com/libbpf/libbpf` `src/` under their own `(LGPL-2.1 OR BSD-2-Clause)` licence, so a
build needs no system libbpf; only `bpf_helper_defs.h` carries two added comment lines, which say why).
