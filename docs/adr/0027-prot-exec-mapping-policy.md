# ADR 0027: a PROT_EXEC mapping of code the agent could write needs an exec.allow grant, and a file mapping may not become writable and executable

Status: accepted 2026-09-29 (before TIER3-PLAN T14), with file_mprotect deciding on the effective prot (amended 2026-09-29, note below); built 2026-09-30 at T14, the compile warning with it (note below). Proposed 2026-09-23. Step C of ADR 0024; lands after step B. Amends SEMANTICS §4 (the dynamic loader and PROT_EXEC mmap) and GAPS C31.

Decision: At tiers 2 and 3, when the contract has an exec: section, the plane refuses with -EACCES (rule exec-map, reason exec-not-allowed) in three cases:
(a) a PROT_EXEC mapping of an anonymous file (an SB_NOUSER superblock such as a memfd, or an unlinked file), unless exec.anonymous is set;
(b) a PROT_EXEC mapping of a file whose nearest fs entry is a write or ask entry and that no exec.allow entry covers, either the file itself or a directory entry above it;
(c) SELinux's execmem and execmod checks for files: a PROT_EXEC mapping that is also PROT_WRITE on a private file mapping, and an mprotect that adds PROT_EXEC to a file mapping with copy-on-write pages (vma->anon_vma set).
mmap_file decides on the effective prot (ADR 0024 item 8), and file_mprotect on the effective prot too: the kernel passes it as the hook's prot argument (reqprot plus READ_IMPLIES_EXEC's PROT_EXEC), never reqprot. For a backing file (FMODE_BACKING) the walk starts at backing_file_user_path() on 6.8+, where f_path is the real layer path; on 6.6 and 6.7 f_path is still the user path. Both bodies return 0 before the run_set lookup when the file is NULL or PROT_EXEC is absent. Anonymous memory (MAP_ANONYMOUS) is not a file and stays GAPS A2. Tier 1 has no hook and keeps that limit stated; compile --test shows the difference per tier. compile warns when a write entry holds ELF shared objects or known native-module trees (.venv, *.node under node_modules, target/) that no exec.allow entry covers. The record calls this a narrowing, not a closure.

Why: [measured] fmod_ret on security_mmap_file refused a PROT_EXEC map of one inode, scoped to one cgroup, on all seven kernels.
[documented, security/security.c] security_mmap_file passes mmap_prot(file, prot), which adds PROT_EXEC under READ_IMPLIES_EXEC.
[documented, security/selinux/hooks.c v6.12, checked today] file_map_prot_check requires EXECMEM for PROT_EXEC on a private file mapping that is also writable, and selinux_file_mprotect requires EXECMOD for a file mapping with anon_vma (text relocations).
[documented, fs/open.c v6.6 and fs/backing-file.c v6.8, checked today] On overlay mounts the vma carries the backing file, whose f_path is the real path from 6.8.
[inference] Private W then X (map a readable library MAP_PRIVATE, write code, mprotect to exec) is not 'a pre-existing library'; the execmod rule closes it. Rule (b) holds only once step B refuses mutations inside nested deny_read trees.
[inference] exec.allow already bounds which built binaries run; tying (b) to it keeps declared builds working. The memfd arm already requires exec.anonymous for memfd JITs, so (a) breaks nothing new.

Security argument: It closes drop-and-map and private write-then-execute race-free, because the kernel decides on the file and vma actually being mapped; personality(READ_IMPLIES_EXEC) is covered by the effective prot in both modes, and overlay mounts are decided on the user path. It can only refuse. Stated residuals: code mapped from a readable pre-existing file outside write entries and never modified; anonymous executable memory (A2). Text relocations are refused, not a residual.

Options considered: Rejected:
- Refuse every file under fs.write: breaks pip-installed native extensions and in-run builds.
- A strict library allow-list: the contract has no library list.
- Doing nothing: a mapping of code the run wrote stays undecided though the hook exists.
- Attaching mmap_file and file_mprotect only once a run of the build restricts exec (performance review's suggestion): a dynamic program set for a saving only on hosts whose contracts never restrict exec. Condition to revisit: doctor data showing lingering builds with no exec-restricting run.

Consequence: A contract that loads native code it builds or installs under a write entry names that directory in exec.allow, as it already must to execute binaries there; compile warns. Libraries with text relocations fail to load in an exec-restricted run at tiers 2 and 3, and the refusal names the file. Tiers 1 and 2/3 differ here, and compile --test shows it. Host cost of the pair: +70 to +170 ns per anonymous mmap, +76 to +118 ns per mprotect (measured), less with the early return.

Implementation plan:

- decide.bpf.c: the mmap_file and file_mprotect bodies, reusing ADR 0025's write, ask and exec rows. Both return early when file is NULL or PROT_EXEC is absent, and walk from backing_file_user_path() for FMODE_BACKING on 6.8+ (bpf_rdonly_cast to struct backing_file).
- A compile warning in pkg/spec/agent compile_exec.go (after ADR 0031, internal/policy/compile).
- A rewrite of SEMANTICS §4's paragraph on the dynamic loader and PROT_EXEC mmap; a host-cost row in CAPABILITIES.
Tests at tier cgroup, as root in GUEST in both modes and on MATRIX:
- A Python mmap of a .so dropped under a write entry is refused; the same file under an exec.allow directory is allowed.
- A ctypes load of a system library is allowed.
- personality(READ_IMPLIES_EXEC) plus a PROT_READ map of a dropped file is refused.
- The mprotect spelling is refused, including personality(READ_IMPLIES_EXEC) with a PROT_NONE map mprotected to PROT_READ.
- A private map of a system library, written and mprotected to PROT_EXEC, is refused (execmod); a PROT_WRITE|PROT_EXEC private file map is refused (execmem).
- A .so dropped on an overlay mount and mprotected to exec is refused.
- A memfd PROT_EXEC map without exec.anonymous is refused.
- Node, Java and V8 JIT smoke tests (anonymous memory) are unaffected.
- pip install numpy into a venv under a write entry with exec.allow: [.venv] imports.
All are also ADR 0017 cells.

*Amended 2026-09-29 (T1, TIER3-PLAN §11; accepted):* reviewed before T14 and accepted with one correction. The
decision said file_mprotect decides "on the requested prot". mm/mprotect.c's do_mprotect_pkey calls
security_file_mprotect(vma, reqprot, prot) with prot already carrying PROT_EXEC when READ_IMPLIES_EXEC applies and
PROT_READ is asked for, so deciding on reqprot let personality(READ_IMPLIES_EXEC), a PROT_NONE file map (mmap_prot
adds no exec without PROT_READ) and mprotect(PROT_READ) map written code executable without either hook refusing.
The hook now decides on prot, as SELinux does with checkreqprot=0, and a test cell covers the spelling. The
rest stands: the walk is ADR 0024 (1)'s, the rows are ADR 0025's with gen, and the FMODE_BACKING rdonly cast exists
wherever backing files do (6.8+, which has bpf_rdonly_cast).

*Built 2026-09-30 (T14; docs/p0/enforce-plane.md §2.14):* both hooks in `bpf/decide_stepc.h`. Three things the
decision left open are settled there. "Covers" is `bprm_check`'s three arms (an exec.allow directory above the file,
the file's own exec row under its name in its directory, a name row), so whatever the plane lets run the ELF loader
may map. An inode the kernel marks private (the shmem file behind `MAP_SHARED|MAP_ANONYMOUS`, a SysV segment) is
anonymous memory with MAP_ANONYMOUS (A2), not an anonymous file under (a). The fmod_ret program attaches to
`security_mmap_file(file, prot, flags)`, which takes no reqprot, so the one body reads its arguments by mode and
computes `mmap_prot()` itself in fmod_ret mode. A refused map is the plane's own `refused` line (`op: mmap` or
`mprotect`, `rule: exec-map`), since the record has no mapping kind. The compile warning is `exec-map`
(agent-contract E39), and `compile --test` answers `exec.map` rows with the tier split, with conformance cells in the
`exec` fixture (enforce-plane §2.14's condition 2).
