# Captured translated TLS programs

These 64 little-endian BPF instruction streams were read from eight real x86-64
KVM kernels on 2026-11-12. The source revision was
`353d5ce4a172bf9e6dfbab6047443f73c55ccb6b`. Each row loaded every capture body,
passed the production `CheckCaptureStack` check, passed fresh and adopted
collection checks, attached all six doctor probes, and offered uprobe capture.
Amazon Linux 6.1 tested the optional dispatcher bodies with attach type NONE;
its production collection has six programs. Every other row loaded eight
production programs. Native multi attachment is not established for Amazon 6.1.

`manifest.json` records each kernel, reported preemption setting, expected attach
type, byte length, SHA256, tail-call instruction offset, and complete source
console path and hash. Files preserve the kernel bytes, including kernel-specific
helper offsets and map identifiers. They are scanner inputs, not loadable objects.
No instruction was removed, rewritten, or synthesized. Each stream contains one
public tail-call helper (12).

The original stock dump path in `TestCaptureStackInvariantOnThisKernel` called
`asm.Instructions.Marshal`. On these kernels it rejected some translated helper
offsets as non-native helper numbers. The original failing consoles are retained.
A scratch-only test overlay replaced the dump encoder with the exact
`ProgramInfo.insns` buffer that cilium/ebpf v0.22.0 obtains through
`BPF_OBJ_GET_INFO_BY_FD`. The production checks and capture objects were unchanged.
The test printed the raw buffer in numbered chunks, with length and SHA256.
Reassembly checked contiguous chunk numbering, length, digest, and the retained
tail call for every program.

The successful external consoles are named `capture/<row>-final-1/guest.console`,
with adjacent guest status and harness logs. The manifest records those relative
names and source-console SHA256 digests; the consoles are not part of these fixtures.
The extraction used `extract.py`; the disclosed dump-only overlay was
`raw-dump-overlay.json` and `raw-dump.go`.

There were no synthetic fixture files to replace: the previous scanner inputs
were inline synthetic instructions in `ssl_stack_test.go`. Those small failure
controls remain unchanged. These authentic streams replace synthetic-only kernel
evidence. Their initial commit added test data only, verified through a scratch
scanner overlay. Permanent host tests now round-trip all 64 byte for byte through
the corrected dump encoder and run the existing scanner on them. The encoder
preserves numeric translated helper offsets without resolving them as helper
names; product loading and read-back behavior are unchanged. The corrected stock
check still needs guest reruns on RHEL 9 and Fedora 7.2, owed in a guest. Arm64
kernel acceptance is also owed in a guest.
