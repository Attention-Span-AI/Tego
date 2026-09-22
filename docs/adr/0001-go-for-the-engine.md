# ADR 0001: Go for the engine, C for BPF programs

Status: accepted 2026-09-21.
Decision: the engine, CLI and page are Go (`CGO_ENABLED=0`, one static binary); BPF programs are C with CO-RE compiled by bpf2go at dev time.
Why: cilium/ebpf maturity, static binary, reference code (Tetragon, Tracee, ecapture).
Consequence: the low-level runtime may be reimplemented in Rust later behind the same `spec/`; nothing above it changes.
