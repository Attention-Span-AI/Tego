# Common targets. `make help` lists them.
.PHONY: help gen build build-bpf maze maze-tap test integration lint precommit precommit-affected spdx licenses vm-test vm-matrix vm-root-test vm-perf vm-pairs vm-clang release doctor overhead e2e-reason
GO ?= go
# CLANG: another clang for `make gen` than the pinned toolchain, e.g. CLANG=$$(test/vm/fetch-clang.sh), for
# trying a change (its objects are not the ones to commit). gen.go says `-cc clang` and bpf2go derives
# `llvm-strip` from it, so CLANG must name a file called clang with an llvm-strip beside it; its directory goes
# first on PATH.
CLANG ?=
BPF_TOOLCHAIN ?=
# vm-test: the one kernel-matrix row it runs; vm-matrix: the rows it runs, every row when empty
# (`test/vm/fetch-kernel.py --list`).
VM_KERNEL ?= ubuntu-24.04
VM_ROWS ?=
# vm-root-test: where the static test binaries, the guest logs and summary.json go.
VM_OUT ?= bin/vm
help:        ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-12s %s\n", $$1, $$2}'
# gen removes the previous bpf2go output before regenerating, so an object or target dropped from
# internal/bpf/gen.go leaves no stale file behind; the output is committed, and CI's bpf-gen job fails
# on any difference between it and what this target writes (bpf/README.md).
# gen compiles with the pinned toolchain, which scripts/bpf-toolchain.sh fetches on first use: LLVM 20.1.8 run on
# Ubuntu 24.04's glibc, since the release clang's output depends on the glibc it runs on (bpf/README.md). CI job
# bpf-gen fails on committed objects any other toolchain made. CLANG=/path/to/clang compiles with that clang
# instead, for trying a change, never for objects to commit.
# BPF_TOOLCHAIN is the directory the toolchain is kept in (the script's default when empty). The committed files
# are removed only once the toolchain is there, so a failed fetch leaves them as they were.
gen:         ## regenerate the committed bpf2go objects and bindings with the pinned toolchain (CLANG=... for another)
	$(if $(CLANG),$(if $(filter clang,$(notdir $(CLANG))),,$(error CLANG must name a binary called clang, got $(CLANG))))
	bin="$(if $(CLANG),$(abspath $(dir $(CLANG))),$$(./scripts/bpf-toolchain.sh $(BPF_TOOLCHAIN)))" && \
		rm -f internal/bpf/*_bpfel.go internal/bpf/*_bpfeb.go internal/bpf/*_bpfel.o internal/bpf/*_bpfeb.o && \
		PATH="$$bin:$$PATH" $(GO) generate ./internal/bpf/...
# build embeds the tier-2 BPF objects (-tags tegobpf): the bpf2go output is committed, so this needs no clang
# and no `make gen`, and a binary without them can only ever run tier 1. A plain `go build ./cmd/tego` is the
# tier-1-only build, and reports tier cgroup as not built with the fix line. The binary is static and not PIE as
# a release choice, so it runs on any distribution's loader or none; tier 2 no longer needs it, since its marks are
# placed after the child stage's execve (ADR 0021 (2), (4); enforce.Buildable has no linking check), and the guest
# run of a PIE build is ADR 0021's open condition. CGO_ENABLED=0 alone does not give a static binary:
# -buildmode=pie, which GOFLAGS or a distribution's Go can ask for, links a cgo-free binary against the loader
# too. -buildmode=exe on the command line overrides GOFLAGS.
# build writes the pair (ADR 0100 (1a), (1b)): bin/tego-control first, then bin/tego linked with its SHA-256
# (internal/handoff.controlSHA256), which `tego serve` and the other control nouns hand off to and nothing else; a
# tego built without it refuses the handoff [control-unpinned]. tego-control links no BPF and takes no tag.
# check-control-pin.sh then checks the pin and that both print the same version.
build:       ## both static binaries: bin/tego (tier-2 BPF objects embedded) pinned to bin/tego-control's SHA-256
	CGO_ENABLED=0 $(GO) build -buildmode=exe -trimpath -ldflags '-s -w' -o bin/tego-control ./cmd/tego-control
	chmod go-w bin/tego-control
	pin=$$(sha256sum bin/tego-control | cut -d' ' -f1) && \
		CGO_ENABLED=0 $(GO) build -buildmode=exe -tags tegobpf -trimpath \
		-ldflags "-s -w -X github.com/attention-span-ai/tego/internal/handoff.controlSHA256=$$pin" -o bin/tego ./cmd/tego
	./scripts/check-control-pin.sh bin/tego bin/tego-control
build-bpf: build ## the same binary as build, under the name the fix lines and older docs give
maze:        ## build the maze CLI and install it as `maze` in $(go env GOBIN) (~/go/bin), on macOS and Linux
	$(GO) install -trimpath ./cmd/maze
maze-tap:    ## build a maze release snapshot and serve it from a local Homebrew tap, to install it the way a user does
	./scripts/maze-local-tap.sh
# test and integration are CI's steps: inside the user's systemd manager, held to their skip lists, integration
# built cgo-free, so release.sh check does not pass with the cgroup-placement tests skipped; -count=1, as CI and
# precommit run them (a cached pass can be stale for a test that runs go build or go list).
test:        ## unit tests, as CI runs them (user manager, test/unit-skips.txt)
	GO="$(GO)" ./scripts/gated-test.sh test/unit-skips.txt "$$($(GO) env CGO_ENABLED)" -count=1 ./...
integration: ## root-free integration tests (Landlock tier on this box), as CI runs them
	GO="$(GO)" ./scripts/gated-test.sh test/integration-skips.txt 0 -count=1 -tags integration ./...
lint:        ## precommit's static steps: format, the four vets, licenses, spdx, both golangci-lint runs, skiplists, exits, descriptor ownership (check-fd), rulecheck, isocheck (required)
	./scripts/gofmt-clean.sh && $(GO) vet ./... && $(GO) vet -tags integration ./... && $(GO) vet -tags tegobpf ./... && $(GO) vet -tags 'integration tegobpf' ./... && ./scripts/check-spdx.sh && GO="$(GO)" ./scripts/check-licenses.sh && golangci-lint run --config .golangci.yml && ./scripts/lint-untagged.sh && ./scripts/check-skiplists.sh && GO="$(GO)" ./scripts/check-exits.sh && GO="$(GO)" ./scripts/check-fd.sh && $(GO) run ./tools/rulecheck && $(GO) run ./tools/isocheck
# precommit is the merge gate: an inherited TEGO_PRECOMMIT_SINCE would make it the scoped check, so it is cleared.
precommit:   ## CI build-test's checks before a commit: gofmt, vets, both lints, spdx, skiplists, script self-tests, gated tests (.githooks); TEGO_PRECOMMIT_JOBS=1 runs them one at a time
	TEGO_PRECOMMIT_SINCE= GO="$(GO)" ./scripts/precommit.sh
# precommit-affected: BASE is a revision here (bench-gate's BASE is a checkout); master when unset.
precommit-affected: ## in-between check of what the change since BASE (a revision, default master) reaches (tools/affected); never a merge's gate
	TEGO_PRECOMMIT_SINCE="$(or $(BASE),master)" GO="$(GO)" ./scripts/precommit.sh
spdx:        ## SPDX header check
	./scripts/check-spdx.sh
licenses:    ## license texts and notices for the linked dependency versions
	GO="$(GO)" ./scripts/check-licenses.sh
vm-test:     ## doctor and kill tests 1, 2, 4, 5, 6, 7 on one kernel-matrix row's own kernel, as root in a KVM guest (VM_KERNEL=...)
	GO="$(GO)" VM_OUT="$(VM_OUT)" ./test/vm/matrix.sh $(VM_KERNEL)
vm-matrix:   ## the same on every kernel-matrix row (VM_ROWS="debian-13 rhel-9" for some), with a summary table
	GO="$(GO)" VM_OUT="$(VM_OUT)" ./test/vm/matrix.sh $(VM_ROWS)
vm-root-test: ## privileged integration suites as root in a KVM guest, no host root (test/vm/root-suites.sh)
	GO="$(GO)" VM_OUT="$(VM_OUT)" ./test/vm/root-suites.sh
vm-perf:     ## the tier-3 perf suite in a KVM guest: cold and warm start, fill, open cost, concurrency (test/vm/perf.sh; PERF_BOOT=bpf|default, PERF_KERNEL=<matrix row>)
	GO="$(GO)" ./test/vm/perf.sh $(PERF_ARGS)
# vm-pairs: ADR 0021's pairs runs, one guest per variant (test/vm/pairs.sh's header lists them); its results go under
# $(VM_OUT)/pairs/<row>/<boot>/<variant>/summary.json.
vm-pairs:    ## ADR 0021's tier-2 pairs runs in KVM guests (test/vm/pairs.sh; VARIANTS=, PAIRS_KERNEL=<row>, PAIRS_BOOT=bpf|default|both, PAIRS_N=50 for a smoke)
	GO="$(GO)" VM_OUT="$(VM_OUT)" ./test/vm/pairs.sh
vm-clang:    ## fetch clang/LLVM without root and print its path, for `make gen CLANG=...`
	@./test/vm/fetch-clang.sh
release:     ## goreleaser snapshot
	goreleaser release --snapshot --clean
doctor:      ## run the built binary's doctor
	./bin/tego doctor
e2e-reason: ## the reason channel end to end with the real Claude Code and the model stub (test/e2e/reason-claude/run.sh; local, not in CI; exit 77 is a skip)
	./test/e2e/reason-claude/run.sh
overhead:    ## overhead benchmark (test/e2e/overhead); takes minutes, not part of `test`
	./test/e2e/kt3-overhead.sh
.PHONY: race vuln preset-freeze coverage coverage-vm coverage-test install-test skipgate-test release-test harness-test bench-gate bench-gate-test budgets budgets-test deadcode-report-test
# race needs cgo, which every build of the binary itself turns off (see build): the detector's runtime is
# linked through it. The privileged suites are not raced here: they need root, which this target does not take.
race:        ## unit and unprivileged integration tests under the race detector (needs a C toolchain)
	CGO_ENABLED=1 ./scripts/in-user-manager.sh $(GO) test -count=1 -race -shuffle=on -p 4 ./...
	CGO_ENABLED=1 ./scripts/in-user-manager.sh $(GO) test -count=1 -race -shuffle=on -p 4 -tags integration ./...
vuln:        ## govulncheck: fails on a vulnerability the code can reach, lists the rest
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.8.0 -tags tegobpf ./...
# VERSION is a tag name, which git lets hold $ ( ) ; and quotes. The recipe reads it as the shell variable make exports,
# so it is data: $(VERSION) here would paste it into the recipe's text, as code, in release.yml's job with the signing
# identity. A value set in the environment (VERSION="$TAG" make preset-freeze) also reaches the shell unexpanded by make.
preset-freeze: ## at a release cut (VERSION=vX.Y.Z): every preset revision is in pkg/spec/presets' released table with its sha256 (ADR 0068 D3)
	TEGO_RELEASE_VERSION="$$VERSION" $(GO) test -count=1 -run '^TestReleasedRevisionsAreFrozen$$' ./pkg/spec/presets
coverage:    ## merged coverage of the unit and unprivileged integration suites into bin/coverage (scripts/coverage.sh)
	GO="$(GO)" ./scripts/in-user-manager.sh ./scripts/coverage.sh -o bin/coverage
coverage-vm: ## the same plus the privileged suites as root in KVM guests (VM_PKGS="launch doctor" for some)
	GO="$(GO)" ./scripts/coverage.sh --vm -o bin/coverage $(VM_PKGS)
coverage-test: ## scripts/coverage.sh's reading of its arguments, with a stand-in for go
	./scripts/coverage_test.sh
bench-gate:  ## CI's bench gate against BASE, a checkout of the base commit (needs benchstat; scripts/bench-gate.sh)
	GO="$(GO)" ./scripts/bench-gate.sh $(BASE)
bench-gate-test: ## scripts/bench-gate.sh's decision and runs, with stand-ins for go and benchstat
	./scripts/bench-gate_test.sh
budgets:     ## the absolute timing budgets as their specs write them (ADR 0048 C8, plan fill, flood, Borrow ratio, the 55k-line rules read); run on an idle machine
	GO="$(GO)" ./scripts/timing-budgets.sh
budgets-test: ## scripts/timing-budgets.sh's runs and decision, with a stand-in for go
	./scripts/timing-budgets_test.sh
deadcode-report-test: ## report collector orchestration with stand-ins, without downloading or running analysis
	./scripts/deadcode-report_test.sh
install-test: ## scripts/install.sh's verification paths against a release laid out on local disk
	./scripts/install_test.sh
skipgate-test: ## scripts/skipgate.sh's allowlist and must-pass reading over canned go test -json streams
	./scripts/skipgate_test.sh
	./scripts/check-skiplists_test.sh
release-test: ## scripts/release.sh push and tag refusals, bpf-toolchain.sh's directory guard and check-control-pin.sh, in throwaway directories
	./scripts/release_test.sh
	./scripts/check-control-pin_test.sh
	./scripts/bpf-toolchain_test.sh
	./scripts/tree-files_test.sh
harness-test: ## the kill tests', overhead harness's and kernel matrix's own shell tests, with stand-ins (no root, guest or network)
	./scripts/check-spdx_test.sh
	./scripts/scrub-capture_test.sh
	./scripts/check-licenses_test.sh
	./scripts/fuzz-corpus_test.sh
	./test/e2e/lib_test.sh
	./test/e2e/kt4_test.sh
	./test/e2e/kt5_test.sh
	./test/e2e/kt2_pairs_test.sh
	./test/e2e/m0_demo_test.sh
	./test/e2e/overhead/kt3_test.sh
	./test/e2e/overhead/bench_test.sh
	./test/e2e/overhead/run_test.sh
	./test/vm/matrix_test.sh
	./test/vm/guarded-run_test.sh
	./test/vm/bounded-run_test.sh
	./test/vm/fwd-run_test.sh
	./test/vm/kvm-run_test.sh
	./test/e2e/pydeps_test.sh
	./test/vm/root-suites_test.sh
	./test/vm/kvm-step_test.sh
	./test/vm/kvm-modules_test.sh
	./test/vm/kvm-files_test.sh
	./test/vm/kvm-cleanup_test.sh
	./test/vm/tier2-pairs_test.sh
	./test/vm/pairs_test.sh
	./test/vm/doctor-refusal_test.sh
	./test/vm/doctor-facts_test.sh
	./test/vm/perf_test.sh
	./test/vm/python-pkgs_test.sh
	./test/vm/fetch-kernel_test.sh
