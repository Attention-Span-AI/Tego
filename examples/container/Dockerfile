# SPDX-License-Identifier: Apache-2.0
#
# The Tego container image (docs/user/container.md): tego and tego-control, static, on a small Debian base with the
# tools an agent usually needs as an option. Build it from the repository's root:
#
#   docker build -f examples/container/Dockerfile -t tego:local .
#
# Targets:
#   runtime  (default) the two binaries, the entrypoint that hands the `tego` user a cgroup subtree, a machine config
#            and an example agent; for running agents under `tego run`.
#   binaries the two binaries alone on an empty base, to copy into an agent image of your own:
#            COPY --from=tego:binaries /usr/local/bin/tego /usr/local/bin/tego-control /usr/local/bin/
#            (copy both: tego hands `tego serve` to the tego-control whose SHA-256 it was built with).
#
# Build arguments:
#   EXTRA_PACKAGES  Debian packages for the agent, none by default. Usual ones: "python3 nodejs npm ripgrep curl
#                   jq openssh-client make". Anything installed is still governed by the contract's exec rules.
#   TEGO_UID/GID    the uid and gid of the `tego` user (10001). Give your own (`id -u`) when tego-control serve is to
#                   be opened from the host: the dashboard answers only a browser whose socket that uid owns.
#   VERSION, COMMIT, DATE  what `tego version` prints; CI passes the commit's. Left empty, the build has no VCS
#                   stamp to fall back on (.git is not sent to the build) and prints "dev".
#
# The base images are pinned by digest (an index digest, so every architecture), resolved from the registry on
# 2026-10-27, and written out in the FROM lines, where Dependabot's docker ecosystem proposes the updates. The Go
# image is go.mod's toolchain (compose_test.go holds the two equal).

FROM golang:1.27.3-trixie@sha256:c124b9ad3452f46061b5054607d26ea51730dae5372c5e469920063ba2bc6dcc AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=""
ARG COMMIT=""
ARG DATE=""
# make build's pair, with the release's version stamps: tego-control first, then tego with the tier-2 BPF objects
# (-tags tegobpf; the bpf2go output is committed, so no clang) and tego-control's SHA-256 pinned in it (ADR 0100
# (1b)). Static and not PIE, as the release builds them, so they run on any base. check-control-pin.sh then checks
# the pin; it does not run the binaries as root, which tego-control refuses.
RUN set -eu; \
	mod=$(go list -m); \
	x="-X $mod/internal/buildinfo.version=$VERSION -X $mod/internal/buildinfo.commit=$COMMIT -X $mod/internal/buildinfo.date=$DATE"; \
	CGO_ENABLED=0 go build -buildmode=exe -trimpath -ldflags "-s -w $x" -o /out/tego-control ./cmd/tego-control; \
	pin=$(sha256sum /out/tego-control | cut -d' ' -f1); \
	CGO_ENABLED=0 go build -buildmode=exe -tags tegobpf -trimpath \
		-ldflags "-s -w $x -X $mod/internal/handoff.controlSHA256=$pin" -o /out/tego ./cmd/tego; \
	./scripts/check-control-pin.sh /out/tego /out/tego-control

FROM scratch AS binaries
COPY --from=build /out/tego /out/tego-control /usr/local/bin/

FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad AS runtime
ARG EXTRA_PACKAGES=""
ARG TEGO_UID=10001
ARG TEGO_GID=10001
# ca-certificates and git for almost any agent, setpriv for the entrypoint's drop to the user (Debian ships it in
# util-linux or, from trixie on, in a package of its own; whichever this base has). procps gives the operator ps.
RUN set -eu; \
	apt-get update; \
	apt-get install -y --no-install-recommends ca-certificates git procps $EXTRA_PACKAGES; \
	command -v setpriv >/dev/null || apt-get install -y --no-install-recommends setpriv; \
	setpriv --version; \
	rm -rf /var/lib/apt/lists/*
# The user every run is started as, with a home in the passwd database: tego finds its state directory (~/.tego: the
# chain anchor, its own log) through passwd, never $HOME. The directories exist in the image, owned by the
# user, so a named volume mounted on them starts with that owner. The home itself is 0755, not the 0700 Debian's
# useradd gives it: the entrypoint runs as root with every capability dropped but a few (compose.yaml), so without
# CAP_DAC_OVERRIDE it could not reach /home/tego/.tego in a 0700 home it does not own. ~/.tego itself stays 0700.
RUN set -eu; \
	groupadd --gid "$TEGO_GID" tego; \
	useradd --uid "$TEGO_UID" --gid "$TEGO_GID" --home-dir /home/tego --create-home --shell /bin/bash tego; \
	install -d -m 0700 -o tego -g tego /home/tego/.tego /var/lib/tego/runs; \
	install -d -m 0755 -o tego -g tego /work /work/out; \
	chmod 0755 /home/tego
COPY --from=build /out/tego /out/tego-control /usr/local/bin/
COPY examples/container/tego-entrypoint.sh /usr/local/bin/tego-entrypoint
COPY examples/container/config.yaml /etc/tego/config.yaml
COPY examples/container/hello.yaml examples/container/hello-agent.sh examples/container/smoke.sh /usr/local/share/tego/
# The machine config is root's and read-only to everyone else, as tego's trust check wants of /etc/tego (R20).
RUN chmod 0755 /usr/local/bin/tego-entrypoint /usr/local/share/tego/hello-agent.sh /usr/local/share/tego/smoke.sh \
	&& chmod 0644 /etc/tego/config.yaml /usr/local/share/tego/hello.yaml
# tego's whole state, kept out of the container's writable layer: the anchor, then the ledger (compose.yaml mounts a
# volume on each; docs/user/container.md says why they are two).
VOLUME ["/home/tego/.tego", "/var/lib/tego/runs"]
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/tego-entrypoint"]
CMD ["tego", "doctor"]
