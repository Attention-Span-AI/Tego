# Tego in a container

The container image and a compose file for running an agent under `tego run` on a server, with the dashboard on the
host's loopback. [docs/user/container.md](../../docs/user/container.md) is the guide: what each setting is for, which
tier works in a container, and how the ledger and the chain anchor are kept.

| File | What it is |
| ---- | ---------- |
| `Dockerfile` | The image: build from the repository root with Docker BuildKit, `docker build -f examples/container/Dockerfile -t tego:local .` |
| `Dockerfile.dockerignore` | What the build leaves out of its context. |
| `compose.yaml` | The agent service (`tego run`) and the dashboard service (`tego-control serve`). |
| `tego-entrypoint.sh` | Hands the `tego` user a cgroup subtree, then drops every capability and runs the command as that user. |
| `config.yaml` | The image's machine config: the ledger on its own volume. |
| `hello.yaml`, `hello-agent.sh` | The example agent and its contract. |
| `smoke.sh` | The image's own check, which CI runs inside it. |

The tests in this directory (`go test ./examples/container/`) hold these files to each other and to the engine
without a container runtime; `.github/workflows/container.yml` builds and runs the image.

## Published releases

Every release tag publishes `ghcr.io/attention-span-ai/tego` for Linux amd64 and arm64. `v0.1.1` produces `0.1.1`,
`0.1` and `latest`; a prerelease such as `v0.1.1-rc.1` produces only `0.1.1-rc.1`. The release notes and the image
job summary give the signed multi-platform digest. The
[install guide](https://github.com/Attention-Span-AI/Tego/blob/main/docs/INSTALL.md#run-in-a-container) shows
`docker run` and verification with cosign against the exact tag's `release.yml` identity.

`release.yml` waits for the release gate, binary reproduction and vulnerability scan. It checks the original release
binaries against the release job's checksums and checks the control pins, then builds this Dockerfile with
`--build-arg BINARY_SOURCE=verified --build-context release=<verified-binaries-directory>`. That directory holds
`amd64/tego`, `amd64/tego-control`, `arm64/tego` and `arm64/tego-control`. The `verified` stage copies them, so the
image ships the exact signed release pair. Source builds remain the default for local use and `container.yml`.
Binary reproducibility is unchanged; the complete image is not claimed reproducible because Debian packages and
layer metadata can change. OCI labels and index annotations identify the source, revision, version, licence and
description. A separate `sign` job verifies all downloaded release assets and the pushed index digest before
signing the checksums and image and attesting provenance. Only that job holds OIDC authority; it runs no checkout,
project code or build hooks. Its certificate identity remains `release.yml@refs/tags/<tag>`, independent of job name.
`publish` receives the checksum signature bundle and releases the draft only after signing succeeds.

A failed signing/attestation step can leave a pushed image in GHCR while the GitHub release stays a draft. Verify
by digest before running. On the first push GHCR creates a private package: an organization/package admin must make
it public once in the package settings ([release runbook](../../docs/VERSIONING.md#72-how-the-tag-is-made)).

The published image uses uid/gid 10001. The dashboard accepts only a browser whose socket its uid owns; build locally
with `TEGO_UID`/`TEGO_GID` set to your own for a dashboard opened from the host, as the container guide describes.
