# Tego in a container

The container image and a compose file for running an agent under `tego run` on a server, with the dashboard on the
host's loopback. [docs/user/container.md](../../docs/user/container.md) is the guide: what each setting is for, which
tier works in a container, and how the ledger and the chain anchor are kept.

| File | What it is |
| ---- | ---------- |
| `Dockerfile` | The image: build from the repository root, `docker build -f examples/container/Dockerfile -t tego:local .` |
| `Dockerfile.dockerignore` | What the build leaves out of its context. |
| `compose.yaml` | The agent service (`tego run`) and the dashboard service (`tego-control serve`). |
| `tego-entrypoint.sh` | Hands the `tego` user a cgroup subtree, then drops every capability and runs the command as that user. |
| `config.yaml` | The image's machine config: the ledger on its own volume. |
| `hello.yaml`, `hello-agent.sh` | The example agent and its contract. |
| `smoke.sh` | The image's own check, which CI runs inside it. |

The tests in this directory (`go test ./examples/container/`) hold these files to each other and to the engine
without a container runtime; `.github/workflows/container.yml` builds and runs the image.
