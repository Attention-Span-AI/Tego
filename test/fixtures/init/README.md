# test/fixtures/init — a project for `maze init` to scan

`demo-repo/` is a throwaway project: a fake `.env` (`DATABASE_URL` with a made-up password), the Claude Code
contract from `examples/agents/claude-code.yaml` as `agent.yaml`, and `verdicts.yaml`, one row per rule init must
produce. `fakebin/` holds stand-in `claude` and `git` executables, because `compile` refuses a contract whose
command or `exec.allow` entry is not on the run's PATH (`exec-not-on-path`).

Nothing here is secret and nothing here runs an agent: the loop below compiles and evaluates, it does not enforce.

## Check the contract from a Mac

The CLI builds only for Linux, so cross-compile it and run it in a container (Colima shares only the home folder,
which is why the repo has to live under `~`):

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/linux-arm64/tego ./cmd/tego
colima start
docker run --rm -v "$PWD":/r -w /r/test/fixtures/init/demo-repo \
  -e PATH=/r/test/fixtures/init/fakebin:/usr/local/bin:/usr/bin:/bin \
  debian:stable-slim /r/bin/linux-arm64/tego compile agent.yaml --offline --test verdicts.yaml
```

Expected: `3 rows: 3 passed, 0 failed`. On Linux, skip the container: `make build`, then the same `compile` line
with `bin/tego`.
