# spec/ — Layer 0, the standards

Language-neutral, versioned, published. `pkg/spec` in Go mirrors these files. Tests tie some of them to the code: the agent schema (`TestSchemaJSONMatchesGo`, the whole schema's shape at every depth, amended 2026-10-05: it compared the first two levels only; `TestSchemaJSONValuesMatchGo`, the size, duration, `net.ask` and `fs.ask` value patterns against the Go checks, not every value rule — `net.dns.max_stale`'s 24h cap is a description), the config README (`TestSpecREADMENamesEveryParsedKey`, key names only, not defaults or ceiling ranges), the capability matrix (`TestMatrixGolden`, every cell of `CAPABILITIES.md`), the record fixtures (`pkg/spec/record`, decoded and chain-verified, which checks the fixtures and not the field list in prose) and the built-in `deny_read` row of `policy/SEMANTICS.md` (`TestSemanticsDenyReadRowNamesBuiltInList`, the credential entries, not browser paths). Everything else here is not checked for drift.

| Dir | What | Version |
|---|---|---|
| `agent/v0/` | the agent contract: JSON Schema for `agent.yaml`, examples | v0 |
| `record/v1/` | the run record: the field list in prose (`README.md`) and fixture ledgers; no JSON Schema yet | v1 |
| `identity/` | run identity: env vars, cgroup path, id formats, exit codes | doc |
| `reason/` | the reason channel: errno, reason record, file/socket, hook payload | doc |
| `backend/` | backend capability matrix (`CAPABILITIES.md`); the conformance suite is `test/conformance`, ADR 0017 | doc |
| `config/v0/` | the machine config: layers, ceilings, settings; its Go mirror `pkg/spec/config` is checked for key names only | v0 |
| `policy/` | policy semantics: defaults, precedence, matching, gate predicates | doc |
| `policy/conformance/` | the filesystem conformance table, embedded as a Go package and run by `test/conformance` | doc |

**spec/ vs docs/.** spec/ holds what other programs and people rely on as a format or a guarantee (a contract, a record, a code set, a capability per tier). Design, plans and component behaviour live in docs/: docs/p0 for each engine component, docs/adr for decisions. docs/spec/exec-command-rows.md is a design table that `tego` prints to users, so it stays in docs/. When spec/ and a docs/p0 spec disagree about a format, spec/ wins; about engine behaviour, check the code (docs/README.md, "When two docs disagree").

A change here is a breaking change until the version bumps. Fixtures in `record/v1/fixtures/` are the contract that `internal/check` is built against.
