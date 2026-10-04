# Runtime fixture roles

The executable-contract entry points are `observe.newFixture`,
`cgroup.newFixture` and `supervisor.TestFallbackMutationConverges`. They load and
compile an on-disk contract over an isolated tree. `migration_test.go` verifies
those calls and inventories direct imported `agent.RuleTable` literals across
all build tags in the three runtime test directories. The per-function JSON
dispositions describe intentional partial kernel/map, pure-query and failure
inputs; they do not claim those tables came from compilation.

The inventory does not statically follow every copied table, constructor alias
or later field mutation. These additional cases have a separate purpose:

- `supervisor/gate_test.go` calls the classified `testPolicy` constructor and
  mutates gate, transport, floor and argument-bound states to exercise copied
  syscall decisions. Its fake notification memory can change during approval.
  This is a synthetic syscall/floor matrix, not a full launch contract.
- `supervisor/ask_open_integration_test.go` uses actual private files and a
  thread-local seccomp notification/ADDFD delivery path, with a controlled
  policy fixture. It proves the held descriptor and completion mechanism.
  The compiled CLI contract and Tier3 floor are separately exercised by
  `cgroup/plane_ask_outcomes_integration_test.go`.
- `internal/cli/gate_test.go` compiles real on-disk contracts. It is outside the
  three runtime inventory directories and is not an exception to their gate.
- `observe.addSyntheticParentIndex` appends a deliberate project-directory
  identity to a compiled fixture for six wire-attribution tests: full recording,
  aggregate overflow, rename endpoints, file-operation chain returns,
  record-off chain refusals and chain/model disagreement. A normal compiler
  does not produce that implicit project-directory entry. The common compiled
  fixture remains unmodified in the other tests.

Changing a direct-literal count or adding an unclassified literal fails the
inventory test. This maintenance check complements actual compiler and kernel
tests; it is not a proof that every possible dynamically constructed table was
compiled.
