# ADR 0030: rule IDs are unique across the specs and tied to tests; specs state the current rule

Status: proposed 2026-09-23; first step built 2026-09-24 in report mode, before the rename: tools/rulecheck (a command with its own tests, run by scripts/precommit.sh and CI build-test) fails on an ID defined twice in one docs/p0 spec and on a reference in docs/ or spec/ to a rule, edge case or lettered part its document does not have, reports the same references in Go comments, and lists the rules no test mentions. Condition: the prefixed rename, the // rule: citations, the Rule-Text-Only trailer, the [security] tag and uncited.txt are not built. Lands before the semantic ADRs (0016 onward) so every amendment they make is written once, in the new form.

Decision: (1) Every numbered rule gets a globally unique ID made of its document's prefix and its number: SEM for spec/policy/SEMANTICS.md (numbered for the first time, by section, e.g. SEM-2.4); SUP supervisor.md; LL enforce-landlock.md; CGO enforce-cgroup-observe.md; RL runtime-launch.md; RLG record-ledger.md; CD capture-derive.md; AC agent-contract.md; IC identity-config.md; LCD limits-check-doctor-cli.md; PLN the new enforce-plane.md (ADR 0024). ADRs keep ADR-00NN. (2) A rule whose loosening would weaken enforcement or the record carries the tag [security] in its heading (for example SUP-R5 fail-closed, SUP-R15c deny_write, CGO-R12 the slot scrub). (3) Tests cite the rules they check with a comment // rule: SUP-R15. (4) tools/rulecheck, a go test, fails CI when a test cites an unknown or removed ID; when a rule's text changes in a diff that touches no test citing it, unless the commit carries the trailer Rule-Text-Only: <id>, which rulecheck refuses for [security] rules; and when a normative rule has no citing test and is not in tools/rulecheck/uncited.txt, a baseline that may only shrink. (5) The rename is one scripted commit at a docs freeze. If no freeze is reachable before ADR 0017 starts, rulecheck lands first in report mode and the rename follows at the next freeze. (6) From then on a spec states the current rule only; history goes to a dated Changes list at the end of each document and to git, and code comments cite an ID instead of restating rationale.

Why: [measured, regex counts] 455 numbered R/E/I items across 9 documents with only 100 distinct IDs; 82 are defined in more than one document ('R1' and 'R10' in all nine). About 91% of roughly 9,700 references in Go code carry no document name. SEMANTICS, where drift happens, has no numbered rules. 206 'amended/added <date>' passages are edited in place. Production comment bytes (1.38 MB) exceed code bytes (1.18 MB).
[inference] Without unique IDs 'every rule has a test' cannot be checked, and in-place amendments hide the current rule; that is how R9's 'verdict: inferred' survived beside a schema that has no such value. Renaming after this program would amend a dozen specs under colliding IDs and then rename them again. [security review, accepted] An editorial trailer must not let a security rule's text loosen without its tests.

Security argument: Security rules become traceable to the tests that hold them (SUP-R5, SUP-R15c, CGO-R12). Removing or loosening one without touching its tests fails CI, and the editorial escape hatch is closed for [security] rules.

Options considered: Rejected:
- The status quo.
- A grep-based mention check: IDs collide, so it overstates coverage (267 of 302 found by a loose check).
- Moving rules into code: the specs are the normative artefact.
- Renaming after the semantic ADRs: every spec amendment in this set would be written twice.

Consequence: One large mechanical commit at a coordinated freeze, then near-zero ongoing cost. Rule text changes need test attention or an explicit trailer, never for [security] rules.

Implementation plan:

- tools/rulerename: maps (document, ID) to the prefixed ID over docs/, spec/ and *.go; dry-run diff first; one commit at the freeze, together with the collapse of in-place amendments into Changes lists.
- tools/rulecheck: parser for the ID forms, the trailer and the [security] tag; its own tests over fixtures of each form; tools/rulecheck/uncited.txt generated at the rename.
- CI job wiring (report mode until the rename, gating after).
- ADR 0028 S6's decision tables later supply SEM citations.
Acceptance: rulecheck green on master; the uncited baseline listed; a test that changes a [security] rule's text with only the trailer fails.
Docs: ADR 0030; docs/p0/README.md (the prefixes); CONTRIBUTING (citations, trailer).
