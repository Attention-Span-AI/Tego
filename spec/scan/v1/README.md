# Scan snapshot v1

`schema.json` is the structural contract for `tego.scan/1` (ADR 0145).
`fixtures/basic.json` is synthetic A, B, C and G data. It describes no real scan
or installation. The independent validator is exercised by the catalog package's
schema test. The CLI whole-command fixture also validates actual JSON against
this schema, checks strict decoding and exact equality with the private saved
object. The reader enforces ADR 0145 semantic rules for c1/c2/c3 and c4 with A/B/C/D/E/F/G and advanced scope; reserved
later kinds and catalogs remain unsupported. Schema validation alone does not
establish privacy or truth.

The result is a private display cache. A same-user writer can forge a valid
object. No reader may treat it as a receipt, authorize an action from it, copy
stored text into a command, or infer absence from a zero count.

The process categories are separate required counts: exited_during_scan,
kernel_threads and unreadable_programs. Unreadable own program files also have
a required pid list and the required fixed `unreadable_programs_warning` field:
"Tego cannot tell whether these are agents; any program can make itself unreadable."
The warning is present even for a zero count. Check codes distinguish default unreadable-observed
(exit 3) from the explicit none-observed-allow-unreadable mode (exit 0).
With `--allow-unreadable-programs`, exit 0 does NOT mean no agent runs outside Tego.
Exit 3 has the same uncertainty.
Path patterns reject relative, control and bidi text; the semantic decoder also
requires unicode.IsPrint and rejects the replacement rune. Collection applies
the same filter before paths reach the encoder.


Catalog c2 adds closed declaration ids; c1 snapshots remain readable.
`fixtures/project.json` adds a synthetic F declaration, never installation proof.
An older c1 reader rejects c2 rather than salvaging rows; its guide currently
shows the generic "invalid, unsafe or unavailable" saved-result reason. The
new fixed source reason mode also requires a reader that recognizes that code.

| Format | Package name | Dependency id |
| --- | --- | --- |
| npm | @anthropic-ai/claude-code | dep-claude |
| npm | @openai/codex | dep-codex |
| npm | opencode-ai | dep-opencode |
| npm | @google/gemini-cli | dep-gemini |
| npm | @langchain/langgraph | dep-langgraph-js |
| Python | langgraph | dep-langgraph |
| Python | crewai | dep-crewai |

The npm launcher names come from the inherited wrapper catalog. LangGraph and
CrewAI are declaration hints from their official install documentation:
[LangGraph Python](https://docs.langchain.com/oss/python/langgraph/quickstart),
[LangGraph JavaScript](https://docs.langchain.com/oss/javascript/langgraph/overview),
[CrewAI](https://docs.crewai.com/en/installation). No vendor install or runtime
validation is claimed by these dependency hints. Names are exact for npm;
Python uses case folding and distribution-name separator normalization.
All four direct npm dependency tables are selected. Transitive lockfile contents
are excluded. Versions, scripts, URLs, comments and ignored values are discarded.

F marker rules are marker-langgraph (langgraph.json), marker-crew (crew.jsonc),
and marker-agents (config/agents.yaml). Their dependency is null and fact is path.
All other F rows require a closed dependency id and dependency fact. The reader
checks that the source and detail paths agree and have the selected filename.
The current directory is the sole root; no parent or child directory walk,
includes or alternate requirements filename is allowed. F's openat2 traversal
refuses links and mount crossings beneath that root. Reason mount is a visible
not-read row. An unavailable openat2 returns unsupported, never a weaker walk.
In both passes, regular root-owned passwd/group/NSS files and every path
component must exclude group/other write bits, including resolved symlink
targets and sticky writable ancestors. The shared config resolver pins and
rechecks placement and the descriptors used to read bytes. Unverifiable
placement refuses accounts-unreadable with a named administrator repair.

D/E/F use a separate strict policy for discovery reads only. Group write needs
complete bounded files-only local passwd/group/NSS evidence, an existing local
group entry, no listed member except the inode owner and no other primary-gid
account. All three files are read twice through fresh opens. Bytes must match
between passes, and descriptor/path device, inode, size, mtime and ctime must
match within and across passes. Metadata is an additional refusal, never proof
of equal contents. Differences or errors refuse with accounts-unreadable and a
repair to run the scan again; there is no retry. Root's in-place writes leaving
both passes reading the same bytes are not detected, including undo between
passes and fragmented reads within one timestamp tick. Membership changed
after the scan remains a limit. Missing, failed, truncated, malformed or
size-limited evidence and directory-service sources refuse; there is no primary-gid fallback. World
write and access ACLs also refuse. Account/boot metadata, records, locks, run
directories and saved-result parents retain the base's group/other-write refusals.
The optional source field `writable_group` names a mode-refused account group
(or `gid N`) at every discovery call site. Parent refusals retain the parent's
locator, so the footer's `chmod g-w` targets the path actually at fault. Its
grammar is bounded, and the field is accepted only on not-read/partial sources
with reason mode. Optional `group_evidence` requires that same group-labelled
mode refusal and carries one closed code: accounts-unreadable, accounts-limit,
accounts-malformed, directory-service, owner-not-local, group-missing,
shared-primary, other-member or access-acl. The footer renders the reason and
the command for that source locator. Older strict readers may refuse a
snapshot containing either field.
Complete local evidence does not exclude retained process group credentials,
later membership changes or host group members omitted in a container. It is
only evidence for a discovery row. Project declarations neither establish
installation nor tick the guide's find step.

Catalog c3 adds configured MCP and user-unit observations. Nonzero optional
counts are `mcp_servers` and `user_units`. Config details add `server` and
`arguments`; unit details add `unit`, `arguments` and `specifiers_unexpanded`.
Config scope `local` identifies only Claude's `projects.<current folder>.mcpServers`
entry; other remembered folders are skipped. `user` and `project` retain their
meanings. Source reason `unresolved` is restricted by the strict decoder to failed
or partial E sources; text says the named startup could not be determined.
Host remains null. Program is an
existing native catalog id or null for MCP; units also accept the inherited
Node-wrapper catalog ids. No command text is stored. Evidence facts are mcp-key, exec-start and
timer-unit. Configured rows never establish a running process or tick Find.
D/E failures retain partial status and source uncertainty; only process coverage
decides the check. An observed outside process keeps priority. Older readers reject c3 or its new local-scope/unresolved codes. The reader still accepts c1/c2.

`fixtures/configured.json` is synthetic c3 MCP, service and timer data. It is
neither a real scan nor installation/runtime proof. The strict decoder fuzzer
uses it to reach all three configured detail shapes; the independent structural
validator checks it too.

Catalog c4 adds explicit advanced scope, system units, cron and validated
container cgroup hints. `fixtures/advanced.json` is synthetic, not a root or
distribution-install proof. An advanced process with `uid` different from
`as.recipient_uid` must have `cwd: null`; the strict encoder and decoder reject
a foreign working folder. Collection never reads that folder, and text rows
say "folder not recorded for other accounts". Recipient process folders retain
their existing meaning. Process `unit` remains null; configured unit names are
separate typed unit metadata. The complete retained cross-user field list and
its purpose are in [the user page](../../../docs/site/finding-agents.md).

Optional `account_repair` is printable text of at most 2048 bytes on discovery
mode refusals with `accounts-unreadable` and a named writable group. It names
the failed account file or component and repair. Older strict readers may
refuse this field. It contains placement diagnostics, never account contents.
