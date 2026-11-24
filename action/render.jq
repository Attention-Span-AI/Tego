# SPDX-License-Identifier: Apache-2.0
# All record strings are untrusted. Code spans neutralise Markdown and controls.
def clean: tostring | gsub("[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]"; "?");
def prose: clean | gsub("`"; "'") | "`" + . + "`";
def code: clean | gsub("`"; "'") | (if length > 200 then .[0:96] + "..." + .[-96:] else . end) | "`" + . + "`";
def cell: code | gsub("\\|"; "\\|");
def rel: tostring | if $ws != "" and startswith($ws + "/") then ltrimstr($ws + "/") else . end;
def capname: if . == "containers.namespace_sandbox" then "nested container isolation" else gsub("[._]"; " ") end;
def bullets($xs; $max; f):
  [($xs // [])[0:$max][] | "- " + (f)] +
  (if ($xs // [] | length) > $max then ["- and \(($xs | length) - $max) more entries; see receipt.json"] else [] end) | join("\n");
def countpaths($xs; $f):
  if $f.recorded == false then "not recorded"
  else (if $f.truncated then "at least " else "" end) + (($xs // [] | length) | tostring) end;
$r[0] as $R | $v[0] as $V | $s[0] as $S | ($c[0] // null) as $C | $m[0] as $M
| ($S.tier // $R.tier // "unknown") as $tier
| [
  $marker,
  (if $R.coverage.complete != true then "### Incomplete: Tego receipt" else "### Tego receipt" end),
  "",
  "Unsigned (\($unsigned_reason | code)): a report, not evidence. This receipt is not signed.",
  "",
  "#### What this record does not cover", "",
  "- A receipt on a pull request is only as honest as the workflow file that made it. On pull_request that file comes from the pull request. Its author can make the comment and summary say anything. Trust reports only from a workflow on a protected branch that you reviewed.",
  "- The runner user, root and unconfined processes can rewrite the record and its anchor. A matching receipt and record do not establish honest execution or authorship.",
  "- Data the agent can read can leave through any allowed host. Remote effects, in-process work and a crash tail can be missing. Coverage does not mean every action was observed.",
  "- Tier \($tier | code): \($tierlines[0][$tier] // "unknown; no enforcement claim" | prose)",
  (if ($S.capabilities["record.reads_mmap_chmod"] // false) and ($R.sensitive_reads_unknown != true)
   then "- Reads: this tier records read activity; tracing can miss lines on kernels that preempt kernel code."
   else "- Reads: \($R.sensitive_reads_note // "Read coverage is unknown; a clean list says nothing about reads." | code)" end),
  (bullets($R.coverage.gaps; 20; (.field | code) + ": " + (.why | code))),
  (if $R.files.note then "- Files: \($R.files.note | code)" else empty end),
  (if $R.connections_note then "- Connections: \($R.connections_note | code)" else empty end),
  (if $R.sensitive_reads_note then "- Read note: \($R.sensitive_reads_note | code)" else empty end),
  (bullets($R.notes; 20; code)),
  (if ($S.best_effort // [] | length) > 0 then "- Best effort: " + ($S.best_effort[0:20] | map(capname | code) | join(", ")) else empty end),
  "",
  (if $V.verified and $V.anchored and $V.ended
   then "The record verified on the runner after the run: \($V.lines | code) lines."
   else "**The record did not verify as an ended run.** \($V.error // "No end or anchor was recorded." | code)" end),
  "",
  "| | |", "|---|---|",
  "| Event commit | \($commit | cell) |",
  "| Agent | \($R.agent | cell) |",
  "| Command | \(($R.command // [] | join(" ")) | cell) |",
  "| Outcome | \($R.exit_code // $R.end_reason // "no end recorded" | cell) |",
  "| Tier | \($tier | cell) |",
  "| Compiled contract hash | \($S.contract_hash | cell) (as tego compile prints it) |",
  "| Contract file SHA-256 | \($M.contract_file_sha256 // "unavailable" | cell) |",
  "| Record | \($R.run | cell), head \($V.head | cell) |",
  "| Receipt bytes | receipt.json, SHA-256 \($M.receipt_sha256 | cell) |",
  "| Tego | \($S.tego_version | cell) |",
  "",
  "This text is a display. Retain receipt.json and run/events.jsonl from the artifact to compare them with the same Tego release. No files or this text carry a CI signature. Artifact retention is finite; save a copy before expiry.",
  "",
  "#### What the agent was allowed", "",
  (if $C == null then "The compiled contract was not available."
   else [
     "Write:", (bullets([$C.fs[]? | select(.kind == "write") | .path]; 10; rel | code)),
     "Programs: " + (if $C.exec_unrestricted then "any" else "restricted" end),
     (bullets([$C.exec[]?.path]; 10; code)),
     "Network: " + (if $C.net_unrestricted then "any host" elif ($C.net | length) == 0 then "no host" else "restricted" end),
     (bullets([$C.net[]?.raw]; 10; code)),
     "Variables passed:", (bullets($C.env_pass // ["the launcher's variables after scrubbing"]; 10; code)),
     "Reads refused:", (bullets([$C.fs[]? | select(.kind == "deny_read" and (.builtin | not)) | .path]; 10; rel | code)),
     "Built-in read refusals are in compile.json; this display does not count them."
   ] | join("\n") end),
  "",
  "Additional command grant (outside the compiled hash): \($S.run_command_grant // "none recorded" | code).",
  "Runtime grants added after compile:",
  (if ($S.runtime_grants // [] | length) == 0 then "None recorded." else bullets($S.runtime_grants; 10; code) end),
  "",
  "#### What it did", "",
  "| Programs started | Files written | Created | Deleted | Renamed | Connection tries | Asked a person |",
  "|---|---|---|---|---|---|---|",
  "| \(if ($R.programs_more // 0) > 0 then "at least " else "" end)\([$R.programs[]?.count] | add // 0) | \(countpaths($R.files.written; $R.files)) | \(countpaths($R.files.created; $R.files)) | \(countpaths($R.files.deleted; $R.files)) | \(countpaths($R.files.renamed; $R.files)) | \($R.connection_tries) | \($R.asks.asked) |",
  (if ($R.programs_more // 0) > 0 then "- \($R.programs_more) more programs outside the receipt's top list; the start count is a lower bound." else empty end),
  (if ($R.connections_more // 0) > 0 then "- \($R.connections_more) more connections outside the receipt's list." else empty end),
  (if $R.files.truncated then "- File lists were truncated; counts are lower bounds." else empty end),
  (bullets($R.files.written; 10; "Wrote " + (rel | code))),
  (bullets($R.files.created; 10; "Created " + (rel | code))),
  (bullets($R.files.deleted; 10; "Deleted " + (rel | code))),
  (bullets($R.files.renamed; 10; "Renamed " + (.from | rel | code) + " to " + (.to | rel | code))),
  (bullets($R.programs; 10; (.path | code) + " count " + (.count | code))),
  (bullets($R.connections; 10; (.destination | code) + " count " + (.count | code))),
  "",
  "#### Refused actions", "",
  (if $R.refusals.total == 0 then "No refusals recorded. See the limits above."
   else "Recorded refusals: \($R.refusals.total | code)." end),
  (bullets($R.refusals.by_rule; 10; (.rule | code) + " (" + (.reason | code) + ") count " + (.count | code))),
  "| Time (UTC) | Operation | Target | Rule |", "|---|---|---|---|",
  ([$R.refusals.list[0:25][]? | "| \(.ts[11:19] | cell) | \(.op | cell) | \(.target | rel | cell) | \(.rule | cell) |"] | join("\n")),
  (if $R.refusals.list_truncated then "- The refusal list was truncated in receipt.json." else empty end),
  (if ($R.refusals.total // 0) > 25 then "- This display shows at most 25 refusals; see receipt.json for the retained list." else empty end),
  "Protected or secret-looking files opened or tried (at most 10):",
  (bullets($R.sensitive_reads; 10; (.path | rel | code) + " (refused " + (.verdicts.refused | code) + ", allowed " + (.verdicts.allowed | code) + ")")),
  "",
  "Capabilities this run did not have:",
  (bullets([$S.capabilities // {} | to_entries[] | select(.value == false) | .key]; 40; capname | code)),
  "",
  "There is no model inside Tego. The artifact also holds compile.json and the on-runner chain check."
] | map(select(. != null)) | join("\n")
