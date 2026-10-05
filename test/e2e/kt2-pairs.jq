# kt2-pairs.jq: reads a whole events.jsonl (jq -rs --arg src <source>) and prints
# "<requests> <parsed responses> <requests from another source> <capture gaps> <record gap count> <pairs>".
# A response counts when it parsed (parser_version set, status 200). A pair is one distinct ssl_request line
# with a parsed response whose request_seq names that line's seq, so a duplicated emission or an unrelated
# event adds to the request and response counts (which the caller caps at the number of steps) and never
# to the pairs.
[.[] | select(.kind == "ssl_request")] as $q
| [.[] | select(.kind == "ssl_response" and (.parser_version // "") != "" and .status == 200)] as $r
| [$q[] | select(.source != $src)] as $other
| [.[] | select(.kind == "gap" and .what == "capture")] as $cg
| ([.[] | select(.kind == "gap" and .what == "record") | .count // 0] | add // 0) as $rg
| ([$r[] | .request_seq | select(. != null)] | unique) as $answered
| ([$q[] | .seq | select(. as $s | $answered | index($s) != null)] | unique | length) as $pairs
| "\($q | length) \($r | length) \($other | length) \($cg | length) \($rg) \($pairs)"
