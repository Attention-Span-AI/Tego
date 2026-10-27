# MCP fixtures

Recorded on 2026-10-19 from the official TypeScript SDK (`@modelcontextprotocol/sdk` 1.17.0, protocol revision
2025-06-18), a real client talking to a real server on the loopback, with the scripts in `record/`
(`MCP_SDK_DIR` names a directory holding `npm install @modelcontextprotocol/sdk@1.17.0 zod@3.23.8`). No model and no
network service took part. The client initializes, lists tools, calls `db_query` and then `echo` (with a newline and
quotes in its argument), and closes.

| File | Transport | Recorded how |
|---|---|---|
| `stdio-client.jsonl` | stdio | every byte the client wrote to the server's stdin (`record/tee.cjs`), verbatim |
| `streamable-sse.jsonl` | streamable HTTP, answers as SSE | one JSON line per exchange: the request's method, path, content type and exact body, and the response |
| `streamable-json.jsonl` | streamable HTTP, `enableJsonResponse` | as above |
| `http-sse-legacy.jsonl` | HTTP+SSE (2024-11-05) | as above: the POSTs to `/messages?sessionId=...`; the GET `/sse` stream never ends, so it is not a line |

Recording again: `node record/client.cjs stdio <out>`; `node record/server-http.cjs <out> <port> sse|json` beside
`node record/client.cjs http http://127.0.0.1:<port>/mcp` or `node record/client.cjs sse http://127.0.0.1:<port>/sse`.
