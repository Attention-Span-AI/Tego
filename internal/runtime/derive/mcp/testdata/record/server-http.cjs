// SPDX-License-Identifier: Apache-2.0
// Serves the streamable transport at /mcp and the HTTP+SSE one at /sse + /messages, recording every request
// (method, path, content-type, body) and its response (status, content-type, body) as JSON lines in argv[2].
const http = require('http'); const fs = require('fs'); const c = require('./common.cjs');
const { StreamableHTTPServerTransport } = c.r('@modelcontextprotocol/sdk/server/streamableHttp.js');
const { SSEServerTransport } = c.r('@modelcontextprotocol/sdk/server/sse.js');
const log = (o) => fs.appendFileSync(process.argv[2], JSON.stringify(o) + '\n');
const st = new StreamableHTTPServerTransport({ sessionIdGenerator: () => 'sess-1', enableJsonResponse: process.argv[4] === 'json' });
c.makeServer().connect(st);
const sse = {};
http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (b) => chunks.push(b));
  req.on('end', async () => {
    const body = Buffer.concat(chunks);
    const rec = { method: req.method, path: req.url, content_type: req.headers['content-type'] || '', body: body.toString('utf8') };
    const w = res.write.bind(res), e = res.end.bind(res); const out = [];
    res.write = (b, ...a) => { if (b) out.push(Buffer.from(b)); return w(b, ...a); };
    res.end = (b, ...a) => { if (b && typeof b !== 'function') out.push(Buffer.from(b)); log({ request: rec, status: res.statusCode, response_type: res.getHeader('content-type') || '', response: Buffer.concat(out).toString('utf8') }); return e(b, ...a); };
    const parsed = body.length ? JSON.parse(body.toString('utf8')) : undefined;
    if (req.url.startsWith('/mcp')) return st.handleRequest(req, res, parsed);
    if (req.url === '/sse') { const t = new SSEServerTransport('/messages', res); sse[t.sessionId] = t; await c.makeServer().connect(t); return; }
    if (req.url.startsWith('/messages')) { const id = new URL(req.url, 'http://x').searchParams.get('sessionId'); return sse[id].handlePostMessage(req, res, parsed); }
    res.statusCode = 404; res.end();
  });
}).listen(Number(process.argv[3]), '127.0.0.1');
