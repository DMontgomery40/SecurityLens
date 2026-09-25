// Remote MCP endpoint: Streamable HTTP in stateless JSON mode at /mcp.
// Each request gets a fresh server and transport; there are no sessions.

import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { createLensMcpServer } from '../../src/lib/isp/node/mcpServer.js';

const WINDOW_MS = 60_000;
const LIMIT_PER_WINDOW = 60;
const buckets = new Map();

function allowRequest(key) {
  const now = Date.now();
  const bucket = buckets.get(key);
  if (!bucket || now - bucket.start > WINDOW_MS) {
    if (buckets.size > 5000) buckets.clear();
    buckets.set(key, { start: now, count: 1 });
    return true;
  }
  bucket.count += 1;
  return bucket.count <= LIMIT_PER_WINDOW;
}

function jsonRpcError(status, code, message) {
  return new Response(JSON.stringify({ jsonrpc: '2.0', error: { code, message }, id: null }), {
    status,
    headers: { 'content-type': 'application/json' }
  });
}

export default async (req, context) => {
  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: 'This server is stateless. Send JSON-RPC requests with POST.' }, id: null }), {
      status: 405,
      headers: { 'content-type': 'application/json', allow: 'POST' }
    });
  }

  if (!allowRequest(context?.ip || 'unknown')) {
    return jsonRpcError(429, -32000, 'Too many requests. Try again in a minute.');
  }

  const server = createLensMcpServer({ githubToken: globalThis.Netlify?.env?.get?.('GITHUB_TOKEN') || null });
  const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });

  try {
    await server.connect(transport);
    return await transport.handleRequest(req);
  } catch (error) {
    console.error('mcp request failed', error);
    return jsonRpcError(500, -32603, 'Internal error.');
  } finally {
    await transport.close().catch(() => {});
    await server.close().catch(() => {});
  }
};

export const config = { path: '/mcp' };
