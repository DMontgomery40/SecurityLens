// Report endpoints for the Instruction Security Policy report-to directive.
//   POST /api/reports        create an endpoint and a view key
//   POST /r/:id              agents send reports here
//   GET  /api/reports?id=…   read reports (Authorization: Bearer <view key>)

import { getStore, getDeployStore } from '@netlify/blobs';
import { createReportService, chooseReportStore } from '../../src/lib/isp/node/reports.js';

const MINTS_PER_HOUR = 20;
const SUBMITS_PER_MINUTE = 60;
const buckets = new Map();

function allow(key, limit, windowMs) {
  const now = Date.now();
  const bucket = buckets.get(key);
  if (!bucket || now - bucket.start > windowMs) {
    if (buckets.size > 10000) buckets.clear();
    buckets.set(key, { start: now, count: 1 });
    return true;
  }
  bucket.count += 1;
  return bucket.count <= limit;
}

function deployContextOf(context) {
  return context?.deploy?.context ?? globalThis.Netlify?.context?.deploy?.context ?? null;
}

export default async (req, context) => {
  const { store, scope } = chooseReportStore(deployContextOf(context), { getStore, getDeployStore });
  const json = (body, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-report-store': scope }
    });
  const url = new URL(req.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';
  const service = createReportService({ store });
  const ip = context?.ip || 'unknown';
  const id = context?.params?.id || null;

  try {
    if (path === '/api/reports' && req.method === 'POST') {
      if (!allow(`mint:${ip}`, MINTS_PER_HOUR, 3_600_000)) return json({ error: { code: 'rate-limited', message: 'Too many endpoints created. Try again later.' } }, 429);
      return json(await service.mint({ baseUrl: url.origin }), 201);
    }

    if (path.startsWith('/r/') && req.method === 'POST') {
      if (!allow(`submit:${ip}`, SUBMITS_PER_MINUTE, 60_000)) return json({ error: { code: 'rate-limited', message: 'Too many reports.' } }, 429);
      const result = await service.submit(id, await req.text());
      return result.status === 204 ? new Response(null, { status: 204, headers: { 'x-report-store': scope } }) : json({ error: { code: 'rejected', message: result.error } }, result.status);
    }

    if (path === '/api/reports' && req.method === 'GET') {
      const key = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '').trim();
      const result = await service.list(url.searchParams.get('id'), key);
      return result.status === 200 ? json(result) : json({ error: { code: 'denied', message: result.error } }, result.status);
    }

    return json({ error: { code: 'method-not-allowed', message: 'Unsupported method for this path.' } }, 405);
  } catch (error) {
    console.error('reports failed', error);
    return json({ error: { code: 'storage-failed', message: 'Reports are unavailable right now.' } }, 503);
  }
};

export const config = { path: ['/api/reports', '/r/:id'] };
