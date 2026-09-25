// Public lens API: GET /api/lens?url=… or POST { url } / { html, url }.
// view=report (default) returns the full analysis, view=agent the agent
// view, view=policy a generated policy. format=text returns plain text.

import { lensUrl, FetchError } from '../../src/lib/isp/node/lens.js';
import { analyzeDocument } from '../../src/lib/isp/analyze.js';
import { toAgentView } from '../../src/lib/isp/agentView.js';
import { generatePolicy } from '../../src/lib/isp/generate.js';

const MAX_HTML_BYTES = 2 * 1024 * 1024;
const WINDOW_MS = 60_000;
const LIMIT_PER_WINDOW = 30;
const buckets = new Map();

function allowRequest(key) {
  const now = Date.now();
  const bucket = buckets.get(key);
  if (!bucket || now - bucket.start > WINDOW_MS) {
    buckets.set(key, { start: now, count: 1 });
    if (buckets.size > 5000) buckets.clear();
    return true;
  }
  bucket.count += 1;
  return bucket.count <= LIMIT_PER_WINDOW;
}

function json(body, status = 200, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extra }
  });
}

function problem(code, message, status) {
  return json({ error: { code, message } }, status);
}

async function readInput(req) {
  if (req.method === 'GET') {
    const params = new URL(req.url).searchParams;
    return { url: params.get('url'), html: null, view: params.get('view'), format: params.get('format') };
  }

  const text = await req.text();
  if (text.length > MAX_HTML_BYTES + 4096) throw new FetchError('too-large', 'The request body is larger than 2 MB.', 413);
  let body;
  try {
    body = JSON.parse(text || '{}');
  } catch {
    throw new FetchError('invalid-json', 'The request body must be JSON.', 400);
  }
  const params = new URL(req.url).searchParams;
  return {
    url: typeof body.url === 'string' ? body.url : null,
    html: typeof body.html === 'string' ? body.html : null,
    headers: body.headers && typeof body.headers === 'object' ? body.headers : {},
    view: body.view || params.get('view'),
    format: body.format || params.get('format')
  };
}

function render(report, view, format) {
  if (view === 'agent') {
    const agentView = toAgentView(report);
    if (format === 'text') return new Response(agentView.text, { headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' } });
    return json(agentView);
  }
  if (view === 'policy') return json(generatePolicy(report));
  return json(report);
}

export default async (req, context) => {
  if (req.method !== 'GET' && req.method !== 'POST') {
    return problem('method-not-allowed', 'Use GET or POST.', 405);
  }

  if (!allowRequest(context?.ip || 'unknown')) {
    return problem('rate-limited', 'Too many requests. Try again in a minute.', 429);
  }

  try {
    const input = await readInput(req);

    if (input.html !== null) {
      if (input.html.length > MAX_HTML_BYTES) return problem('too-large', 'HTML must be 2 MB or smaller.', 413);
      const report = analyzeDocument({ html: input.html, url: input.url || null, headers: input.headers, source: 'submitted-html' });
      return render(report, input.view, input.format);
    }

    if (!input.url) return problem('missing-url', 'Provide a url, or html to analyze.', 400);
    const report = await lensUrl(input.url);
    return render(report, input.view, input.format);
  } catch (error) {
    if (error instanceof FetchError) return problem(error.code, error.message, error.status || 502);
    console.error('lens failed', error);
    return problem('analysis-failed', 'The page could not be analyzed.', 500);
  }
};

export const config = { path: '/api/lens' };
