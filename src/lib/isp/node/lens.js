// Fetch a page safely and analyze it. Shared by the API, CLI, and MCP server.

import { safeFetch, FetchError } from './safeFetch.js';
import { analyzeDocument } from '../analyze.js';
import { WELL_KNOWN_PATH } from '../policy.js';

const HTML_TYPES = new Set(['text/html', 'application/xhtml+xml']);

async function fetchWellKnown(origin, fetchOptions) {
  try {
    const result = await safeFetch(`${origin}${WELL_KNOWN_PATH}`, {
      ...fetchOptions,
      maxBytes: 16 * 1024,
      timeoutMs: 4000,
      allowedTypes: ['text/plain']
    });
    return result.status === 200 && result.contentType === 'text/plain' ? result.body.trim() : null;
  } catch {
    return null;
  }
}

export async function lensUrl(url, { fetchOptions = {}, includeWellKnown = true } = {}) {
  let origin = null;
  try {
    origin = new URL(url).origin;
  } catch {
    origin = null;
  }

  const [page, earlyWellKnown] = await Promise.all([
    safeFetch(url, { ...fetchOptions, allowedTypes: [...HTML_TYPES] }),
    includeWellKnown && origin ? fetchWellKnown(origin, fetchOptions) : Promise.resolve(null)
  ]);

  let wellKnown = earlyWellKnown;
  const finalOrigin = new URL(page.url).origin;
  if (includeWellKnown && finalOrigin !== origin) wellKnown = await fetchWellKnown(finalOrigin, fetchOptions);

  const report = analyzeDocument({ html: page.body, url: page.url, headers: page.headers, wellKnown, source: 'server-html' });
  report.fetch = {
    requestedUrl: url,
    finalUrl: page.url,
    status: page.status,
    redirects: page.redirects,
    bytes: page.bytes,
    contentType: page.contentType,
    wellKnown: wellKnown !== null
  };
  return report;
}

export { FetchError };
