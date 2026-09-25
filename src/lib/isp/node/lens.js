// Fetch a page safely and analyze it. Shared by the API, CLI, and MCP server.

import { safeFetch, FetchError } from './safeFetch.js';
import { analyzeDocument } from '../analyze.js';
import { WELL_KNOWN_PATH } from '../policy.js';
import { analyzeRepository, parseGitHubRepoUrl } from '../repo.js';
import { fetchRepository } from './repoFetch.js';

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

export async function lensUrl(url, { fetchOptions = {}, includeWellKnown = true, policyOverride = null } = {}) {
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

  const headers = typeof policyOverride === 'string' ? { ...page.headers, 'instruction-security-policy': policyOverride } : page.headers;
  const report = analyzeDocument({ html: page.body, url: page.url, headers, wellKnown, source: 'server-html' });
  report.fetch = {
    requestedUrl: url,
    finalUrl: page.url,
    status: page.status,
    redirects: page.redirects,
    bytes: page.bytes,
    contentType: page.contentType,
    wellKnown: wellKnown !== null,
    policyOverride: typeof policyOverride === 'string'
  };
  return report;
}

export function isRepositoryUrl(url) {
  return parseGitHubRepoUrl(url) !== null;
}

export async function lensRepository(url, { token = null, fetchImpl } = {}) {
  const target = parseGitHubRepoUrl(url);
  if (!target) throw new FetchError('invalid-url', 'Enter a repository URL such as https://github.com/owner/name.', 400);
  const fetched = await fetchRepository(target, { token, ...(fetchImpl ? { fetchImpl } : {}) });
  return analyzeRepository(fetched);
}

export { FetchError };
