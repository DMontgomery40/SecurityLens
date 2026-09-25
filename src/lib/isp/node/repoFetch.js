// Fetch what an agent working in a GitHub repository would read: agent
// instruction files, agent configuration, open issues and pull requests, and
// recent comments. Only api.github.com and raw.githubusercontent.com are
// contacted, so no user-supplied host is ever fetched.

import { FetchError } from './safeFetch.js';
import { classifyPath } from '../repo.js';

const API = 'https://api.github.com';
const RAW = 'https://raw.githubusercontent.com';
const MAX_FILE_BYTES = 256 * 1024;
const TIMEOUT_MS = 8000;

async function request(fetchImpl, url, headers) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    return await fetchImpl(url, { headers, signal: controller.signal });
  } catch (error) {
    throw new FetchError(error?.name === 'AbortError' ? 'timeout' : 'connection-failed', 'GitHub did not respond in time.', 504);
  } finally {
    clearTimeout(timer);
  }
}

function encodePath(path) {
  return path.split('/').map(encodeURIComponent).join('/');
}

export async function fetchRepository({ owner, repo }, { token = null, fetchImpl = globalThis.fetch, maxFiles = 30, maxIssues = 30, maxComments = 60 } = {}) {
  const apiHeaders = {
    accept: 'application/vnd.github+json',
    'x-github-api-version': '2022-11-28',
    'user-agent': 'SecurityLens/2.0 (+https://securitylens.io/agents)',
    ...(token ? { authorization: `Bearer ${token}` } : {})
  };
  let rateLimitRemaining = null;

  async function api(path) {
    const response = await request(fetchImpl, `${API}${path}`, apiHeaders);
    const remaining = response.headers.get('x-ratelimit-remaining');
    if (remaining !== null) rateLimitRemaining = Number(remaining);
    if ((response.status === 403 || response.status === 429) && (remaining === '0' || response.status === 429)) {
      throw new FetchError('github-rate-limited', 'GitHub’s rate limit for unauthenticated requests is used up. Add a GitHub token and try again.', 429);
    }
    if (response.status === 404) throw new FetchError('github-not-found', `github.com/${owner}/${repo} was not found, or it is private.`, 404);
    if (!response.ok) throw new FetchError('github-error', `GitHub returned HTTP ${response.status}.`, 502);
    return response.json();
  }

  const base = `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
  const meta = await api(base);
  const branch = meta.default_branch || 'main';
  const [tree, issues, comments] = await Promise.all([
    api(`${base}/git/trees/${encodeURIComponent(branch)}?recursive=1`),
    api(`${base}/issues?state=open&sort=updated&per_page=${maxIssues}`),
    api(`${base}/issues/comments?sort=updated&direction=desc&per_page=${maxComments}`)
  ]);

  const matched = (tree.tree || []).filter((entry) => entry.type === 'blob' && classifyPath(entry.path));
  const readable = matched.filter((entry) => (entry.size || 0) <= MAX_FILE_BYTES);
  const selected = readable
    .sort((a, b) => a.path.split('/').length - b.path.split('/').length || a.path.localeCompare(b.path))
    .slice(0, maxFiles);

  const files = (
    await Promise.all(
      selected.map(async (entry) => {
        const response = await request(fetchImpl, `${RAW}/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${encodeURIComponent(branch)}/${encodePath(entry.path)}`, {
          'user-agent': apiHeaders['user-agent']
        });
        if (!response.ok) return null;
        const text = await response.text();
        return { path: entry.path, text: text.slice(0, MAX_FILE_BYTES) };
      })
    )
  ).filter(Boolean);

  const order = new Map(selected.map((entry, index) => [entry.path, index]));
  files.sort((a, b) => order.get(a.path) - order.get(b.path));

  return {
    repo: { owner, name: repo, defaultBranch: branch, url: meta.html_url || `https://github.com/${owner}/${repo}` },
    files,
    issues: (Array.isArray(issues) ? issues : []).map((issue) => ({
      number: issue.number,
      title: issue.title || '',
      body: issue.body || '',
      url: issue.html_url,
      isPullRequest: Boolean(issue.pull_request),
      author: issue.user?.login || null
    })),
    comments: (Array.isArray(comments) ? comments : []).map((comment) => ({
      issueNumber: Number(String(comment.issue_url || '').split('/').pop()) || null,
      body: comment.body || '',
      url: comment.html_url,
      author: comment.user?.login || null
    })),
    coverage: {
      treeTruncated: Boolean(tree.truncated),
      filesMatched: matched.length,
      filesRead: files.length,
      filesSkippedTooLarge: matched.length - readable.length,
      issuesRead: Array.isArray(issues) ? issues.length : 0,
      commentsRead: Array.isArray(comments) ? comments.length : 0,
      rateLimitRemaining,
      authenticated: Boolean(token)
    }
  };
}
