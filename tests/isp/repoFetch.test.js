import { fetchRepository } from '../../src/lib/isp/node/repoFetch.js';

function fakeGitHub(routes) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), headers: init?.headers || {} });
    const route = routes[String(url)];
    if (!route) return new Response('not found', { status: 404 });
    const { status = 200, body, headers = {} } = typeof route === 'function' ? route() : route;
    return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers: { 'x-ratelimit-remaining': '42', ...headers } });
  };
  return { fetchImpl, calls };
}

const API = 'https://api.github.com/repos/acme/widgets';
const RAW = 'https://raw.githubusercontent.com/acme/widgets/main';

describe('fetchRepository', () => {
  test('collects instruction files, configs, open issues, and recent comments', async () => {
    const { fetchImpl, calls } = fakeGitHub({
      [API]: { body: { default_branch: 'main', html_url: 'https://github.com/acme/widgets', private: false } },
      [`${API}/git/trees/main?recursive=1`]: {
        body: { truncated: false, tree: [{ path: 'AGENTS.md', type: 'blob', size: 40 }, { path: '.mcp.json', type: 'blob', size: 30 }, { path: 'src/index.js', type: 'blob', size: 10 }, { path: 'docs', type: 'tree' }] }
      },
      [`${RAW}/AGENTS.md`]: { body: 'Run npm test before committing.' },
      [`${RAW}/.mcp.json`]: { body: '{"mcpServers":{}}' },
      [`${API}/issues?state=open&sort=updated&per_page=30`]: {
        body: [
          { number: 3, title: 'Bug', body: 'It breaks', html_url: 'https://github.com/acme/widgets/issues/3', user: { login: 'dev' } },
          { number: 4, title: 'Fix', body: 'Patch', html_url: 'https://github.com/acme/widgets/pull/4', user: { login: 'dev2' }, pull_request: {} }
        ]
      },
      [`${API}/issues/comments?sort=updated&direction=desc&per_page=60`]: {
        body: [{ body: 'Thanks!', html_url: 'https://github.com/acme/widgets/issues/3#issuecomment-1', issue_url: `${API}/issues/3`, user: { login: 'dev3' } }]
      }
    });

    const result = await fetchRepository({ owner: 'acme', repo: 'widgets' }, { fetchImpl, token: 'ghp_test' });
    expect(result.repo).toEqual({ owner: 'acme', name: 'widgets', defaultBranch: 'main', url: 'https://github.com/acme/widgets' });
    expect(result.files.map((file) => file.path)).toEqual(['.mcp.json', 'AGENTS.md']);
    expect(result.issues.map((issue) => [issue.number, issue.isPullRequest])).toEqual([[3, false], [4, true]]);
    expect(result.comments[0]).toMatchObject({ issueNumber: 3, author: 'dev3' });
    expect(result.coverage).toMatchObject({ treeTruncated: false, rateLimitRemaining: 42, filesRead: 2 });
    expect(calls.find((call) => call.url.startsWith(API)).headers.authorization).toBe('Bearer ghp_test');
    expect(calls.some((call) => call.url.startsWith(RAW) && call.headers.authorization)).toBe(false);
  });

  test('turns a rate limit into a clear error', async () => {
    const { fetchImpl } = fakeGitHub({ [API]: { status: 403, body: { message: 'API rate limit exceeded' }, headers: { 'x-ratelimit-remaining': '0' } } });
    await expect(fetchRepository({ owner: 'acme', repo: 'widgets' }, { fetchImpl })).rejects.toMatchObject({ code: 'github-rate-limited', status: 429 });
  });

  test('reports a missing or private repository', async () => {
    const { fetchImpl } = fakeGitHub({});
    await expect(fetchRepository({ owner: 'acme', repo: 'widgets' }, { fetchImpl })).rejects.toMatchObject({ code: 'github-not-found', status: 404 });
  });

  test('skips oversized files and caps how many it reads', async () => {
    const tree = Array.from({ length: 50 }, (_, index) => ({ path: `pkg${index}/AGENTS.md`, type: 'blob', size: 10 }));
    tree.push({ path: 'huge/CLAUDE.md', type: 'blob', size: 5_000_000 });
    const routes = {
      [API]: { body: { default_branch: 'main', html_url: 'https://github.com/acme/widgets' } },
      [`${API}/git/trees/main?recursive=1`]: { body: { truncated: true, tree } },
      [`${API}/issues?state=open&sort=updated&per_page=30`]: { body: [] },
      [`${API}/issues/comments?sort=updated&direction=desc&per_page=60`]: { body: [] }
    };
    for (let index = 0; index < 50; index += 1) routes[`${RAW}/pkg${index}/AGENTS.md`] = { body: 'ok' };
    const { fetchImpl } = fakeGitHub(routes);
    const result = await fetchRepository({ owner: 'acme', repo: 'widgets' }, { fetchImpl, maxFiles: 25 });
    expect(result.files).toHaveLength(25);
    expect(result.coverage).toMatchObject({ treeTruncated: true, filesMatched: 51, filesRead: 25, filesSkippedTooLarge: 1 });
  });
});
