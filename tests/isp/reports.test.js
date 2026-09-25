import { createReportService, chooseReportStore, MAX_REPORTS_PER_ENDPOINT } from '../../src/lib/isp/node/reports.js';

function memoryStore() {
  const data = new Map();
  return {
    data,
    async get(key, options) {
      if (!data.has(key)) return null;
      return options?.type === 'json' ? JSON.parse(data.get(key)) : data.get(key);
    },
    async setJSON(key, value) {
      data.set(key, JSON.stringify(value));
    },
    async list({ prefix } = {}) {
      return { blobs: [...data.keys()].filter((key) => key.startsWith(prefix || '')).sort().map((key) => ({ key, etag: '1' })), directories: [] };
    }
  };
}

describe('report endpoints', () => {
  let store;
  let service;
  let clock;

  beforeEach(() => {
    store = memoryStore();
    clock = Date.parse('2026-09-25T17:00:00Z');
    service = createReportService({ store, now: () => clock });
  });

  test('minting returns an endpoint and a separate view key, and stores only a hash of the key', async () => {
    const minted = await service.mint({ baseUrl: 'https://securitylens.io' });
    expect(minted.endpoint).toMatch(/^https:\/\/securitylens\.io\/r\/[a-z2-7]{12}$/);
    expect(minted.viewUrl).toBe(`https://securitylens.io/reports/${minted.id}#key=${minted.key}`);
    expect(minted.key.length).toBeGreaterThanOrEqual(32);
    const stored = [...store.data.values()].join('');
    expect(stored).not.toContain(minted.key);
  });

  test('accepts a spec report, trims it to known fields, and lists newest first', async () => {
    const { id, key } = await service.mint({ baseUrl: 'https://securitylens.io' });
    const first = await service.submit(id, JSON.stringify({ type: 'isp-violation', documentURL: 'https://blog.test/1', zone: 'untrusted', rule: 'instruction-override', excerpt: 'x'.repeat(900), secret: 'drop me' }));
    clock += 1000;
    await service.submit(id, JSON.stringify({ type: 'isp-violation', documentURL: 'https://blog.test/2', excerpt: 'second' }));
    expect(first.status).toBe(204);

    const listed = await service.list(id, key);
    expect(listed.status).toBe(200);
    expect(listed.reports.map((report) => report.documentURL)).toEqual(['https://blog.test/2', 'https://blog.test/1']);
    expect(listed.reports[1].excerpt).toHaveLength(512);
    expect(listed.reports[1].secret).toBeUndefined();
    expect(listed.reports[1].receivedAt).toBe('2026-09-25T17:00:00.000Z');
  });

  test('accepts the Reporting API array format', async () => {
    const { id, key } = await service.mint({ baseUrl: 'https://securitylens.io' });
    const result = await service.submit(id, JSON.stringify([{ type: 'isp-violation', url: 'https://blog.test/3', body: { rule: 'role-marker', excerpt: 'fake system tag' } }]));
    expect(result.status).toBe(204);
    expect((await service.list(id, key)).reports[0]).toMatchObject({ documentURL: 'https://blog.test/3', rule: 'role-marker' });
  });

  test.each([
    ['a wrong key', (minted) => service.list(minted.id, 'wrong-key'), 401],
    ['a missing key', (minted) => service.list(minted.id, ''), 401],
    ['an unknown endpoint', () => service.list('aaaaaaaaaaaa', 'key'), 404]
  ])('refuses to list with %s', async (_label, call, status) => {
    const minted = await service.mint({ baseUrl: 'https://securitylens.io' });
    expect((await call(minted)).status).toBe(status);
  });

  test.each([
    ['unknown endpoint', 'bbbbbbbbbbbb', '{"excerpt":"x"}', 404],
    ['malformed id', '../../etc', '{"excerpt":"x"}', 404],
    ['invalid JSON', null, '{nope', 400],
    ['empty report', null, '{}', 400],
    ['oversized body', null, JSON.stringify({ excerpt: 'x'.repeat(20000) }), 413]
  ])('rejects a submission to an %s', async (_label, idOverride, body, status) => {
    const { id } = await service.mint({ baseUrl: 'https://securitylens.io' });
    expect((await service.submit(idOverride || id, body)).status).toBe(status);
  });

  test('stops accepting reports at the per-endpoint cap', async () => {
    const { id } = await service.mint({ baseUrl: 'https://securitylens.io' });
    const record = await store.get(`endpoints/${id}`, { type: 'json' });
    await store.setJSON(`endpoints/${id}`, { ...record, count: MAX_REPORTS_PER_ENDPOINT });
    expect((await service.submit(id, '{"excerpt":"one more"}')).status).toBe(429);
  });
});

describe('chooseReportStore', () => {
  const factories = { getStore: (name) => `global:${name}`, getDeployStore: (name) => `deploy:${name}` };

  test('production uses the site-wide store', () => {
    expect(chooseReportStore('production', factories)).toEqual({ store: 'global:isp-reports', scope: 'global' });
  });

  test.each(['deploy-preview', 'branch-deploy', 'dev', 'draft', undefined, null, ''])('%s uses a deploy-scoped store', (context) => {
    expect(chooseReportStore(context, factories)).toEqual({ store: 'deploy:isp-reports', scope: 'deploy' });
  });
});
