// Report endpoints for the report-to directive. An endpoint id goes in the
// public policy; a separate view key, stored only as a hash, reads reports.

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export const MAX_REPORTS_PER_ENDPOINT = 1000;
export const MAX_REPORT_BYTES = 8 * 1024;
const LIST_LIMIT = 200;
const ID_PATTERN = /^[a-z2-7]{12}$/;
const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567';
const FIELDS = { type: 60, documentURL: 2048, zone: 40, selector: 300, rule: 80, excerpt: 512, disposition: 60, agent: 200, timestamp: 60 };

function base32(bytes) {
  return [...bytes].map((byte) => BASE32[byte % 32]).join('');
}

function hashKey(key) {
  return createHash('sha256').update(String(key)).digest('hex');
}

function sameHash(a, b) {
  const left = Buffer.from(a, 'hex');
  const right = Buffer.from(b, 'hex');
  return left.length === right.length && timingSafeEqual(left, right);
}

function normalizeReport(raw, receivedAt) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const source = raw.body && typeof raw.body === 'object' ? { ...raw.body, type: raw.body.type || raw.type, documentURL: raw.body.documentURL || raw.url } : raw;
  const report = {};
  for (const [field, limit] of Object.entries(FIELDS)) {
    if (typeof source[field] === 'string' && source[field].trim()) report[field] = source[field].slice(0, limit);
  }
  if (!report.documentURL && !report.excerpt && !report.rule) return null;
  report.receivedAt = receivedAt;
  return report;
}

export function createReportService({ store, now = () => Date.now(), random = randomBytes }) {
  const endpointKey = (id) => `endpoints/${id}`;

  return {
    async mint({ baseUrl }) {
      const id = base32(random(12));
      const key = random(24).toString('base64url');
      await store.setJSON(endpointKey(id), { keyHash: hashKey(key), createdAt: new Date(now()).toISOString(), count: 0 });
      const origin = String(baseUrl).replace(/\/$/, '');
      return { id, key, endpoint: `${origin}/r/${id}`, viewUrl: `${origin}/reports/${id}#key=${key}` };
    },

    async submit(id, bodyText) {
      if (!ID_PATTERN.test(String(id))) return { status: 404, error: 'Unknown report endpoint.' };
      if (String(bodyText || '').length > MAX_REPORT_BYTES) return { status: 413, error: 'Reports must be 8 KB or smaller.' };

      const record = await store.get(endpointKey(id), { type: 'json' });
      if (!record) return { status: 404, error: 'Unknown report endpoint.' };
      if (record.count >= MAX_REPORTS_PER_ENDPOINT) return { status: 429, error: 'This endpoint has reached its report limit.' };

      let parsed;
      try {
        parsed = JSON.parse(bodyText);
      } catch {
        return { status: 400, error: 'Reports must be JSON.' };
      }

      const receivedAt = new Date(now()).toISOString();
      const reports = (Array.isArray(parsed) ? parsed.slice(0, 20) : [parsed]).map((item) => normalizeReport(item, receivedAt)).filter(Boolean);
      if (reports.length === 0) return { status: 400, error: 'The report has none of the expected fields.' };

      const order = String(9_999_999_999_999 - now()).padStart(13, '0');
      await Promise.all(reports.map((report, index) => store.setJSON(`reports/${id}/${order}-${index}-${base32(random(4))}`, report)));
      await store.setJSON(endpointKey(id), { ...record, count: record.count + reports.length, lastReportAt: receivedAt });
      return { status: 204 };
    },

    async list(id, key) {
      if (!ID_PATTERN.test(String(id))) return { status: 404, error: 'Unknown report endpoint.' };
      const record = await store.get(endpointKey(id), { type: 'json' });
      if (!record) return { status: 404, error: 'Unknown report endpoint.' };
      if (!key) return { status: 401, error: 'A view key is required.' };
      if (!sameHash(hashKey(key), record.keyHash)) return { status: 401, error: 'That view key does not match this endpoint.' };

      const { blobs } = await store.list({ prefix: `reports/${id}/` });
      const keys = blobs.map((blob) => blob.key).sort().slice(0, LIST_LIMIT);
      const reports = (await Promise.all(keys.map((blobKey) => store.get(blobKey, { type: 'json' })))).filter(Boolean);
      return { status: 200, reports, total: record.count, createdAt: record.createdAt };
    }
  };
}

// Production reports live in the site-wide store so endpoints survive new
// deploys. Every other context (previews, drafts, branch deploys, local dev)
// gets a deploy-scoped store so test data never reaches production.
export function chooseReportStore(deployContext, { getStore, getDeployStore }, name = 'isp-reports') {
  return deployContext === 'production' ? { store: getStore(name), scope: 'global' } : { store: getDeployStore(name), scope: 'deploy' };
}
