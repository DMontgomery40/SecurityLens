/* eslint-env jest */
import { handler as scanProgressHandler } from '../netlify/functions/scan-progress.js';
import { handler as scanWebpageHandler } from '../netlify/functions/scan-webpage.js';
import { handler as validateTokenHandler } from '../netlify/functions/validate-token.js';
import {
  SecurityLensError,
  normalizeError,
  toErrorResponseBody
} from '../src/lib/errors.js';

describe('SecurityLensError utilities', () => {
  test('normalizeError preserves request metadata', () => {
    const error = normalizeError(
      new Error('boom'),
      {
        code: 'TEST_ERROR',
        status: 418,
        requestId: 'req-test',
        userMessage: 'Readable message'
      }
    );

    expect(error).toBeInstanceOf(SecurityLensError);
    expect(error.code).toBe('TEST_ERROR');
    expect(error.status).toBe(418);
    expect(error.requestId).toBe('req-test');
    expect(error.userMessage).toBe('Readable message');
  });

  test('toErrorResponseBody hides internal details for non-exposed errors', () => {
    const error = new SecurityLensError('sensitive message', {
      code: 'INTERNAL_ERROR',
      status: 500,
      requestId: 'req-hidden',
      expose: false,
      userMessage: 'safe message'
    });

    expect(toErrorResponseBody(error)).toEqual({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
      requestId: 'req-hidden'
    });
  });
});

describe('Structured Netlify error responses', () => {
  test('scan-progress returns structured error when scanId is missing', async () => {
    const response = await scanProgressHandler({
      httpMethod: 'GET',
      headers: {},
      queryStringParameters: {}
    });

    const body = JSON.parse(response.body);

    expect(response.statusCode).toBe(400);
    expect(body.code).toBe('MISSING_SCAN_ID');
    expect(body.requestId).toMatch(/^req-/);
    expect(response.headers['x-request-id']).toBe(body.requestId);
  });

  test('validate-token returns structured error when token is missing', async () => {
    const response = await validateTokenHandler({
      httpMethod: 'POST',
      headers: {},
      body: JSON.stringify({})
    });

    const body = JSON.parse(response.body);

    expect(response.statusCode).toBe(400);
    expect(body.code).toBe('MISSING_TOKEN');
    expect(body.requestId).toMatch(/^req-/);
  });
  test('scan-webpage returns structured error when url is missing', async () => {
    const response = await scanWebpageHandler({
      httpMethod: 'POST',
      headers: {},
      body: JSON.stringify({})
    });

    const body = JSON.parse(response.body);

    expect(response.statusCode).toBe(400);
    expect(body.code).toBe('MISSING_URL');
    expect(body.requestId).toMatch(/^req-/);
  });

  test.each([
    ['http://127.0.0.1/', 403, 'URL_NOT_ALLOWED'],
    ['http://169.254.169.254/latest/meta-data/', 403, 'URL_NOT_ALLOWED'],
    ['http://[::ffff:127.0.0.1]/', 403, 'URL_NOT_ALLOWED'],
    ['http://10.0.0.1:8080/admin', 403, 'URL_NOT_ALLOWED'],
    ['file:///etc/passwd', 400, 'INVALID_URL'],
    ['http://user:secret@example.com/', 400, 'INVALID_URL']
  ])('scan-webpage refuses to fetch %s', async (url, status, code) => {
    const response = await scanWebpageHandler({
      httpMethod: 'POST',
      headers: {},
      body: JSON.stringify({ url })
    });

    const body = JSON.parse(response.body);

    expect(response.statusCode).toBe(status);
    expect(body.code).toBe(code);
  });
});
