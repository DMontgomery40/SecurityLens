import http from 'node:http';
import zlib from 'node:zlib';
import { safeFetch, isBlockedAddress, FetchError } from '../../src/lib/isp/node/safeFetch.js';

describe('isBlockedAddress', () => {
  test.each([
    '127.0.0.1', '127.8.9.10', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254',
    '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '198.18.0.1',
    '::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', 'ff02::1',
    '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:169.254.169.254', '64:ff9b::a9fe:a9fe', '2002:7f00:1::'
  ])('blocks %s', (address) => {
    expect(isBlockedAddress(address)).toBe(true);
  });

  test.each(['93.184.216.34', '8.8.8.8', '172.32.0.1', '2606:4700:4700::1111', '::ffff:8.8.8.8'])('allows %s', (address) => {
    expect(isBlockedAddress(address)).toBe(false);
  });
});

describe('safeFetch URL checks', () => {
  test.each([
    ['ftp://example.com/', 'unsupported-scheme'],
    ['file:///etc/passwd', 'unsupported-scheme'],
    ['http://user:pass@example.com/', 'credentials-in-url'],
    ['http://example.com:22/', 'port-not-allowed'],
    ['not a url', 'invalid-url']
  ])('rejects %s', async (url, code) => {
    await expect(safeFetch(url)).rejects.toMatchObject({ code });
  });

  test.each([
    'http://127.0.0.1/',
    'http://2130706433/',
    'http://0x7f.1/',
    'http://[::1]/',
    'http://[::ffff:127.0.0.1]/',
    'http://169.254.169.254/latest/meta-data/'
  ])('refuses literal private address %s', async (url) => {
    await expect(safeFetch(url)).rejects.toMatchObject({ code: 'blocked-address' });
  });

  test('refuses a hostname that resolves to a private address', async () => {
    const lookup = async () => [{ address: '10.0.0.7', family: 4 }];
    await expect(safeFetch('http://internal.example/', { lookup })).rejects.toMatchObject({ code: 'blocked-address' });
  });

  test('refuses when any resolved address is private', async () => {
    const lookup = async () => [{ address: '93.184.216.34', family: 4 }, { address: '127.0.0.1', family: 4 }];
    await expect(safeFetch('http://mixed.example/', { lookup })).rejects.toMatchObject({ code: 'blocked-address' });
  });
});

describe('safeFetch against a local server', () => {
  let server;
  let port;
  const routes = {
    '/page': (req, res) => {
      res.setHeader('content-type', 'text/html; charset=utf-8');
      res.setHeader('instruction-security-policy', ['untrusted .a', 'voice #b']);
      res.end('<html><body><p>hello</p></body></html>');
    },
    '/gzip': (req, res) => {
      res.setHeader('content-type', 'text/html');
      res.setHeader('content-encoding', 'gzip');
      res.end(zlib.gzipSync('<html><body>compressed page</body></html>'));
    },
    '/latin1': (req, res) => {
      res.setHeader('content-type', 'text/html; charset=iso-8859-1');
      res.end(Buffer.from('<p>caf\xe9</p>', 'latin1'));
    },
    '/redirect-public': (req, res) => {
      res.writeHead(302, { location: '/page' });
      res.end();
    },
    '/redirect-private': (req, res) => {
      res.writeHead(301, { location: `http://internal.example:${port}/page` });
      res.end();
    },
    '/loop': (req, res) => {
      res.writeHead(302, { location: '/loop' });
      res.end();
    },
    '/big': (req, res) => {
      res.setHeader('content-type', 'text/html');
      res.end('x'.repeat(3 * 1024 * 1024));
    },
    '/image': (req, res) => {
      res.setHeader('content-type', 'image/png');
      res.end('png');
    },
    '/slow': () => {}
  };

  // The local server listens on loopback, so the tests treat one fake public
  // hostname as a public address and everything else normally.
  const lookup = async (hostname) => {
    if (hostname === 'public.example') return [{ address: '127.0.0.1', family: 4 }];
    if (hostname === 'internal.example') return [{ address: '10.0.0.9', family: 4 }];
    throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
  };
  const options = () => ({ lookup, isBlocked: (address) => address !== '127.0.0.1' && isBlockedAddress(address), allowedPorts: [port] });

  beforeAll(async () => {
    server = http.createServer((req, res) => (routes[req.url] || ((q, r) => { r.statusCode = 404; r.end(); }))(req, res));
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = server.address().port;
  });
  afterAll(() => new Promise((resolve) => { server.closeAllConnections?.(); server.close(resolve); }));

  test('fetches html and keeps repeated policy headers separate', async () => {
    const result = await safeFetch(`http://public.example:${port}/page`, options());
    expect(result.status).toBe(200);
    expect(result.body).toContain('hello');
    expect(result.headers['instruction-security-policy']).toEqual(['untrusted .a', 'voice #b']);
  });

  test('decompresses gzip', async () => {
    expect((await safeFetch(`http://public.example:${port}/gzip`, options())).body).toContain('compressed page');
  });

  test('decodes the declared charset', async () => {
    expect((await safeFetch(`http://public.example:${port}/latin1`, options())).body).toContain('café');
  });

  test('follows a redirect and reports the final URL', async () => {
    const result = await safeFetch(`http://public.example:${port}/redirect-public`, options());
    expect(result.url).toBe(`http://public.example:${port}/page`);
    expect(result.redirects).toEqual([`http://public.example:${port}/redirect-public`]);
  });

  test('re-checks every redirect hop and refuses a private target', async () => {
    await expect(safeFetch(`http://public.example:${port}/redirect-private`, options())).rejects.toMatchObject({ code: 'blocked-address' });
  });

  test('stops redirect loops', async () => {
    await expect(safeFetch(`http://public.example:${port}/loop`, options())).rejects.toMatchObject({ code: 'too-many-redirects' });
  });

  test('stops reading past the size limit', async () => {
    await expect(safeFetch(`http://public.example:${port}/big`, options())).rejects.toMatchObject({ code: 'too-large' });
  });

  test('rejects content that is not html or text', async () => {
    await expect(safeFetch(`http://public.example:${port}/image`, options())).rejects.toMatchObject({ code: 'unsupported-content-type' });
  });

  test('times out', async () => {
    await expect(safeFetch(`http://public.example:${port}/slow`, { ...options(), timeoutMs: 300 })).rejects.toMatchObject({ code: 'timeout' });
  });

  test('errors are FetchError instances with a status', async () => {
    const error = await safeFetch('ftp://x/').catch((caught) => caught);
    expect(error).toBeInstanceOf(FetchError);
    expect(error.status).toBe(400);
  });
});
