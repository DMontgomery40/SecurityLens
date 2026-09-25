// Server-side page fetcher that refuses to reach private networks.
// Resolves DNS itself, checks every address, pins the connection to the
// checked address, and re-checks every redirect hop. Node only.

import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import dns from 'node:dns';
import zlib from 'node:zlib';

export class FetchError extends Error {
  constructor(code, message, status) {
    super(message);
    this.name = 'FetchError';
    this.code = code;
    this.status = status;
  }
}

const STATUS = {
  'invalid-url': 400,
  'unsupported-scheme': 400,
  'credentials-in-url': 400,
  'port-not-allowed': 400,
  'blocked-address': 403,
  'dns-failure': 502,
  'connection-failed': 502,
  'too-many-redirects': 502,
  'too-large': 413,
  'unsupported-content-type': 415,
  timeout: 504
};

const fail = (code, message) => new FetchError(code, message, STATUS[code] || 500);

const blockList = new net.BlockList();
for (const [network, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
]) {
  blockList.addSubnet(network, prefix, 'ipv4');
}
for (const [network, prefix] of [
  ['::', 96], ['64:ff9b:1::', 48], ['100::', 64], ['2001::', 23], ['2001:db8::', 32], ['fc00::', 7], ['fe80::', 10],
  ['fec0::', 10], ['ff00::', 8]
]) {
  blockList.addSubnet(network, prefix, 'ipv6');
}

// Expand an IPv6 address into eight 16-bit groups.
function ipv6Groups(address) {
  let value = address.toLowerCase().split('%')[0];
  const dotted = value.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) {
    const octets = dotted[1].split('.').map(Number);
    value = `${value.slice(0, -dotted[1].length)}${((octets[0] << 8) | octets[1]).toString(16)}:${((octets[2] << 8) | octets[3]).toString(16)}`;
  }
  const [head, tail] = value.split('::');
  const headGroups = head ? head.split(':') : [];
  const tailGroups = tail !== undefined && tail !== '' ? tail.split(':') : [];
  const missing = tail === undefined ? 0 : 8 - headGroups.length - tailGroups.length;
  return [...headGroups, ...Array(missing).fill('0'), ...tailGroups].map((group) => Number.parseInt(group || '0', 16));
}

function ipv4FromGroups(high, low) {
  return [high >> 8, high & 0xff, low >> 8, low & 0xff].join('.');
}

// IPv4 addresses embedded in IPv6 forms that route to the IPv4 network.
function embeddedIpv4(groups) {
  const isMapped = groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff;
  const isNat64 = groups[0] === 0x64 && groups[1] === 0xff9b && groups.slice(2, 6).every((group) => group === 0);
  if (isMapped || isNat64) return ipv4FromGroups(groups[6], groups[7]);
  if (groups[0] === 0x2002) return ipv4FromGroups(groups[1], groups[2]);
  return null;
}

export function isBlockedAddress(address) {
  const version = net.isIP(address);
  if (version === 4) return blockList.check(address, 'ipv4');
  if (version !== 6) return true;

  const groups = ipv6Groups(address);
  const embedded = embeddedIpv4(groups);
  if (embedded) return blockList.check(embedded, 'ipv4');
  const canonical = groups.map((group) => group.toString(16)).join(':');
  return blockList.check(canonical, 'ipv6');
}

const DEFAULTS = {
  timeoutMs: 10000,
  maxBytes: 2 * 1024 * 1024,
  maxRedirects: 5,
  allowedPorts: [80, 443, 8080, 8443],
  allowedTypes: ['text/html', 'application/xhtml+xml', 'text/plain'],
  accept: 'text/html,application/xhtml+xml;q=0.9,text/plain;q=0.8',
  userAgent: 'SecurityLens/2.0 (+https://securitylens.io/agents)'
};

function checkUrl(input, options) {
  let url;
  try {
    url = new URL(String(input).trim());
  } catch {
    throw fail('invalid-url', 'Enter a full URL, starting with https://');
  }
  if (!['http:', 'https:'].includes(url.protocol)) throw fail('unsupported-scheme', 'Only http and https URLs can be fetched.');
  if (url.username || url.password) throw fail('credentials-in-url', 'URLs with embedded credentials are not fetched.');
  const port = Number(url.port || (url.protocol === 'https:' ? 443 : 80));
  if (!options.allowedPorts.includes(port)) throw fail('port-not-allowed', `Port ${port} is not allowed.`);
  return url;
}

async function defaultLookup(hostname) {
  return dns.promises.lookup(hostname, { all: true, verbatim: true });
}

async function resolveHost(url, options) {
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  let addresses;
  if (net.isIP(hostname)) {
    addresses = [{ address: hostname, family: net.isIP(hostname) }];
  } else {
    try {
      addresses = await (options.lookup || defaultLookup)(hostname);
    } catch {
      throw fail('dns-failure', `Could not resolve ${hostname}.`);
    }
  }
  if (!addresses?.length) throw fail('dns-failure', `Could not resolve ${hostname}.`);
  const isBlocked = options.isBlocked || isBlockedAddress;
  if (addresses.some(({ address }) => isBlocked(address))) {
    throw fail('blocked-address', `${hostname} points to a private or reserved network address.`);
  }
  return { hostname, ...addresses[0] };
}

function detectCharset(contentType, head) {
  const declared = /charset=["']?([\w-]+)/i.exec(contentType || '');
  if (declared) return declared[1].toLowerCase();
  const meta = /<meta[^>]+charset=["']?([\w-]+)/i.exec(head);
  return meta ? meta[1].toLowerCase() : 'utf-8';
}

function decode(buffer, charset) {
  try {
    return new TextDecoder(charset, { fatal: false }).decode(buffer);
  } catch {
    return new TextDecoder('utf-8', { fatal: false }).decode(buffer);
  }
}

function request(url, target, options, deadline) {
  return new Promise((resolve, reject) => {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      reject(fail('timeout', 'The page took too long to respond.'));
      return;
    }

    const client = url.protocol === 'https:' ? https : http;
    const req = client.request(
      {
        protocol: url.protocol,
        hostname: target.hostname,
        port: url.port || undefined,
        path: `${url.pathname}${url.search}`,
        method: 'GET',
        servername: net.isIP(target.hostname) ? undefined : target.hostname,
        headers: { accept: options.accept, 'accept-encoding': 'gzip, deflate, br', 'user-agent': options.userAgent },
        lookup: (_hostname, lookupOptions, callback) => {
          if (lookupOptions?.all) callback(null, [{ address: target.address, family: target.family }]);
          else callback(null, target.address, target.family);
        }
      },
      (response) => {
        clearTimeout(timer);
        resolve({ response, abort: () => req.destroy() });
      }
    );

    const timer = setTimeout(() => {
      req.destroy(fail('timeout', 'The page took too long to respond.'));
    }, remaining);

    req.on('error', (error) => {
      clearTimeout(timer);
      reject(error instanceof FetchError ? error : fail('connection-failed', `Could not connect: ${error.code || error.message}`));
    });
    req.end();
  });
}

function readBody(response, abort, options, deadline) {
  return new Promise((resolve, reject) => {
    const encoding = (response.headers['content-encoding'] || '').toLowerCase();
    let stream = response;
    if (encoding === 'gzip' || encoding === 'x-gzip') stream = response.pipe(zlib.createGunzip());
    else if (encoding === 'deflate') stream = response.pipe(zlib.createInflate());
    else if (encoding === 'br') stream = response.pipe(zlib.createBrotliDecompress());

    const chunks = [];
    let size = 0;
    const timer = setTimeout(() => {
      abort();
      reject(fail('timeout', 'The page took too long to respond.'));
    }, Math.max(1, deadline - Date.now()));

    stream.on('data', (chunk) => {
      size += chunk.length;
      if (size > options.maxBytes) {
        clearTimeout(timer);
        abort();
        stream.destroy();
        reject(fail('too-large', `The page is larger than ${Math.round(options.maxBytes / 1024 / 1024)} MB.`));
        return;
      }
      chunks.push(chunk);
    });
    stream.on('end', () => {
      clearTimeout(timer);
      resolve(Buffer.concat(chunks));
    });
    stream.on('error', () => {
      clearTimeout(timer);
      reject(fail('connection-failed', 'The response could not be read.'));
    });
  });
}

function collectHeaders(response) {
  const headers = {};
  const distinct = response.headersDistinct || {};
  for (const [name, value] of Object.entries(response.headers)) headers[name] = value;
  const policy = distinct['instruction-security-policy'];
  if (policy) headers['instruction-security-policy'] = policy.length > 1 ? policy : policy[0];
  return headers;
}

export async function safeFetch(input, overrides = {}) {
  const options = { ...DEFAULTS, ...overrides };
  const deadline = Date.now() + options.timeoutMs;
  const redirects = [];
  let url = checkUrl(input, options);

  for (let hop = 0; ; hop += 1) {
    const target = await resolveHost(url, options);
    const { response, abort } = await request(url, target, options, deadline);
    const status = response.statusCode || 0;

    if ([301, 302, 303, 307, 308].includes(status) && response.headers.location) {
      abort();
      if (hop >= options.maxRedirects) throw fail('too-many-redirects', 'The page redirected too many times.');
      redirects.push(url.href);
      url = checkUrl(new URL(response.headers.location, url).href, options);
      continue;
    }

    const contentType = response.headers['content-type'] || '';
    const mediaType = contentType.split(';')[0].trim().toLowerCase();
    if (mediaType && !options.allowedTypes.includes(mediaType)) {
      abort();
      throw fail('unsupported-content-type', `The URL returned ${mediaType}, not a web page.`);
    }

    const buffer = await readBody(response, abort, options, deadline);
    const charset = detectCharset(contentType, buffer.subarray(0, 1024).toString('latin1'));

    return {
      url: url.href,
      status,
      headers: collectHeaders(response),
      contentType: mediaType || null,
      body: decode(buffer, charset),
      bytes: buffer.length,
      redirects,
      address: target.address
    };
  }
}
