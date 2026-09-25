import pino from 'pino';

const isBrowser =
  typeof window !== 'undefined' &&
  typeof window.document !== 'undefined';

const level =
  globalThis.process?.env?.LOG_LEVEL
    ? globalThis.process.env.LOG_LEVEL
    : 'info';

const options = {
  name: 'securitylens',
  level,
  timestamp: pino.stdTimeFunctions.isoTime,
  base: {
    service: 'securitylens',
    runtime: isBrowser ? 'browser' : 'node'
  },
  redact: {
    paths: [
      'token',
      'authorization',
      'headers.authorization',
      'event.headers.authorization',
      'details.token'
    ],
    censor: '[Redacted]'
  },
  serializers: {
    err: pino.stdSerializers.err
  }
};

const destination = isBrowser
  ? undefined
  : pino.destination({
      dest: 2,
      sync: globalThis.process?.env?.NODE_ENV === 'test'
    });

export const rootLogger = isBrowser
  ? pino({
      ...options,
      browser: {
        asObject: true
      }
    })
  : pino(options, destination);

export function createLogger(bindings = {}) {
  return Object.keys(bindings).length > 0
    ? rootLogger.child(bindings)
    : rootLogger;
}

export function withLogContext(logger, bindings = {}) {
  return logger?.child ? logger.child(bindings) : createLogger(bindings);
}

export function createRequestId(prefix = 'req') {
  const uuid =
    typeof globalThis.crypto !== 'undefined' &&
    typeof globalThis.crypto.randomUUID === 'function'
      ? globalThis.crypto.randomUUID()
      : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;

  return `${prefix}-${uuid}`;
}

export function getRequestIdFromHeaders(headers = {}, prefix = 'req') {
  return (
    headers['x-request-id'] ||
    headers['X-Request-Id'] ||
    headers['x-correlation-id'] ||
    createRequestId(prefix)
  );
}
