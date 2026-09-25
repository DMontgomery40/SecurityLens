import { normalizeError, toErrorResponseBody } from '../../../src/lib/errors.js';
import { createLogger, getRequestIdFromHeaders } from '../../../src/lib/logger.js';

export function createFunctionContext(functionName, event, options = {}) {
  const requestId = getRequestIdFromHeaders(event?.headers || {});
  const logger = createLogger({
    scope: 'netlify-function',
    functionName,
    requestId
  });

  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': options.allowHeaders || 'Content-Type',
    'Access-Control-Allow-Methods': options.allowMethods || 'POST, OPTIONS',
    'x-request-id': requestId,
    ...(options.headers || {})
  };

  return {
    requestId,
    logger,
    headers
  };
}

export function jsonResponse(statusCode, headers, body) {
  return {
    statusCode,
    headers,
    body: body === undefined ? '' : JSON.stringify(body)
  };
}

export function optionsResponse(headers) {
  return {
    statusCode: 204,
    headers
  };
}

export function methodNotAllowedResponse(headers) {
  return jsonResponse(405, headers, {
    error: 'Method not allowed',
    code: 'METHOD_NOT_ALLOWED'
  });
}

export function parseJsonBody(event) {
  try {
    return JSON.parse(event?.body || '{}');
  } catch (error) {
    throw normalizeError(error, {
      code: 'INVALID_JSON_BODY',
      status: 400,
      message: 'Request body must be valid JSON',
      userMessage: 'Request body must be valid JSON'
    });
  }
}

export function errorResponse(error, headers, logger, fallbackMessage = 'Internal server error') {
  const normalized = normalizeError(error, {
    message: fallbackMessage,
    userMessage: fallbackMessage
  });

  if (logger) {
    logger.error(
      {
        err: normalized,
        errorCode: normalized.code,
        status: normalized.status,
        requestId: normalized.requestId,
        details: normalized.details
      },
      'Function request failed'
    );
  }

  return jsonResponse(
    normalized.status || 500,
    headers,
    toErrorResponseBody(normalized, fallbackMessage)
  );
}
