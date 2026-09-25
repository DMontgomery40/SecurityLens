import { SecurityLensError, normalizeError } from './errors.js';

function composeSignal(signal, timeoutSignal) {
  if (!signal) {
    return timeoutSignal;
  }

  if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.any === 'function') {
    return AbortSignal.any([signal, timeoutSignal]);
  }

  return timeoutSignal;
}

export async function fetchWithTimeout(
  url,
  { timeoutMs = 10000, fetchImpl = fetch, signal, ...options } = {}
) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetchImpl(url, {
      ...options,
      signal: composeSignal(signal, controller.signal)
    });
  } catch (error) {
    if (error?.name === 'AbortError') {
      throw new SecurityLensError('Request timed out', {
        code: 'REQUEST_TIMEOUT',
        status: 408,
        details: {
          url,
          timeoutMs
        },
        userMessage: 'Request timed out. Please try again.',
        cause: error
      });
    }

    throw normalizeError(error, {
      code: 'NETWORK_ERROR',
      status: 502,
      message: 'Network request failed',
      userMessage: 'Network request failed. Please try again.',
      details: {
        url
      }
    });
  } finally {
    clearTimeout(timer);
  }
}

export async function parseJsonResponse(response) {
  const text = await response.text();

  if (!text) {
    return null;
  }

  try {
    return JSON.parse(text);
  } catch (error) {
    throw new SecurityLensError('Response body was not valid JSON', {
      code: 'INVALID_JSON_RESPONSE',
      status: 502,
      details: {
        status: response.status,
        preview: text.slice(0, 200)
      },
      userMessage: 'Received an invalid response from the server.',
      cause: error
    });
  }
}
