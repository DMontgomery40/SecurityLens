import { SecurityLensError, getErrorMetadata, normalizeError } from './errors.js';
import { fetchWithTimeout, parseJsonResponse } from './http.js';
import { authManager } from './githubAuth.js';
import { createLogger, createRequestId, withLogContext } from './logger.js';

export class ApiError extends SecurityLensError {
  constructor(message, status, options = {}) {
    super(message, {
      code: options.code || 'API_ERROR',
      status,
      details: options.details || {},
      requestId: options.requestId,
      userMessage: options.userMessage || message,
      expose: status < 500,
      cause: options.cause
    });
    this.name = 'ApiError';
  }
}

const logger = createLogger({
  component: 'apiClient'
});

async function requestJson(
  path,
  {
    body,
    headers = {},
    timeoutMs = 25000,
    requestId = createRequestId(),
    errorMessage = 'Request failed'
  } = {}
) {
  const requestLogger = withLogContext(logger, {
    requestId,
    path
  });

  requestLogger.info(
    {
      method: 'POST'
    },
    'Starting API request'
  );

  const response = await fetchWithTimeout(path, {
    method: 'POST',
    timeoutMs,
    headers: {
      'Content-Type': 'application/json',
      'x-request-id': requestId,
      ...headers
    },
    body: JSON.stringify(body)
  });

  const data = await parseJsonResponse(response);

  if (!response.ok) {
    const apiError = new ApiError(
      data?.error || `${errorMessage} (${response.status})`,
      response.status,
      {
        code: data?.code || 'API_REQUEST_FAILED',
        requestId: data?.requestId || requestId,
        details: {
          path,
          body: data
        }
      }
    );

    requestLogger.warn(
      {
        status: response.status,
        errorCode: apiError.code,
        serverRequestId: data?.requestId || requestId
      },
      'API request failed'
    );

    throw apiError;
  }

  requestLogger.info(
    {
      status: response.status
    },
    'API request completed'
  );

  return data;
}

export const scanWebPage = async (url, options = {}) => {
  try {
    return await requestJson('/.netlify/functions/scan-webpage', {
      body: { url },
      requestId: options.requestId,
      errorMessage: 'Website scan failed'
    });
  } catch (error) {
    const normalized = normalizeError(error, {
      code: error?.code || 'WEBPAGE_SCAN_REQUEST_FAILED',
      status: error?.status || 500,
      message: 'Website scan request failed',
      requestId: error?.requestId || options.requestId,
      userMessage: error?.userMessage || error?.message || 'Website scan failed'
    });

    logger.error(getErrorMetadata(normalized), 'Website scan request failed');
    throw normalized;
  }
};

export async function scanRepository(url, options = {}) {
  try {
    const token = authManager.getToken();
    if (!token) {
      throw new ApiError('GitHub token is required', 401, {
        code: 'MISSING_TOKEN',
        requestId: options.requestId
      });
    }

    return await requestJson('/.netlify/functions/scan-repository', {
      body: { url },
      requestId: options.requestId,
      headers: {
        Authorization: `Bearer ${token}`
      },
      errorMessage: 'Repository scan failed'
    });
  } catch (error) {
    const normalized = normalizeError(error, {
      code: error?.code || 'REPOSITORY_SCAN_REQUEST_FAILED',
      status: error?.status || 500,
      message: 'Repository scan request failed',
      requestId: error?.requestId || options.requestId,
      userMessage: error?.userMessage || error?.message || 'Repository scan failed'
    });

    logger.error(getErrorMetadata(normalized), 'Repository scan request failed');
    throw normalized;
  }
}
