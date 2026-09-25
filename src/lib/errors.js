export class SecurityLensError extends Error {
  constructor(
    message,
    {
      code = 'INTERNAL_ERROR',
      status = 500,
      details = {},
      requestId = undefined,
      userMessage = message,
      expose = status < 500,
      cause = undefined
    } = {}
  ) {
    super(message, cause ? { cause } : undefined);
    this.name = 'SecurityLensError';
    this.code = code;
    this.status = status;
    this.details = details;
    this.requestId = requestId ?? details.requestId;
    this.userMessage = userMessage;
    this.expose = expose;
  }
}

export function isSecurityLensError(error) {
  return error instanceof SecurityLensError;
}

export function normalizeError(error, fallback = {}) {
  if (isSecurityLensError(error)) {
    if (
      fallback.requestId &&
      !error.requestId
    ) {
      error.requestId = fallback.requestId;
    }

    if (
      fallback.details &&
      Object.keys(fallback.details).length > 0
    ) {
      error.details = {
        ...fallback.details,
        ...error.details
      };
    }

    return error;
  }

  const message =
    error instanceof Error && error.message
      ? error.message
      : fallback.message || 'Unexpected error';

  const status =
    fallback.status ||
    (typeof error === 'object' && error?.status) ||
    500;

  const code =
    fallback.code ||
    (typeof error === 'object' && error?.code) ||
    'INTERNAL_ERROR';

  const details = {
    ...(fallback.details || {}),
    ...(typeof error === 'object' && error?.details ? error.details : {})
  };

  if (!(error instanceof Error) && error !== undefined) {
    details.originalValue = error;
  }

  return new SecurityLensError(message, {
    code,
    status,
    details,
    requestId:
      fallback.requestId ||
      (typeof error === 'object' && error?.requestId) ||
      details.requestId,
    userMessage: fallback.userMessage || message,
    expose:
      fallback.expose !== undefined ? fallback.expose : status < 500,
    cause: error instanceof Error ? error : undefined
  });
}

export function getUserFacingMessage(
  error,
  fallbackMessage = 'Something went wrong. Please try again.'
) {
  const normalized = normalizeError(error, {
    message: fallbackMessage,
    userMessage: fallbackMessage
  });

  return normalized.userMessage || fallbackMessage;
}

export function getErrorMetadata(error) {
  const normalized = normalizeError(error);

  return {
    err: normalized,
    errorCode: normalized.code,
    status: normalized.status,
    requestId: normalized.requestId,
    details: normalized.details
  };
}

export function toErrorResponseBody(error, fallbackMessage = 'Internal server error') {
  const normalized = normalizeError(error, {
    message: fallbackMessage,
    userMessage: fallbackMessage
  });

  return {
    error: normalized.expose ? normalized.userMessage : fallbackMessage,
    code: normalized.code,
    requestId: normalized.requestId
  };
}
