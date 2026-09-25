/* eslint-env node */
import { validateGitHubToken, encryptToken } from './utils/secureToken.js';
import { checkTokenRateLimit } from './utils/rateLimiter.js';
import { SecurityLensError } from '../../src/lib/errors.js';
import {
  createFunctionContext,
  errorResponse,
  jsonResponse,
  methodNotAllowedResponse,
  optionsResponse,
  parseJsonBody
} from './utils/http.js';

export const handler = async (event) => {
  const { headers, logger, requestId } = createFunctionContext('validate-token', event, {
    allowMethods: 'POST, OPTIONS'
  });

  if (event.httpMethod === 'OPTIONS') {
    return optionsResponse(headers);
  }

  // Only allow POST requests
  if (event.httpMethod !== 'POST') {
    return methodNotAllowedResponse(headers);
  }

  try {
    // Get client IP for rate limiting
    const clientIP = event.headers['x-forwarded-for'] || event.headers['client-ip'] || 'unknown';
    
    // Check rate limit
    await checkTokenRateLimit(clientIP);

    // Parse request body
    const { token } = parseJsonBody(event);

    if (!token) {
      throw new SecurityLensError('Token is required', {
        code: 'MISSING_TOKEN',
        status: 400,
        requestId,
        userMessage: 'Token is required'
      });
    }

    // Validate GitHub token
    await validateGitHubToken(token);

    // Encrypt token for client storage
    const encryptedToken = await encryptToken(token);

    logger.info(
      {
        clientIP
      },
      'GitHub token validated'
    );

    return jsonResponse(200, headers, {
      valid: true,
      secureToken: encryptedToken,
      requestId
    });
  } catch (error) {
    return errorResponse(error, headers, logger, 'Token validation failed');
  }
};
