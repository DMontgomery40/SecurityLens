import { validateGitHubToken, encryptToken } from './utils/secureToken.js';
import { checkTokenRateLimit } from './utils/rateLimiter.js';

export const handler = async (event, context) => {
  // Only allow POST requests
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    // Get client IP for rate limiting
    const clientIP = event.headers['x-forwarded-for'] || event.headers['client-ip'];
    
    // Check rate limit
    await checkTokenRateLimit(clientIP);

    // Parse request body
    const { token } = JSON.parse(event.body);

    if (!token) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Token is required' })
      };
    }

    // Validate GitHub token
    await validateGitHubToken(token);

    // Encrypt token for client storage
    const encryptedToken = await encryptToken(token);

    return {
      statusCode: 200,
      body: JSON.stringify({
        valid: true,
        secureToken: encryptedToken
      })
    };
  } catch (error) {
    return {
      statusCode: error.message.includes('Rate limit') ? 429 : 400,
      body: JSON.stringify({ error: error.message })
    };
  }
};