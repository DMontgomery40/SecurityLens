import { Octokit } from '@octokit/rest';
import { decryptToken } from './utils/secureToken.js';
import { checkRateLimit } from './utils/rateLimiter.js';
import VulnerabilityScanner from '../../src/lib/scanner.js';

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
    await checkRateLimit(clientIP);

    // Parse request body
    const { url, secureToken } = JSON.parse(event.body);

    if (!url) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Repository URL is required' })
      };
    }

    // Initialize GitHub client
    let octokit;
    if (secureToken) {
      try {
        const token = await decryptToken(secureToken);
        octokit = new Octokit({
          auth: token,
          userAgent: 'plugin-vulnerability-scanner'
        });
      } catch (error) {
        return {
          statusCode: 401,
          body: JSON.stringify({ error: 'Invalid token' })
        };
      }
    } else {
      octokit = new Octokit({
        userAgent: 'plugin-vulnerability-scanner'
      });
    }

    // Parse GitHub URL
    const urlRegex = /github\.com\/([^/]+)\/([^/]+)(?:\/tree\/([^/]+))?\/?(.*)/;
    const match = url.match(urlRegex);
    
    if (!match) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Invalid GitHub URL format' })
      };
    }

    const [, owner, repo, branch = 'main', path = ''] = match;

    // Fetch repository content
    const scanner = new VulnerabilityScanner({
      octokit,
      enableNewPatterns: true,
      enablePackageScanners: true
    });

    const results = await scanner.fetchRepositoryFiles(url, octokit);

    return {
      statusCode: 200,
      body: JSON.stringify(results)
    };
  } catch (error) {
    console.error('Scan error:', error);

    return {
      statusCode: error.message.includes('Rate limit') ? 429 : 500,
      body: JSON.stringify({ 
        error: error.message || 'An error occurred during scanning'
      })
    };
  }
};