import { Octokit } from '@octokit/rest';
import VulnerabilityScanner from '../../src/lib/scanner.js';


export const handler = async (event, context) => {
  // Enable CORS
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'POST, OPTIONS'
  };

  // Handle preflight requests
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 204,
      headers
    };
  }

  // Only allow POST requests
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const { url } = JSON.parse(event.body);

    if (!url) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Repository URL is required' })
      };
    }

    // Extract GitHub token from headers
    const token = event.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: 'GitHub token is required' })
      };
    }

    // Initialize GitHub client with token
    const octokit = new Octokit({
      auth: token,
      userAgent: 'security-lens-scanner',
      baseUrl: 'https://api.github.com',
      request: {
        timeout: 25000
      }
    });

    // Parse GitHub URL - handle both /blob/ and /tree/ paths
    const githubRegex = /github\.com\/([^/]+)\/([^/]+)(?:\/(?:blob|tree)\/([^/]+))?\/?(.*)/;
    const match = url.match(githubRegex);
    
    if (!match) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Invalid GitHub URL format' })
      };
    }

    const [, owner, repo, branch = 'main', path = ''] = match;

    try {
      // First verify the token works by getting the authenticated user
      await octokit.rest.users.getAuthenticated();

      // Then check rate limit
      const rateLimit = await octokit.rest.rateLimit.get();
      console.log('Rate limit:', rateLimit.data.rate);

      if (rateLimit.data.rate.remaining === 0) {
        return {
          statusCode: 429,
          headers,
          body: JSON.stringify({
            error: 'Rate limit exceeded',
            resetAt: new Date(rateLimit.data.rate.reset * 1000).toISOString()
          })
        };
      }

      // Initialize scanner
      const scannerInstance = new VulnerabilityScanner({
        enableNewPatterns: true,
        enablePackageScanners: true,
        octokit
      });

      // Recursive function to scan directory contents
      async function scanDirectory(currentPath) {
        const { data: contents } = await octokit.rest.repos.getContent({
          owner,
          repo,
          path: currentPath,
          ref: branch
        });

        const files = Array.isArray(contents) ? contents : [contents];
        let findings = [];

        for (const item of files) {
          try {
            if (item.type === 'dir') {
              // Recursively scan subdirectories
              const subFindings = await scanDirectory(item.path);
              findings.push(...subFindings);
            } else if (item.type === 'file') {
              // Skip large files and binary files
              if (item.size > 1024 * 1024) { // Skip files larger than 1MB
                console.log(`Skipping large file: ${item.path} (${item.size} bytes)`);
                continue;
              }

              // Check if file is likely binary based on path
              const binaryExtensions = /\.(jpg|jpeg|png|gif|ico|pdf|zip|tar|gz|bin|exe|dll)$/i;
              if (binaryExtensions.test(item.path)) {
                console.log(`Skipping binary file: ${item.path}`);
                continue;
              }

              const { data: content } = await octokit.rest.repos.getContent({
                owner,
                repo,
                path: item.path,
                ref: branch,
                mediaType: {
                  format: 'raw'
                }
              });

              const fileContent = typeof content === 'string' ? content : Buffer.from(content).toString('utf8');
              const fileFindings = await scannerInstance.scanFile(fileContent, item.path);
              findings.push(...fileFindings);
            }
          } catch (error) {
            console.error(`Error processing ${item.path}:`, error);
          }
        }
        return findings;
      }

      // Start recursive scan from the initial path
      const allFindings = await scanDirectory(path);

      // Process findings to match client-side data structure
      const processedFindings = allFindings.reduce((acc, finding) => {
        const key = finding.type;
        if (!acc[key]) {
          acc[key] = {
            type: finding.type,
            severity: finding.severity || 'LOW',
            description: finding.description || 'No description provided',
            allLineNumbers: { [finding.file]: finding.lineNumbers || [] }
          };
        } else {
          // Merge line numbers if same type
          const file = finding.file;
          if (!acc[key].allLineNumbers[file]) {
            acc[key].allLineNumbers[file] = finding.lineNumbers || [];
          } else {
            const merged = new Set([...acc[key].allLineNumbers[file], ...finding.lineNumbers]);
            acc[key].allLineNumbers[file] = Array.from(merged).sort((a, b) => a - b);
          }
        }
        return acc;
      }, {});

      // Generate report
      const report = scannerInstance.generateReport(allFindings);

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          findings: processedFindings,
          summary: report.summary,
          rateLimit: rateLimit.data.rate
        })
      };

    } catch (error) {
      console.error('GitHub API error:', error);
      
      if (error.status === 401) {
        return {
          statusCode: 401,
          headers,
          body: JSON.stringify({
            error: 'Invalid GitHub token. Please check your token and try again.'
          })
        };
      }
      if (error.status === 403) {
        return {
          statusCode: 403,
          headers,
          body: JSON.stringify({
            error: 'Access denied or rate limit exceeded. Try again later.'
          })
        };
      }
      if (error.status === 404) {
        return {
          statusCode: 404,
          headers,
          body: JSON.stringify({
            error: 'Repository or path not found. Please check the URL.'
          })
        };
      }
      throw error;
    }
  } catch (error) {
    console.error('Scan error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        error: 'Internal server error',
        details: error.message
      })
    };
  }
};
