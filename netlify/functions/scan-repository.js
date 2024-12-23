const { Octokit } = require('@octokit/rest');
const VulnerabilityScanner = require('../../src/lib/scanner').default;

exports.handler = async (event) => {
  // Only allow POST requests
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const { url } = JSON.parse(event.body);

    if (!url) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Repository URL is required' })
      };
    }

    // Initialize GitHub client (without token for now)
    const octokit = new Octokit({
      userAgent: 'plugin-vulnerability-scanner'
    });

    // Parse GitHub URL
    const githubRegex = /github\.com\/([^/]+)\/([^/]+)(?:\/tree\/([^/]+))?\/?(.*)/;
    const match = url.match(githubRegex);
    
    if (!match) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Invalid GitHub URL format' })
      };
    }

    const [, owner, repo, branch = 'main', path = ''] = match;

    try {
      // First check rate limit
      const rateLimit = await octokit.rateLimit.get();
      console.log('Rate limit:', rateLimit.data.rate);

      if (rateLimit.data.rate.remaining === 0) {
        return {
          statusCode: 429,
          body: JSON.stringify({
            error: 'Rate limit exceeded',
            resetAt: new Date(rateLimit.data.rate.reset * 1000).toISOString()
          })
        };
      }

      // Initialize scanner
      const scanner = new VulnerabilityScanner({
        enableNewPatterns: true,
        enablePackageScanners: true,
        octokit
      });

      // Get repository contents and scan them
      const { data: contents } = await octokit.repos.getContent({
        owner,
        repo,
        path,
        ref: branch
      });

      // Process files
      const files = Array.isArray(contents) ? contents : [contents];
      let allFindings = [];

      for (const file of files) {
        if (file.type === 'file') {
          try {
            const { data: content } = await octokit.repos.getContent({
              owner,
              repo,
              path: file.path,
              ref: branch,
              mediaType: {
                format: 'raw'
              }
            });

            const fileContent = Buffer.from(content, 'base64').toString('utf8');
            const findings = await scanner.scanFile(fileContent, file.path);
            allFindings.push(...findings);
          } catch (error) {
            console.error(`Error scanning file ${file.path}:`, error);
          }
        }
      }

      // Generate report
      const report = scanner.generateReport(allFindings);

      return {
        statusCode: 200,
        body: JSON.stringify({
          files: files.map(f => ({
            name: f.name,
            path: f.path,
            type: f.type,
            size: f.size
          })),
          findings: allFindings,
          summary: report.summary,
          rateLimit: rateLimit.data.rate
        })
      };

    } catch (error) {
      if (error.status === 403) {
        return {
          statusCode: 403,
          body: JSON.stringify({
            error: 'Access denied or rate limit exceeded. Try again later.'
          })
        };
      }
      if (error.status === 404) {
        return {
          statusCode: 404,
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
      body: JSON.stringify({
        error: 'Internal server error',
        details: error.message
      })
    };
  }
};