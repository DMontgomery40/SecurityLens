import { Octokit } from '@octokit/rest';
import { RepositoryCrawler } from '../../src/lib/RepositoryCrawler.js';
import { FileScanner } from '../../src/lib/FileScanner.js';
import { ReportBuilder } from '../../src/lib/ReportBuilder.js';
import { authManager } from '../../src/lib/githubAuth.js';


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

      // Set up authentication for modular components
      authManager.setToken(token);
      
      // Initialize modular components with concurrency control
      const rawConcurrency = parseInt(process.env.SCANNER_CONCURRENCY) || 10;
      const concurrency = Math.min(Math.max(rawConcurrency, 1), 50); // Clamp between 1-50
      const repositoryCrawler = new RepositoryCrawler({ concurrency });
      const fileScanner = new FileScanner({
        enableNewPatterns: true,
        enablePackageScanners: true
      });
      const reportBuilder = new ReportBuilder();

      // Construct GitHub URL for the crawler
      const githubUrl = `https://github.com/${owner}/${repo}`;
      const fullUrl = branch !== 'main' ? `${githubUrl}/tree/${branch}` : githubUrl;
      const scanUrl = path ? `${fullUrl}/${path}` : fullUrl;
      
      console.log(`Scanning repository: ${scanUrl}`);
      
      // Use RepositoryCrawler to get files with timeout handling
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Scan timeout - repository too large for Netlify function')), 25000);
      });
      
      const scanPromise = (async () => {
        // Get files using the modular crawler
        const { files, rateLimit: rateLimitInfo, fromCache } = await repositoryCrawler.getFiles(scanUrl, token, false);
        
        console.log(`Retrieved ${files.length} files from repository${fromCache ? ' (cached)' : ''}`);
        
        // Scan files using FileScanner
        let allFindings = [];
        let processedFiles = 0;
        
        for (const file of files) {
          try {
            const fileFindings = await fileScanner.scanFile(file.content, file.path);
            if (fileFindings && fileFindings.length > 0) {
              allFindings.push(...fileFindings);
            }
            processedFiles++;
            
            // Progress logging for large repositories
            if (processedFiles % 50 === 0) {
              console.log(`Processed ${processedFiles}/${files.length} files...`);
            }
          } catch (error) {
            console.error(`Error scanning file ${file.path}:`, error.message);
          }
        }
        
        console.log(`Scan complete: ${allFindings.length} findings in ${processedFiles} files`);
        
        return { allFindings, rateLimitInfo, fromCache, filesProcessed: processedFiles };
      })();
      
      // Race between scan and timeout
      const { allFindings, rateLimitInfo, fromCache, filesProcessed } = await Promise.race([
        scanPromise,
        timeoutPromise
      ]);
      
      // Generate report using ReportBuilder
      const report = reportBuilder.generateReport(allFindings, { 
        rateLimit: rateLimitInfo, 
        fromCache,
        filesProcessed 
      });
      
      // Add recommendations
      const recommendations = reportBuilder.generateRecommendations(allFindings);

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          findings: report.findings,
          summary: report.summary,
          recommendations,
          rateLimit: rateLimitInfo || rateLimit.data.rate,
          fromCache,
          filesProcessed
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
