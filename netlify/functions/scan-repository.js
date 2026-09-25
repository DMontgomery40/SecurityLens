/* eslint-env node */
import { Octokit } from '@octokit/rest';
import { RepositoryCrawler } from '../../src/lib/RepositoryCrawler.js';
import { FileScanner } from '../../src/lib/FileScanner.js';
import { ReportBuilder } from '../../src/lib/ReportBuilder.js';
import { authManager } from '../../src/lib/githubAuth.js';
import {
  SecurityLensError,
  getErrorMetadata,
  normalizeError
} from '../../src/lib/errors.js';
import {
  createFunctionContext,
  errorResponse,
  jsonResponse,
  methodNotAllowedResponse,
  optionsResponse,
  parseJsonBody
} from './utils/http.js';

function getConcurrency() {
  const rawConcurrency = Number.parseInt(globalThis.process?.env?.SCANNER_CONCURRENCY || '10', 10);

  if (!Number.isFinite(rawConcurrency) || rawConcurrency < 1) {
    return 10;
  }

  return Math.min(rawConcurrency, 50);
}

function mapRepositoryError(error, requestId) {
  if (error instanceof SecurityLensError) {
    return normalizeError(error, { requestId });
  }

  if (error?.status === 401) {
    return new SecurityLensError('Invalid GitHub token. Please check your token and try again.', {
      code: 'AUTH_FAILED',
      status: 401,
      requestId,
      userMessage: 'Invalid GitHub token. Please check your token and try again.'
    });
  }

  if (error?.status === 403) {
    return new SecurityLensError('Access denied or rate limit exceeded. Try again later.', {
      code: 'RATE_LIMITED',
      status: 403,
      requestId,
      userMessage: 'Access denied or rate limit exceeded. Try again later.'
    });
  }

  if (error?.status === 404) {
    return new SecurityLensError('Repository or path not found. Please check the URL.', {
      code: 'REPO_NOT_FOUND',
      status: 404,
      requestId,
      userMessage: 'Repository or path not found. Please check the URL.'
    });
  }

  return normalizeError(error, {
    code: 'REPOSITORY_SCAN_FAILED',
    status: error?.status || 500,
    message: 'Repository scan failed',
    requestId,
    userMessage: 'Repository scan failed',
    expose: false
  });
}

export const handler = async (event) => {
  const { headers, logger, requestId } = createFunctionContext('scan-repository', event, {
    allowHeaders: 'Content-Type, Authorization'
  });

  if (event.httpMethod === 'OPTIONS') {
    return optionsResponse(headers);
  }

  if (event.httpMethod !== 'POST') {
    return methodNotAllowedResponse(headers);
  }

  try {
    const { url } = parseJsonBody(event);

    if (!url) {
      throw new SecurityLensError('Repository URL is required', {
        code: 'MISSING_REPOSITORY_URL',
        status: 400,
        requestId,
        userMessage: 'Repository URL is required'
      });
    }

    const token = event.headers.authorization?.replace(/^Bearer\s+/i, '');

    if (!token) {
      throw new SecurityLensError('GitHub token is required', {
        code: 'MISSING_TOKEN',
        status: 401,
        requestId,
        userMessage: 'GitHub token is required'
      });
    }

    const octokit = new Octokit({
      auth: token,
      userAgent: 'security-lens-scanner',
      baseUrl: 'https://api.github.com',
      request: {
        timeout: 25000
      }
    });

    await octokit.rest.users.getAuthenticated();
    const rateLimit = await octokit.rest.rateLimit.get();

    if (rateLimit.data.rate.remaining === 0) {
      throw new SecurityLensError('Rate limit exceeded', {
        code: 'RATE_LIMITED',
        status: 429,
        requestId,
        userMessage: 'Rate limit exceeded',
        details: {
          resetAt: new Date(rateLimit.data.rate.reset * 1000).toISOString()
        }
      });
    }

    authManager.setToken(token);

    const concurrency = getConcurrency();
    const repositoryCrawler = new RepositoryCrawler({
      concurrency,
      logger
    });
    const fileScanner = new FileScanner({
      enableNewPatterns: true,
      enablePackageScanners: true,
      logger
    });
    const reportBuilder = new ReportBuilder();
    const { owner, repo, branch, path } = repositoryCrawler.parseGitHubUrl(url);

    logger.info(
      {
        repository: `${owner}/${repo}`,
        branch,
        path: path || '/',
        concurrency
      },
      'Starting repository scan'
    );

    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => {
        reject(
          new SecurityLensError('Scan timeout - repository too large for Netlify function', {
            code: 'SCAN_TIMEOUT',
            status: 408,
            requestId,
            userMessage: 'Repository scan timed out. Try a smaller path or try again.'
          })
        );
      }, 25000);
    });

    const scanPromise = (async () => {
      const { files, fromCache, partial, scanStats, errors } = await repositoryCrawler.getFiles(
        token,
        owner,
        repo,
        branch,
        path,
        (progress) => {
          if (
            progress.current === 0 ||
            progress.current === progress.total ||
            progress.current % 50 === 0
          ) {
            logger.debug(
              {
                phase: progress.phase,
                current: progress.current,
                total: progress.total,
                details: progress.details
              },
              'Repository fetch progress'
            );
          }
        }
      );

      const allFindings = [];
      let processedFiles = 0;

      for (const file of files) {
        try {
          const fileFindings = await fileScanner.scanFile(file.content, file.path);
          if (fileFindings.length > 0) {
            allFindings.push(...fileFindings);
          }
        } catch (error) {
          logger.warn(
            {
              ...getErrorMetadata(
                normalizeError(error, {
                  code: 'REPOSITORY_FILE_ANALYSIS_FAILED',
                  status: 500,
                  message: `Failed to scan ${file.path}`,
                  requestId,
                  details: {
                    filePath: file.path
                  },
                  expose: false
                })
              )
            },
            'Continuing after repository file analysis failure'
          );
        } finally {
          processedFiles += 1;

          if (processedFiles === files.length || processedFiles % 50 === 0) {
            logger.debug(
              {
                processedFiles,
                totalFiles: files.length
              },
              'Repository analysis progress'
            );
          }
        }
      }

      return {
        allFindings,
        files,
        fromCache,
        partial,
        scanStats,
        errors,
        processedFiles
      };
    })();

    const { allFindings, fromCache, partial, scanStats, errors, processedFiles } =
      await Promise.race([scanPromise, timeoutPromise]);

    const report = reportBuilder.generateReport(allFindings, {
      rateLimit: repositoryCrawler.rateLimitInfo || rateLimit.data.rate,
      fromCache
    });

    const recommendations = reportBuilder.generateRecommendations(allFindings);

    logger.info(
      {
        repository: `${owner}/${repo}`,
        findings: report.summary.totalIssues,
        filesProcessed: processedFiles,
        partial: partial || false,
        fromCache
      },
      'Repository scan completed'
    );

    return jsonResponse(200, headers, {
      findings: report.findings,
      summary: report.summary,
      recommendations,
      rateLimit: repositoryCrawler.rateLimitInfo || rateLimit.data.rate,
      fromCache,
      filesProcessed: processedFiles,
      partial: partial || false,
      scanStats: scanStats || null,
      fetchErrors: errors || [],
      requestId
    });
  } catch (error) {
    return errorResponse(mapRepositoryError(error, requestId), headers, logger);
  }
};
