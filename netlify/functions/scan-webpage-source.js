/* eslint-env node */
import { safeFetch, FetchError } from '../../src/lib/isp/node/safeFetch.js';
import * as cheerio from 'cheerio';
import { FileScanner } from '../../src/lib/FileScanner.js';
import { ReportBuilder } from '../../src/lib/ReportBuilder.js';
import { SecurityLensError, getErrorMetadata, normalizeError } from '../../src/lib/errors.js';
import {
  createFunctionContext,
  errorResponse,
  jsonResponse,
  methodNotAllowedResponse,
  optionsResponse,
  parseJsonBody
} from './utils/http.js';

function getScriptConcurrency() {
  const rawConcurrency = Number.parseInt(
    globalThis.process?.env?.WEBPAGE_SCRIPT_CONCURRENCY || '5',
    10
  );

  if (!Number.isFinite(rawConcurrency) || rawConcurrency < 1) {
    return 5;
  }

  return Math.min(rawConcurrency, 20);
}

const SCRIPT_TYPES = [
  'application/javascript',
  'text/javascript',
  'application/x-javascript',
  'application/ecmascript',
  'text/ecmascript',
  'text/plain'
];

const FETCH_ERROR_CODES = {
  'blocked-address': ['URL_NOT_ALLOWED', 403],
  'invalid-url': ['INVALID_URL', 400],
  'unsupported-scheme': ['INVALID_URL', 400],
  'credentials-in-url': ['INVALID_URL', 400],
  'port-not-allowed': ['INVALID_URL', 400],
  'dns-failure': ['URL_UNREACHABLE', 400],
  'connection-failed': ['URL_UNREACHABLE', 400],
  'too-many-redirects': ['URL_UNREACHABLE', 400],
  timeout: ['SCAN_TIMEOUT', 408],
  'too-large': ['PAGE_TOO_LARGE', 413],
  'unsupported-content-type': ['NOT_A_WEB_PAGE', 415]
};

function mapWebpageError(error, requestId) {
  if (error instanceof SecurityLensError) {
    return normalizeError(error, { requestId });
  }

  if (error instanceof FetchError) {
    const [code, status] = FETCH_ERROR_CODES[error.code] || ['URL_UNREACHABLE', 400];
    return new SecurityLensError(error.message, {
      code,
      status,
      requestId,
      userMessage: error.message
    });
  }

  if (error?.code === 'ENOTFOUND' || error?.code === 'ECONNREFUSED') {
    return new SecurityLensError('Cannot reach the specified URL', {
      code: 'URL_UNREACHABLE',
      status: 400,
      requestId,
      userMessage: 'Cannot reach the specified URL'
    });
  }

  if (error?.code === 'ECONNABORTED') {
    return new SecurityLensError('Webpage scan timeout - webpage too complex or has too many scripts', {
      code: 'SCAN_TIMEOUT',
      status: 408,
      requestId,
      userMessage: 'Webpage scan timed out. Please try again.'
    });
  }

  return normalizeError(error, {
    code: 'WEBPAGE_SCAN_FAILED',
    status: error?.status || 500,
    message: 'Webpage scan failed',
    requestId,
    userMessage: 'Webpage scan failed',
    expose: false
  });
}

export const handler = async (event) => {
  const { headers, logger, requestId } = createFunctionContext('scan-webpage', event);

  if (event.httpMethod === 'OPTIONS') {
    return optionsResponse(headers);
  }

  if (event.httpMethod !== 'POST') {
    return methodNotAllowedResponse(headers);
  }

  try {
    const { url } = parseJsonBody(event);

    if (!url) {
      throw new SecurityLensError('No URL provided', {
        code: 'MISSING_URL',
        status: 400,
        requestId,
        userMessage: 'No URL provided'
      });
    }

    logger.info(
      {
        sourceUrl: url
      },
      'Starting webpage scan'
    );

    const response = await safeFetch(url, {
      timeoutMs: 10000,
      maxBytes: 1024 * 1024,
      allowedTypes: ['text/html', 'application/xhtml+xml']
    });

    const html = response.body;
    const $ = cheerio.load(html);
    const scripts = [];

    $('script').each((index, element) => {
      const src = $(element).attr('src');
      if (src) {
        scripts.push({ type: 'external', src });
      } else {
        scripts.push({ type: 'inline', content: $(element).html() || '' });
      }
    });

    const fileScanner = new FileScanner({
      enableNewPatterns: true,
      enablePackageScanners: true,
      logger
    });
    const reportBuilder = new ReportBuilder();
    const scriptContents = [
      {
        filename: 'page.html',
        content: html
      }
    ];
    const maxConcurrentScripts = getScriptConcurrency();

    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => {
        reject(
          new SecurityLensError('Webpage scan timeout - too many scripts or large content', {
            code: 'SCAN_TIMEOUT',
            status: 408,
            requestId,
            userMessage: 'Webpage scan timed out. Please try again.'
          })
        );
      }, 25000);
    });

    const scanPromise = (async () => {
      for (let index = 0; index < scripts.length; index += maxConcurrentScripts) {
        const batch = scripts.slice(index, index + maxConcurrentScripts);
        const batchResults = await Promise.all(
          batch.map(async (script, scriptIndex) => {
            if (script.type === 'inline') {
              return {
                filename: `inline-script-${index + scriptIndex}`,
                content: script.content
              };
            }

            try {
              const absoluteUrl = new URL(script.src, response.url).href;
              const scriptResponse = await safeFetch(absoluteUrl, {
                timeoutMs: 5000,
                maxBytes: 1024 * 1024,
                allowedTypes: SCRIPT_TYPES
              });

              return {
                filename: absoluteUrl,
                content: scriptResponse.body
              };
            } catch (error) {
              logger.warn(
                {
                  ...getErrorMetadata(
                    normalizeError(error, {
                      code: 'SCRIPT_FETCH_FAILED',
                      status: error?.response?.status || 502,
                      message: `Failed to fetch script ${script.src}`,
                      requestId,
                      details: {
                        scriptSource: script.src
                      },
                      expose: false
                    })
                  )
                },
                'Skipping external script fetch failure'
              );

              return null;
            }
          })
        );

        scriptContents.push(...batchResults.filter(Boolean));
      }

      const allFindings = [];
      let scannedCount = 0;

      for (const { filename, content } of scriptContents) {
        if (!content || typeof content !== 'string' || !content.trim()) {
          continue;
        }

        try {
          const fileFindings = await fileScanner.scanFile(content, filename, {
            scanType: 'web',
            sourceContent: content
          });

          if (fileFindings.length > 0) {
            allFindings.push(...fileFindings);
          }

          scannedCount += 1;
        } catch (error) {
          logger.warn(
            {
              ...getErrorMetadata(
                normalizeError(error, {
                  code: 'WEBPAGE_CONTENT_SCAN_FAILED',
                  status: 500,
                  message: `Failed to scan ${filename}`,
                  requestId,
                  details: {
                    filename
                  },
                  expose: false
                })
              )
            },
            'Skipping webpage content scan failure'
          );
        }
      }

      return { allFindings, scannedCount };
    })();

    const { allFindings, scannedCount } = await Promise.race([scanPromise, timeoutPromise]);
    const report = reportBuilder.generateReport(allFindings, {
      fromCache: false
    });
    const recommendations = reportBuilder.generateRecommendations(allFindings);

    logger.info(
      {
        sourceUrl: url,
        scannedCount,
        findings: report.summary.totalIssues
      },
      'Webpage scan completed'
    );

    return jsonResponse(200, headers, {
      message: 'Webpage scan complete',
      sourceUrl: url,
      scriptsScanned: scannedCount,
      findings: allFindings,
      report,
      summary: report.summary,
      recommendations,
      requestId
    });
  } catch (error) {
    return errorResponse(mapWebpageError(error, requestId), headers, logger);
  }
};
