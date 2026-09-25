import { RepositoryCrawler } from './RepositoryCrawler.js';
import { FileScanner, IGNORED_DOMAINS, IGNORED_SCRIPT_CONTENT } from './FileScanner.js';
import { ReportBuilder } from './ReportBuilder.js';
import { ProgressTracker } from './ProgressTracker.js';
import { authManager } from './githubAuth.js';
import { SecurityLensError, getErrorMetadata, normalizeError } from './errors.js';
import { createLogger, withLogContext } from './logger.js';

// Export constants for backward compatibility
export { IGNORED_DOMAINS, IGNORED_SCRIPT_CONTENT };

class VulnerabilityScanner {
  constructor(config = {}) {
    this.config = {
      enablePatterns: true,
      enablePackageScanners: true,
      maxRetries: 3,
      retryDelay: 1000,
      concurrency: 10,
      onProgress: null,
      maxFileSize: 1024 * 1024, // 1MB
      patternTimeout: 30000, // 30 seconds per file
      totalScanTimeout: 300000, // 5 minutes for entire scan
      ...config
    };
    this.logger = withLogContext(config.logger || createLogger(), {
      component: 'VulnerabilityScanner',
      ...(config.runId ? { runId: config.runId } : {})
    });

    // Initialize modules
    this.repositoryCrawler = new RepositoryCrawler({
      concurrency: this.config.concurrency,
      maxRetries: this.config.maxRetries,
      retryDelay: this.config.retryDelay,
      logger: this.logger
    });
    
    this.fileScanner = new FileScanner({
      maxFileSize: this.config.maxFileSize,
      patternTimeout: this.config.patternTimeout,
      logger: this.logger
    });
    
    this.reportBuilder = new ReportBuilder();
    
    this.progressTracker = new ProgressTracker(this.config.onProgress);

    this.rateLimitInfo = null;
  }

  updateProgress(phase, current, total, details = {}) {
    this.progressTracker.update(phase, current, total, details);
  }

  /**
   * Fetch rate limit information from GitHub
   */
  async getRateLimitInfo() {
    this.rateLimitInfo = await this.repositoryCrawler.getRateLimitInfo();
    return this.rateLimitInfo;
  }

  /**
   * Fetch repository files from GitHub
   * @param {string} url - GitHub repository URL
   * @param {Octokit} octokitInstance - Octokit instance with authentication (optional)
   */
  async fetchRepositoryFiles(url) {
    this.updateProgress('fetching', 0, 0);
    this.logger.info(
      {
        url
      },
      'Fetching repository files'
    );

    const { owner, repo, branch, path } = this.repositoryCrawler.parseGitHubUrl(url);
    
    const token = authManager.getToken();
    const result = await this.repositoryCrawler.getFiles(
      token, 
      owner, 
      repo, 
      branch, 
      path,
      (progress) => {
        if (this.config.onProgress) {
          this.config.onProgress(progress);
        }
      }
    );

    // Update rate limit info
    this.rateLimitInfo = this.repositoryCrawler.rateLimitInfo;
    
    this.updateProgress('analyzing', 0, result.files.length);
    this.logger.info(
      {
        repository: `${owner}/${repo}`,
        branch,
        path: path || '/',
        files: result.files.length,
        fromCache: result.fromCache || false
      },
      'Repository files fetched'
    );
    return result;
  }

  /**
   * Scan local files
   * @param {Array<File>} files - Array of uploaded files
   */
  async scanLocalFiles(files) {
    this.updateProgress('initializing', 0, files.length);
    const findings = [];
    let processedFiles = 0;
    let successCount = 0;
    let failureCount = 0;
    const totalFiles = files.length;
    const startTime = Date.now();
    this.logger.info(
      {
        totalFiles
      },
      'Starting local file scan'
    );

    if (this.config.onProgress) {
      this.config.onProgress({ 
        phase: 'analyzing',
        current: 0, 
        total: totalFiles,
        details: { 
          status: 'Starting file analysis...',
          startTime: startTime
        }
      });
    }

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      this.updateProgress('analyzing', i, files.length, { currentFile: file.name });
      try {
        const content = await file.text();
        const fileFindings = await this.fileScanner.scanFile(content, file.name);
        findings.push(...fileFindings);
        successCount++;
      } catch (error) {
        this.logger.warn(
          {
            ...getErrorMetadata(
              normalizeError(error, {
                code: 'LOCAL_FILE_SCAN_FAILED',
                status: 500,
                message: `Failed to scan ${file.name}`,
                details: {
                  fileName: file.name
                },
                expose: false
              })
            )
          },
          'Continuing after local file scan failure'
        );
        failureCount++;
      } finally {
        processedFiles++;
        if (this.config.onProgress) {
          this.config.onProgress({ 
            phase: 'analyzing',
            current: processedFiles, 
            total: totalFiles,
            details: {
              currentFile: file.name,
              successCount: successCount,
              failureCount: failureCount
            }
          });
        }
      }
    }

    // Calculate completion statistics
    const endTime = Date.now();
    const duration = Math.round((endTime - startTime) / 1000 * 100) / 100;
    const completionRate = totalFiles > 0 ? Math.round((successCount / totalFiles) * 100) : 100;

    if (this.config.onProgress) {
      this.config.onProgress({ 
        phase: 'completed',
        current: totalFiles, 
        total: totalFiles,
        details: {
          duration: duration,
          successCount: successCount,
          failureCount: failureCount,
          completionRate: completionRate,
          totalAttempted: totalFiles,
          summary: `Scanned ${successCount}/${totalFiles} files (${completionRate}%) in ${duration}s`
        }
      });
    }

    this.progressTracker.complete();
    const report = this.reportBuilder.generateReport(findings);
    
    // Add scan statistics to report
    report.scanStats = {
      duration: duration,
      totalFiles: totalFiles,
      successCount: successCount,
      failureCount: failureCount,
      completionRate: completionRate
    };
    report.partial = failureCount > 0;

    this.logger.info(
      {
        totalFiles,
        successCount,
        failureCount,
        duration,
        findings: findings.length,
        partial: report.partial
      },
      'Local file scan completed'
    );
    
    return report;
  }

  /**
   * Scan a single file's content
   * @param {string} fileContent - Content of the file
   * @param {string} filePath - Path of the file
   * @param {object} options - Scan options
   */
  async scanFile(fileContent, filePath, options = {}) {
    this.updateProgress('analyzing', 0, 1, { currentFile: filePath });
    
    const findings = await this.fileScanner.scanFile(fileContent, filePath, options);
    
    this.updateProgress('analyzing', 1, 1, { currentFile: filePath });
    return findings;
  }

  /**
   * Generate a structured report from findings
   * @param {Array} findings - Array of vulnerability findings
   */
  generateReport(findings) {
    this.updateProgress('analyzing', 0, 1, { currentFile: 'report generation' });
    
    const report = this.reportBuilder.generateReport(findings, {
      rateLimit: this.rateLimitInfo,
      fromCache: false
    });
    
    this.updateProgress('analyzing', 1, 1, { currentFile: 'report generation' });
    return report;
  }

  /**
   * Generate recommendations based on findings
   * @param {Array} findings - Array of vulnerability findings
   */
  generateRecommendations(findings) {
    return this.reportBuilder.generateRecommendations(findings);
  }

  /**
   * Check if a script should be ignored (third-party content)
   */
  shouldIgnoreScript(content, path) {
    return this.fileScanner.shouldIgnoreScript(content, path);
  }
}

/**
 * Helper function to scan repositories locally
 * @param {string} url - GitHub repository URL
 * @param {function} onProgress - Progress callback function
 */
export async function scanRepositoryLocally(url, onProgress = null, options = {}) {
  const logger = withLogContext(options.logger || createLogger(), {
    scope: 'repository-scan',
    ...(options.requestId ? { requestId: options.requestId } : {})
  });
  const scanner = new VulnerabilityScanner({
    onProgress: onProgress || ((progress) => {
      logger.debug(
        {
          phase: progress.phase,
          current: progress.current,
          total: progress.total
        },
        'Repository scan progress'
      );
    }),
    logger,
    runId: options.requestId
  });

  try {
    const token = authManager.getToken();
    if (!token) {
      throw new SecurityLensError('GitHub token is required', {
        code: 'MISSING_TOKEN',
        status: 401,
        userMessage: 'GitHub token is required',
        expose: true
      });
    }

    logger.info(
      {
        url
      },
      'Starting local repository scan'
    );

    // Test token validity
    await scanner.getRateLimitInfo();

    const result = await scanner.fetchRepositoryFiles(url);
    const { files, fromCache, scanStats, partial, errors } = result;

    const findings = [];
    let processedFiles = 0;
    const totalFiles = files.length;
    const startTime = Date.now();

    if (scanner.config.onProgress) {
      scanner.config.onProgress({ 
        phase: 'analyzing',
        current: 0, 
        total: totalFiles,
        details: {
          status: 'Starting vulnerability analysis...'
        }
      });
    }

    for (const fileInfo of files) {
      try {
        const fileFindings = await scanner.scanFile(fileInfo.content, fileInfo.path);
        findings.push(...fileFindings);
      } catch (error) {
        logger.warn(
          {
            ...getErrorMetadata(
              normalizeError(error, {
                code: 'REPOSITORY_FILE_SCAN_FAILED',
                status: 500,
                message: `Failed to analyze ${fileInfo.path}`,
                details: {
                  filePath: fileInfo.path
                },
                expose: false
              })
            )
          },
          'Continuing after repository file scan failure'
        );
      } finally {
        processedFiles++;
        if (scanner.config.onProgress) {
          scanner.config.onProgress({ 
            phase: 'analyzing',
            current: processedFiles, 
            total: totalFiles,
            details: {
              currentFile: fileInfo.path
            }
          });
        }
      }
    }

    const analysisTime = Math.round((Date.now() - startTime) / 1000 * 100) / 100;

    const report = scanner.generateReport(findings);
    report.rateLimit = scanner.rateLimitInfo;
    report.fromCache = fromCache;
    
    // Include scan statistics from file fetching
    if (scanStats) {
      report.scanStats = {
        ...scanStats,
        analysisTime: analysisTime,
        totalTime: scanStats.duration + analysisTime
      };
    }
    report.partial = partial;
    report.fetchErrors = errors;

    logger.info(
      {
        url,
        findings: report.findings.length,
        partial: report.partial,
        fromCache: report.fromCache || false,
        totalFiles,
        processedFiles
      },
      'Local repository scan completed'
    );

    return report;
  } catch (error) {
    const normalized = normalizeError(error, {
      code: 'LOCAL_REPOSITORY_SCAN_FAILED',
      status: error?.status || 500,
      message: `Repository scan failed for ${url}`,
      details: {
        url
      },
      userMessage: error?.userMessage || error?.message || 'Repository scan failed'
    });

    logger.error(getErrorMetadata(normalized), 'Local repository scan failed');
    throw normalized;
  }
}

export default VulnerabilityScanner;
