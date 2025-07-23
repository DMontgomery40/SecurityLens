import { RepositoryCrawler } from './RepositoryCrawler.js';
import { FileScanner, IGNORED_DOMAINS, IGNORED_SCRIPT_CONTENT } from './FileScanner.js';
import { ReportBuilder } from './ReportBuilder.js';
import { ProgressTracker } from './ProgressTracker.js';
import { authManager } from './githubAuth.js';

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

    // Initialize modules
    this.repositoryCrawler = new RepositoryCrawler({
      concurrency: this.config.concurrency,
      maxRetries: this.config.maxRetries,
      retryDelay: this.config.retryDelay
    });
    
    this.fileScanner = new FileScanner({
      maxFileSize: this.config.maxFileSize,
      patternTimeout: this.config.patternTimeout
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
  async fetchRepositoryFiles(url, octokitInstance) {
    this.updateProgress('fetching', 0, 0);

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
    const totalFiles = files.length;

    if (this.config.onProgress) {
      this.config.onProgress({ current: 0, total: totalFiles });
    }

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      this.updateProgress('analyzing', i, files.length, { currentFile: file.name });
      try {
        const content = await file.text();
        const fileFindings = await this.fileScanner.scanFile(content, file.name);
        findings.push(...fileFindings);
      } catch (error) {
        console.error(`Error scanning file ${file.name}:`, error);
      } finally {
        processedFiles++;
        if (this.config.onProgress) {
          this.config.onProgress({ current: processedFiles, total: totalFiles });
        }
      }
    }

    if (this.config.onProgress) {
      this.config.onProgress({ current: totalFiles, total: totalFiles });
    }

    this.progressTracker.complete();
    return this.reportBuilder.generateReport(findings);
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
 */
export async function scanRepositoryLocally(url) {
  const scanner = new VulnerabilityScanner({
    onProgress: (progress) => {
      // Pass progress object instead of separate values
      console.log(`Scanning progress:`, progress);
    }
  });

  try {
    const token = authManager.getToken();
    if (!token) {
      throw new Error('GitHub token is required');
    }

    // Test token validity
    await scanner.getRateLimitInfo();

    const { files, fromCache } = await scanner.fetchRepositoryFiles(url);

    const findings = [];
    let processedFiles = 0;
    const totalFiles = files.length;

    if (scanner.config.onProgress) {
      scanner.config.onProgress({ current: 0, total: totalFiles });
    }

    for (const fileInfo of files) {
      try {
        const fileFindings = await scanner.scanFile(fileInfo.content, fileInfo.path);
        findings.push(...fileFindings);
      } catch (error) {
        console.error(`Error scanning file ${fileInfo.path}:`, error);
      } finally {
        processedFiles++;
        if (scanner.config.onProgress) {
          scanner.config.onProgress({ current: processedFiles, total: totalFiles });
        }
      }
    }

    if (scanner.config.onProgress) {
      scanner.config.onProgress({ current: totalFiles, total: totalFiles });
    }

    const report = scanner.generateReport(findings);
    report.rateLimit = scanner.rateLimitInfo;
    report.fromCache = fromCache;

    return report;
  } catch (error) {
    console.error('Local scan error:', error);
    throw error;
  }
}

export default VulnerabilityScanner;