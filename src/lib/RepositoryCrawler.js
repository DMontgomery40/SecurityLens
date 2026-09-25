import { Octokit } from '@octokit/core';
import { restEndpointMethods } from '@octokit/plugin-rest-endpoint-methods';
import Cache from './cache/Cache.js';
import { SecurityLensError, getErrorMetadata, normalizeError } from './errors.js';
import { authManager } from './githubAuth.js';
import { fetchWithTimeout } from './http.js';
import { createLogger, withLogContext } from './logger.js';

/**
 * Standardized error object for scanner operations
 */
export class ScanError extends SecurityLensError {
  constructor(code, message, details = {}) {
    super(message, {
      code,
      status: details.status || 500,
      details,
      userMessage: message,
      expose: details.status ? details.status < 500 : true
    });
    this.name = 'ScanError';
  }
}

/**
 * Simple semaphore implementation for concurrency control
 */
class Semaphore {
  constructor(maxConcurrency) {
    this.maxConcurrency = maxConcurrency;
    this.currentConcurrency = 0;
    this.queue = [];
  }

  async acquire() {
    return new Promise((resolve) => {
      if (this.currentConcurrency < this.maxConcurrency) {
        this.currentConcurrency++;
        resolve();
      } else {
        this.queue.push(resolve);
      }
    });
  }

  release() {
    this.currentConcurrency--;
    if (this.queue.length > 0) {
      const next = this.queue.shift();
      this.currentConcurrency++;
      next();
    }
  }

  async execute(task) {
    await this.acquire();
    try {
      return await task();
    } finally {
      this.release();
    }
  }
}

const MyOctokit = Octokit.plugin(restEndpointMethods);

export class RepositoryCrawler {
  constructor(config = {}) {
    this.config = {
      concurrency: 10,
      maxRetries: 3,
      retryDelay: 1000,
      maxFileSize: 500 * 1024, // 500KB default
      fileTimeout: 5000, // 5 seconds per file
      maxScanTime: 25000, // 25 seconds total (under Netlify's 30s limit)
      skipBinaryFiles: true,
      useCache: true,
      ...config
    };
    this.logger = withLogContext(config.logger || createLogger(), {
      component: 'RepositoryCrawler'
    });
    
    this.rateLimitInfo = null;
    this.cache = new Cache({
      logger: this.logger
    });
    this.semaphore = new Semaphore(this.config.concurrency);
    this.errors = [];
    this.scanStartTime = null;
    
    // Initialize Octokit if we have a token
    const token = authManager.getToken();
    if (token) {
      this.octokit = new MyOctokit({
        auth: token
      });
    }
  }

  /**
   * Add an error to the error collection
   * @private
   */
  addError(code, message, details = {}) {
    const error = new ScanError(code, message, details);
    this.errors.push(error);
    this.logger.warn(
      {
        errorCode: code,
        details
      },
      message
    );
    return error;
  }

  /**
   * Get collected errors
   */
  getErrors() {
    return this.errors;
  }

  /**
   * Clear collected errors
   */
  clearErrors() {
    this.errors = [];
  }

  /**
   * Fetch rate limit information from GitHub
   */
  async getRateLimitInfo() {
    if (!this.octokit) {
      return null;
    }

    try {
      const response = await this.octokit.rateLimit.get();
      const { limit, remaining, reset } = response.data.rate;

      this.rateLimitInfo = { limit, remaining, reset };
      return this.rateLimitInfo;
    } catch (error) {
      this.logger.warn(
        getErrorMetadata(
          normalizeError(error, {
            code: 'RATE_LIMIT_LOOKUP_FAILED',
            status: error?.status || 502,
            message: 'Unable to fetch GitHub rate limit information',
            expose: false
          })
        ),
        'Rate limit lookup failed'
      );
      return null;
    }
  }

  /**
   * Get the default branch for a repository
   * @private
   */
  async getDefaultBranch(owner, repo) {
    try {
      const repoData = await this.octokit.rest.repos.get({
        owner,
        repo
      });
      return repoData.data.default_branch;
    } catch (error) {
      this.logger.error(
        getErrorMetadata(
          normalizeError(error, {
            code: 'DEFAULT_BRANCH_LOOKUP_FAILED',
            status: error?.status || 502,
            message: `Unable to determine default branch for ${owner}/${repo}`,
            details: {
              owner,
              repo
            },
            expose: false
          })
        ),
        'Default branch lookup failed'
      );
      throw error;
    }
  }

  /**
   * Get repository tree using Git Data API
   * @private
   */
  async getRepoTree(owner, repo, branch) {
    try {
      let targetBranch = branch;
      
      // If no branch specified or branch not found, get the default branch
      if (!targetBranch || targetBranch === 'main' || targetBranch === 'master') {
        try {
          targetBranch = await this.getDefaultBranch(owner, repo);
          this.logger.info(
            {
              owner,
              repo,
              branch: targetBranch
            },
            'Using repository default branch'
          );
        } catch {
          throw new ScanError(
            'DEFAULT_BRANCH_LOOKUP_FAILED',
            `Could not determine default branch for ${owner}/${repo}`,
            {
              owner,
              repo,
              status: 404
            }
          );
        }
      }

      // Get the commit SHA directly using the branch name
      const { data: refData } = await this.octokit.rest.git.getRef({
        owner,
        repo,
        ref: `heads/${targetBranch}`
      });

      const commitSha = refData.object.sha;
      this.logger.debug(
        {
          owner,
          repo,
          branch: targetBranch,
          commitSha
        },
        'Resolved branch commit'
      );

      // Get the commit to find the tree SHA
      const commitData = await this.octokit.rest.git.getCommit({
        owner,
        repo,
        commit_sha: commitSha
      });

      // Get the full tree recursively
      const treeData = await this.octokit.rest.git.getTree({
        owner,
        repo,
        tree_sha: commitData.data.tree.sha,
        recursive: true
      });

      if (treeData.data.truncated) {
        this.logger.warn(
          {
            owner,
            repo,
            branch: targetBranch
          },
          'Repository tree truncated, falling back to manual traversal'
        );
        return await this.getTreeManually(owner, repo, commitData.data.tree.sha);
      }

      return treeData.data.tree;
    } catch (error) {
      this.logger.error(
        getErrorMetadata(
          normalizeError(error, {
            code: 'REPO_TREE_FETCH_FAILED',
            status: error?.status || 502,
            message: `Failed to fetch repository tree for ${owner}/${repo}`,
            details: {
              owner,
              repo,
              branch
            },
            expose: false
          })
        ),
        'Repository tree fetch failed'
      );
      throw error;
    }
  }

  /**
   * Manually traverse the tree when it's too large for a single request
   * @private
   */
  async getTreeManually(owner, repo, treeSha, path = '') {
    const results = [];
    
    try {
      // Get the current level of the tree
      const treeData = await this.octokit.rest.git.getTree({
        owner,
        repo,
        tree_sha: treeSha
      });

      for (const item of treeData.data.tree) {
        if (item.type === 'blob') {
          results.push({
            ...item,
            path: path ? `${path}/${item.path}` : item.path
          });
        } else if (item.type === 'tree') {
          // Recursively get subtree
          const subtreeItems = await this.getTreeManually(
            owner,
            repo,
            item.sha,
            path ? `${path}/${item.path}` : item.path
          );
          results.push(...subtreeItems);
        }
      }

      return results;
    } catch (error) {
      this.logger.error(
        getErrorMetadata(
          normalizeError(error, {
            code: 'MANUAL_TREE_TRAVERSAL_FAILED',
            status: error?.status || 502,
            message: `Manual tree traversal failed for ${path || '/'}`,
            details: {
              owner,
              repo,
              path
            },
            expose: false
          })
        ),
        'Manual tree traversal failed'
      );
      throw error;
    }
  }

  /**
   * Get files from a repository
   * @param {string} token - GitHub token
   * @param {string} repoOwner - Repository owner
   * @param {string} repoName - Repository name
   * @param {string} branch - Branch name (optional)
   * @param {string} path - Path within repository (optional)
   * @param {function} onProgress - Progress callback
   */
  async getFiles(token, repoOwner, repoName, branch = 'main', path = '', onProgress = null) {
    if (token && !this.octokit) {
      this.octokit = new MyOctokit({
        auth: token
      });
    }

    if (!this.octokit) {
      throw new ScanError('MISSING_TOKEN', 'GitHub token is required');
    }

    // Test token validity
    try {
      await this.octokit.rest.users.getAuthenticated();
    } catch (error) {
      if (error.status === 401) {
        authManager.clearToken();
        throw new ScanError('AUTH_FAILED', 'Invalid GitHub token. Please provide a new token.', {
          originalError: error.message
        });
      }
      throw new ScanError('AUTH_ERROR', 'Authentication error occurred', {
        originalError: error.message,
        status: error.status
      });
    }

    const cleanPath = path.replace(/^\//, ''); // Remove leading slash
    this.logger.info(
      {
        repository: `${repoOwner}/${repoName}`,
        branch,
        path: cleanPath || '/'
      },
      'Starting repository fetch'
    );
    
    const cacheKey = `repo:${repoOwner}/${repoName}/${branch}/${cleanPath}`;
    const cachedData = this.config.useCache ? this.cache.get(cacheKey) : null;
    if (cachedData) {
      this.logger.info(
        {
          cacheKey
        },
        'Using cached repository data'
      );
      if (onProgress) onProgress({ phase: 'analyzing', current: 0, total: 1, details: { currentFile: cacheKey } });
      return { ...cachedData, fromCache: true };
    }

    try {
      this.logger.debug('Fetching repository tree');
      const tree = await this.getRepoTree(repoOwner, repoName, branch);
      
      // Filter by path if specified
      const filteredTree = cleanPath ? 
        tree.filter(item => item.path.startsWith(cleanPath)) : 
        tree;

      this.logger.info(
        {
          repository: `${repoOwner}/${repoName}`,
          files: filteredTree.length,
          filteredPath: cleanPath || '/'
        },
        'Repository tree loaded'
      );

      // Get file contents with semaphore-controlled concurrency
      const blobFiles = filteredTree.filter(item => item.type === 'blob');
      
      // Filter out binary files and large files if configured
      const scannableFiles = this.config.skipBinaryFiles ? 
        blobFiles.filter(file => {
          const ext = file.path.split('.').pop().toLowerCase();
          const binaryExtensions = ['png', 'jpg', 'jpeg', 'gif', 'ico', 'svg', 'pdf', 'zip', 'tar', 'gz', 'rar', '7z', 'exe', 'dll', 'so', 'dylib', 'bin', 'dat', 'db', 'sqlite', 'mp3', 'mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv', 'webm', 'wav', 'flac', 'aac', 'ogg', 'woff', 'woff2', 'ttf', 'eot', 'otf'];
          return !binaryExtensions.includes(ext);
        }) : blobFiles;
      
      const filesWithContent = [];
      const totalFiles = scannableFiles.length;
      
      this.clearErrors(); // Clear any previous errors
      
      // Send initial progress
      const startTime = Date.now();
      this.scanStartTime = startTime;
      if (onProgress) {
        onProgress({ 
          phase: 'fetching', 
          current: 0, 
          total: totalFiles,
          details: { 
            currentFile: 'Starting download...',
            successCount: 0,
            failureCount: 0
          }
        });
      }
      
      // Track progress with atomic counter to avoid race conditions
      let completedCount = 0;
      let successCount = 0;
      let failureCount = 0;

      // Use semaphore to control concurrency
      const filePromises = scannableFiles.map((file) => 
        this.semaphore.execute(async () => {
          try {
            // Check if we're approaching the time limit
            const elapsedTime = Date.now() - this.scanStartTime;
            if (elapsedTime > this.config.maxScanTime) {
              this.addError('TIME_LIMIT', `Skipping ${file.path} - approaching time limit`, {
                filePath: file.path,
                elapsedTime: elapsedTime
              });
              return null;
            }
            
            // Use raw content URL for better performance
            const rawUrl = `https://raw.githubusercontent.com/${repoOwner}/${repoName}/${branch}/${file.path}`;
            const response = await fetchWithTimeout(rawUrl, {
              timeoutMs: this.config.fileTimeout
            });
            
            if (!response.ok) {
              this.addError('FETCH_FAILED', `Failed to fetch file: ${file.path}`, {
                status: response.status,
                statusText: response.statusText,
                filePath: file.path
              });
              
              // Update progress and failure count atomically
              completedCount++;
              failureCount++;
              if (onProgress) {
                onProgress({ 
                  phase: 'fetching',
                  current: completedCount, 
                  total: totalFiles,
                  details: { 
                    currentFile: file.path,
                    successCount: successCount,
                    failureCount: failureCount
                  }
                });
              }
              return null;
            }
            
            const content = await response.text();
            
            // Check file size
            const fileSize = new Blob([content]).size;
            if (fileSize > this.config.maxFileSize) {
              this.addError('FILE_TOO_LARGE', `File ${file.path} exceeds size limit`, {
                filePath: file.path,
                fileSize: fileSize,
                maxSize: this.config.maxFileSize
              });
              
              // Update progress
              completedCount++;
              failureCount++;
              if (onProgress) {
                onProgress({ 
                  phase: 'fetching',
                  current: completedCount, 
                  total: totalFiles,
                  details: { 
                    currentFile: file.path,
                    successCount: successCount,
                    failureCount: failureCount
                  }
                });
              }
              return null;
            }
            
            // Update progress and success count atomically
            completedCount++;
            successCount++;
            if (onProgress) {
              onProgress({ 
                phase: 'fetching',
                current: completedCount, 
                total: totalFiles,
                details: { 
                  currentFile: file.path,
                  successCount: successCount,
                  failureCount: failureCount
                }
              });
            }
            
            return { path: file.path, content };
          } catch (error) {
            this.addError('FETCH_ERROR', `Network error fetching file: ${file.path}`, {
              originalError: error.message,
              filePath: file.path
            });
            
            // Update progress and failure count atomically
            completedCount++;
            failureCount++;
            if (onProgress) {
              onProgress({ 
                phase: 'fetching',
                current: completedCount, 
                total: totalFiles,
                details: { 
                  currentFile: file.path,
                  successCount: successCount,
                  failureCount: failureCount
                }
              });
            }
            return null;
          }
        })
      );
      
      const results = await Promise.all(filePromises);
      filesWithContent.push(...results.filter(f => f !== null));

      // Calculate final statistics
      const endTime = Date.now();
      const duration = Math.round((endTime - startTime) / 1000 * 100) / 100; // seconds with 2 decimal places
      const actualSuccessCount = filesWithContent.length;
      const actualFailureCount = totalFiles - actualSuccessCount;
      const completionRate = totalFiles > 0 ? Math.round((actualSuccessCount / totalFiles) * 100) : 100;

      this.logger.info(
        {
          repository: `${repoOwner}/${repoName}`,
          duration,
          totalFiles,
          successCount: actualSuccessCount,
          failureCount: actualFailureCount,
          completionRate
        },
        'Repository fetch completed'
      );
      
      if (actualFailureCount > 0) {
        this.logger.warn(
          {
            repository: `${repoOwner}/${repoName}`,
            failureCount: actualFailureCount
          },
          'Some repository files failed to download'
        );
      }
      
      // Send completion summary
      if (onProgress) {
        onProgress({
          phase: 'completed',
          current: totalFiles,
          total: totalFiles,
          details: {
            duration: duration,
            successCount: actualSuccessCount,
            failureCount: actualFailureCount,
            completionRate: completionRate,
            totalAttempted: totalFiles,
            summary: `Scanned ${actualSuccessCount}/${totalFiles} files (${completionRate}%) in ${duration}s`
          }
        });
      }
      
      const result = { 
        files: filesWithContent,
        errors: this.errors,
        partial: actualFailureCount > 0,
        scanStats: {
          duration: duration,
          totalFiles: totalFiles,
          successCount: actualSuccessCount,
          failureCount: actualFailureCount,
          completionRate: completionRate
        }
      };
      if (this.config.useCache) {
        this.cache.set(cacheKey, result, 24 * 60 * 60); // Cache for 24 hours
      }
      
      if (onProgress) {
        onProgress({ 
          phase: 'analyzing', 
          current: 0, 
          total: filesWithContent.length,
          details: {
            status: 'Starting vulnerability analysis...'
          }
        });
      }
      
      return { ...result, fromCache: false };
    } catch (error) {
      this.logger.error(
        getErrorMetadata(
          normalizeError(error, {
            code: 'REPOSITORY_FETCH_FAILED',
            status: error?.status || 500,
            message: `Failed to fetch repository files for ${repoOwner}/${repoName}`,
            details: {
              repository: `${repoOwner}/${repoName}`,
              branch,
              path: cleanPath
            },
            expose: false
          })
        ),
        'Repository fetch failed'
      );
      
      // Convert to standardized error format
      if (error.status === 401) {
        throw new ScanError('AUTH_FAILED', 'Invalid GitHub token or insufficient permissions', {
          originalError: error.message,
          status: error.status
        });
      } else if (error.status === 404) {
        throw new ScanError('REPO_NOT_FOUND', 'Repository or branch not found', {
          originalError: error.message,
          status: error.status,
          repository: `${repoOwner}/${repoName}`,
          branch
        });
      } else if (error.status === 403) {
        throw new ScanError('RATE_LIMITED', 'GitHub API rate limit exceeded', {
          originalError: error.message,
          status: error.status
        });
      } else {
        throw new ScanError('UNKNOWN_ERROR', 'An unexpected error occurred', {
          originalError: error.message,
          status: error.status
        });
      }
    }
  }

  /**
   * Parse GitHub URL to extract owner, repo, branch, and path
   * @param {string} url - GitHub repository URL
   */
  parseGitHubUrl(url) {
    const githubRegex = /github\.com\/([^/]+)\/([^/]+)(?:\/(?:tree|blob)\/([^/]+))?(\/.*)?/;
    const match = url.match(githubRegex);

    if (!match) {
      throw new ScanError('INVALID_URL', 'Invalid GitHub URL format', {
        providedUrl: url
      });
    }

    const [, owner, repo, branch = 'main', path = ''] = match;
    return { owner, repo, branch, path };
  }
}
