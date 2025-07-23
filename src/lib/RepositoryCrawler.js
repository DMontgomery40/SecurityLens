import { Octokit } from '@octokit/core';
import { restEndpointMethods } from '@octokit/plugin-rest-endpoint-methods';
import Cache from './cache/Cache.js';
import { authManager } from './githubAuth.js';

/**
 * Standardized error object for scanner operations
 */
export class ScanError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'ScanError';
    this.code = code;
    this.details = details;
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
      ...config
    };
    
    this.rateLimitInfo = null;
    this.cache = new Cache();
    this.semaphore = new Semaphore(this.config.concurrency);
    this.errors = [];
    
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
    console.warn(`Non-fatal error: ${code} - ${message}`);
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
      console.error('Error fetching rate limit:', error);
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
      console.error('Error fetching default branch:', error);
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
          console.log(`Using default branch: ${targetBranch}`);
        } catch (error) {
          console.error('Error getting default branch:', error);
          throw new Error(`Could not determine default branch for ${owner}/${repo}`);
        }
      }

      // Get the commit SHA directly using the branch name
      const { data: refData } = await this.octokit.rest.git.getRef({
        owner,
        repo,
        ref: `heads/${targetBranch}`
      });

      const commitSha = refData.object.sha;
      console.log(`Got commit SHA: ${commitSha}`);

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
        console.warn('Repository tree was truncated! Falling back to manual traversal...');
        return await this.getTreeManually(owner, repo, commitData.data.tree.sha);
      }

      return treeData.data.tree;
    } catch (error) {
      console.error('Error fetching repo tree:', error);
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
      console.error(`Error in manual tree traversal for ${path}:`, error);
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
    console.log(`Scanning repository: ${repoOwner}/${repoName}, branch: ${branch}, path: ${cleanPath}`);
    
    const cacheKey = `repo:${repoOwner}/${repoName}/${branch}/${cleanPath}`;
    const cachedData = this.cache.get(cacheKey);
    if (cachedData) {
      if (onProgress) onProgress({ phase: 'analyzing', current: 0, total: 1, details: { currentFile: cacheKey } });
      return { ...cachedData, fromCache: true };
    }

    try {
      console.log('Fetching repository tree...');
      const tree = await this.getRepoTree(repoOwner, repoName, branch);
      
      // Filter by path if specified
      const filteredTree = cleanPath ? 
        tree.filter(item => item.path.startsWith(cleanPath)) : 
        tree;

      console.log(`Found ${filteredTree.length} files in repository`);

      // Get file contents with semaphore-controlled concurrency
      const blobFiles = filteredTree.filter(item => item.type === 'blob');
      const filesWithContent = [];
      const totalFiles = blobFiles.length;
      
      this.clearErrors(); // Clear any previous errors
      
      // Initialize progress tracking
      if (onProgress) {
        onProgress({
          phase: 'fetching',
          current: 0,
          total: totalFiles,
          details: { status: 'Starting file downloads...' }
        });
      }
      
      // Track progress with atomic counter to avoid race conditions
      let completedCount = 0;

      // Use semaphore to control concurrency
      const filePromises = blobFiles.map((file, index) => 
        this.semaphore.execute(async () => {
          try {
            // Use raw content URL for better performance
            const rawUrl = `https://raw.githubusercontent.com/${repoOwner}/${repoName}/${branch}/${file.path}`;
            const response = await fetch(rawUrl, {
              timeout: 15000 // 15 second timeout
            });
            
            if (!response.ok) {
              this.addError('FETCH_FAILED', `Failed to fetch file: ${file.path}`, {
                status: response.status,
                statusText: response.statusText,
                filePath: file.path
              });
              
              // Update progress atomically
              completedCount++;
              if (onProgress) {
                onProgress({ 
                  phase: 'fetching',
                  current: completedCount, 
                  total: totalFiles,
                  details: { currentFile: file.path }
                });
              }
              return null;
            }
            
            const content = await response.text();
            
            // Update progress atomically
            completedCount++;
            if (onProgress) {
              onProgress({ 
                phase: 'fetching',
                current: completedCount, 
                total: totalFiles,
                details: { currentFile: file.path }
              });
            }
            
            return { path: file.path, content };
          } catch (error) {
            this.addError('FETCH_ERROR', `Network error fetching file: ${file.path}`, {
              originalError: error.message,
              filePath: file.path
            });
            
            // Update progress atomically
            completedCount++;
            if (onProgress) {
              onProgress({ 
                phase: 'fetching',
                current: completedCount, 
                total: totalFiles,
                details: { currentFile: file.path }
              });
            }
            return null;
          }
        })
      );
      
      const results = await Promise.all(filePromises);
      filesWithContent.push(...results.filter(f => f !== null));

      console.log(`Successfully fetched ${filesWithContent.length} files`);
      
      if (this.errors.length > 0) {
        console.warn(`${this.errors.length} non-fatal errors occurred during file fetching`);
      }
      
      const result = { 
        files: filesWithContent,
        errors: this.errors,
        partial: this.errors.length > 0
      };
      this.cache.set(cacheKey, result, 24 * 60 * 60); // Cache for 24 hours
      
      if (onProgress) {
        onProgress({ phase: 'analyzing', current: 0, total: filesWithContent.length });
      }
      
      return { ...result, fromCache: false };
    } catch (error) {
      console.error('Error fetching repository files:', error);
      
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