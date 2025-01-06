import { Octokit } from '@octokit/core';
import { restEndpointMethods } from '@octokit/plugin-rest-endpoint-methods';
import { repoCache } from './cache';
import { patterns, patternCategories, recommendations } from './patterns';
import { authManager } from './githubAuth';

// Create an Octokit class with the REST plugin
const MyOctokit = Octokit.plugin(restEndpointMethods);

class VulnerabilityScanner {
  constructor(config = {}) {
    this.config = {
      enablePatterns: true,
      enablePackageScanners: true,
      maxRetries: 3,
      retryDelay: 1000,
      octokit: null,
      onProgress: null,
      maxFileSize: 1024 * 1024, // 1MB
      patternTimeout: 30000, // 30 seconds per file
      totalScanTimeout: 300000, // 5 minutes for entire scan
      ...config
    };

    // Initialize Octokit if we have a token
    const token = authManager.getToken();
    if (token) {
      this.config.octokit = new MyOctokit({
        auth: token
      });
    }

    // Enhanced debug logging
    console.log('Initializing scanner with patterns:', {
      patternsLoaded: !!patterns,
      patternCount: patterns ? Object.keys(patterns).length : 0,
      patternTypes: patterns ? Object.keys(patterns) : []
    });

    this.vulnerabilityPatterns = { ...patterns };

    // Validate patterns
    let validPatterns = 0;
    Object.entries(this.vulnerabilityPatterns).forEach(([key, pattern]) => {
      if (!pattern.pattern || !pattern.severity || !pattern.description) {
        console.error(`Invalid pattern configuration for ${key}:`, pattern);
        delete this.vulnerabilityPatterns[key];
      } else {
        validPatterns++;
      }
    });
    console.log(`Scanner initialized with ${validPatterns} valid patterns`);

    this.rateLimitInfo = null;
  }

  /**
   * Fetch rate limit information from GitHub
   */
  async getRateLimitInfo() {
    if (!this.config.octokit) {
      return null;
    }

    try {
      const response = await this.config.octokit.rateLimit.get();
      const { limit, remaining, reset } = response.data.rate;

      this.rateLimitInfo = { limit, remaining, reset };
      return this.rateLimitInfo;
    } catch (error) {
      console.error('Error fetching rate limit:', error);
      return null;
    }
  }

  /**
   * Get repository tree using Git Data API
   * @private
   */
  async getRepoTree(owner, repo, branch) {
    try {
      // First get the branch reference
      const branchRef = branch.replace('refs/heads/', '');
      console.log(`Getting tree for branch: ${branchRef}`);
      
      const branchData = await this.config.octokit.rest.git.getRef({
        owner,
        repo,
        ref: `heads/${branchRef}`
      });

      // Get the commit SHA that the branch points to
      const commitSha = branchData.data.object.sha;
      console.log(`Got commit SHA: ${commitSha}`);

      // Get the commit to find the tree SHA
      const commitData = await this.config.octokit.rest.git.getCommit({
        owner,
        repo,
        commit_sha: commitSha
      });

      // Get the full tree recursively
      const treeData = await this.config.octokit.rest.git.getTree({
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
      const treeData = await this.config.octokit.rest.git.getTree({
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
   * Fetch repository files from GitHub
   * @param {string} url - GitHub repository URL
   * @param {Octokit} octokitInstance - Octokit instance with authentication
   */
  async fetchRepositoryFiles(url, octokitInstance) {
    if (octokitInstance) {
      this.config.octokit = octokitInstance;
    }

    // Enhanced regex to better handle branches and paths
    const githubRegex = /github\.com\/([^/]+)\/([^/]+)(?:\/(?:tree|blob)\/([^/]+))?(\/.*)?/;
    const match = url.match(githubRegex);

    if (!match) {
      throw new Error('Invalid GitHub URL format');
    }

    const [, owner, repo, branch = 'main', path = ''] = match;
    const cleanPath = path.replace(/^\//, ''); // Remove leading slash
    
    console.log(`Scanning repository: ${owner}/${repo}, branch: ${branch}, path: ${cleanPath}`);
    
    const cacheKey = `${owner}/${repo}/${branch}/${cleanPath}`;
    const cachedData = repoCache.get(cacheKey);
    if (cachedData) {
      return { ...cachedData, fromCache: true };
    }

    try {
      console.log('Fetching repository tree...');
      const tree = await this.getRepoTree(owner, repo, branch);
      
      // Filter by path if specified
      const filteredTree = cleanPath ? 
        tree.filter(item => item.path.startsWith(cleanPath)) : 
        tree;

      console.log(`Found ${filteredTree.length} files in repository`);

      // Get file contents in parallel with chunking to avoid overwhelming
      const chunkSize = 10; // Process 10 files at a time
      const chunks = [];
      
      for (let i = 0; i < filteredTree.length; i += chunkSize) {
        const chunk = filteredTree.slice(i, i + chunkSize);
        chunks.push(chunk);
      }

      const filesWithContent = [];
      let processedFiles = 0;
      const totalFiles = filteredTree.length;

      // Process chunks sequentially to maintain progress updates
      for (const chunk of chunks) {
        const chunkResults = await Promise.all(
          chunk
            .filter(item => item.type === 'blob')
            .map(async file => {
              try {
                // Use raw content URL for better performance
                const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${file.path}`;
                const response = await fetch(rawUrl);
                
                if (!response.ok) {
                  console.error(`Failed to fetch ${file.path}: ${response.status}`);
                  return null;
                }
                
                const content = await response.text();
                processedFiles++;
                
                if (this.config.onProgress) {
                  this.config.onProgress({ 
                    current: processedFiles, 
                    total: totalFiles,
                    phase: 'fetching'
                  });
                }
                
                return { path: file.path, content };
              } catch (error) {
                console.error(`Error fetching ${file.path}:`, error);
                processedFiles++;
                if (this.config.onProgress) {
                  this.config.onProgress({ 
                    current: processedFiles, 
                    total: totalFiles,
                    phase: 'fetching'
                  });
                }
                return null;
              }
            })
        );
        
        filesWithContent.push(...chunkResults.filter(f => f !== null));
      }

      console.log(`Successfully fetched ${filesWithContent.length} files`);
      
      const result = { files: filesWithContent };
      repoCache.set(cacheKey, result);
      return { ...result, fromCache: false };
    } catch (error) {
      console.error('Error fetching repository files:', error);
      throw error;
    }
  }

  /**
   * Scan local files
   * @param {Array<File>} files - Array of uploaded files
   */
  async scanLocalFiles(files) {
    const findings = [];
    let processedFiles = 0;
    const totalFiles = files.length;

    if (this.config.onProgress) {
      this.config.onProgress({ current: 0, total: totalFiles });
    }

    for (const file of files) {
      try {
        const content = await file.text();
        const fileFindings = await this.scanFile(content, file.name);
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

    return this.generateReport(findings);
  }

  /**
   * Scan a single file's content
   * @param {string} fileContent - Content of the file
   * @param {string} filePath - Path of the file
   */
  async scanFile(fileContent, filePath) {
    console.log(`Scanning file: ${filePath}`, {
      contentProvided: !!fileContent,
      contentLength: fileContent ? fileContent.length : 0,
      activePatterns: Object.keys(this.vulnerabilityPatterns).length
    });

    if (!fileContent || typeof fileContent !== 'string') {
      console.error('Invalid file content provided to scanner');
      return [];
    }

    // Check file size
    const contentSize = new Blob([fileContent]).size;
    if (contentSize > this.config.maxFileSize) {
      console.warn(`File ${filePath} exceeds size limit of ${this.config.maxFileSize} bytes`);
      return [];
    }

    const findings = [];

    if (!this.vulnerabilityPatterns || Object.keys(this.vulnerabilityPatterns).length === 0) {
      console.error('No vulnerability patterns loaded');
      return findings;
    }

    try {
      const lines = fileContent.split('\n');
      const lineOffsets = new Array(lines.length + 1).fill(0);
      for (let i = 0; i < lines.length; i++) {
        lineOffsets[i + 1] = lineOffsets[i] + lines[i].length + 1; // +1 for newline
      }
      lineOffsets[lines.length] = lineOffsets[lines.length - 1] + 1;

      // Log file type and first few lines for debugging
      const fileExt = filePath.split('.').pop().toLowerCase();
      console.log(`File type: ${fileExt}, First few lines:`, lines.slice(0, 3));

      for (const [vulnType, vulnInfo] of Object.entries(this.vulnerabilityPatterns)) {
        try {
          console.log(`Checking pattern: ${vulnType}`, {
            pattern: vulnInfo.pattern,
            severity: vulnInfo.severity
          });

          const regex = new RegExp(vulnInfo.pattern, 'g');
          const matches = new Set();

          let match;
          while ((match = regex.exec(fileContent)) !== null) {
            console.log(`Found match for ${vulnType}:`, {
              matchText: match[0],
              matchIndex: match.index
            });

            let lineNumber = 0;
            while (lineNumber < lineOffsets.length && lineOffsets[lineNumber] <= match.index) {
              lineNumber++;
            }
            lineNumber--;
            matches.add(lineNumber);
          }

          if (matches.size > 0) {
            console.log(`Found ${matches.size} matches for ${vulnType} in ${filePath}`);
            findings.push({
              type: vulnType,
              severity: vulnInfo.severity,
              description: vulnInfo.description,
              file: filePath,
              lineNumbers: Array.from(matches).sort((a, b) => a - b),
              category: vulnInfo.category,
              subcategory: vulnInfo.subcategory,
              cwe: vulnInfo.cwe
            });
          }
        } catch (error) {
          console.error(`Error processing pattern ${vulnType}:`, error);
        }
      }

      console.log('Generated findings with categories:', findings.map(f => ({
        type: f.type, 
        category: f.category,
        subcategory: f.subcategory,
        lineCount: f.lineNumbers.length
      })));

      return findings;
    } catch (error) {
      console.error(`Error scanning file ${filePath}:`, error);
      console.error('Scan context:', {
        patternsLoaded: !!this.vulnerabilityPatterns,
        patternCount: this.vulnerabilityPatterns ? Object.keys(this.vulnerabilityPatterns).length : 0,
        fileSize: fileContent ? fileContent.length : 0
      });
      throw error;
    }
  }

  /**
   * Generate a structured report from findings
   * @param {Array} findings - Array of vulnerability findings
   */
  generateReport(findings) {
    // Group findings by type
    const groupedFindings = findings.reduce((acc, finding) => {
      if (!acc[finding.type]) {
        acc[finding.type] = {
          severity: finding.severity,
          description: finding.description,
          category: finding.category,
          subcategory: finding.subcategory,
          files: [],
          allLineNumbers: {},
          cwe: finding.cwe
        };
      }
      // Add file to files array if not already present
      if (finding.file && !acc[finding.type].files.includes(finding.file)) {
        acc[finding.type].files.push(finding.file);
      }
      // Aggregate line numbers by file
      if (finding.file && finding.lineNumbers) {
        acc[finding.type].allLineNumbers[finding.file] = finding.lineNumbers;
      }
      return acc;
    }, {});

    // Convert to array format
    const processedFindings = Object.entries(groupedFindings).map(([type, data]) => ({
      type,
      severity: data.severity,
      description: data.description,
      category: data.category,
      subcategory: data.subcategory,
      files: data.files,
      allLineNumbers: data.allLineNumbers,
      cwe: data.cwe
    }));

    // Calculate severity stats
    const severityStats = processedFindings.reduce((acc, finding) => {
      const severity = finding.severity || 'LOW';
      const instanceCount = Object.values(finding.allLineNumbers)
        .reduce((sum, lines) => sum + lines.length, 0);

      if (!acc[severity]) {
        acc[severity] = { uniqueCount: 0, instanceCount: 0 };
      }
      acc[severity].uniqueCount++;
      acc[severity].instanceCount += instanceCount;
      return acc;
    }, {
      CRITICAL: { uniqueCount: 0, instanceCount: 0 },
      HIGH: { uniqueCount: 0, instanceCount: 0 },
      MEDIUM: { uniqueCount: 0, instanceCount: 0 },
      LOW: { uniqueCount: 0, instanceCount: 0 }
    });

    return {
      findings: processedFindings,
      summary: {
        totalIssues: processedFindings.length,
        criticalIssues: severityStats.CRITICAL.uniqueCount,
        highIssues: severityStats.HIGH.uniqueCount,
        mediumIssues: severityStats.MEDIUM.uniqueCount,
        lowIssues: severityStats.LOW.uniqueCount,
        criticalInstances: severityStats.CRITICAL.instanceCount,
        highInstances: severityStats.HIGH.instanceCount,
        mediumInstances: severityStats.MEDIUM.instanceCount,
        lowInstances: severityStats.LOW.instanceCount
      }
    };
  }

  /**
   * Generate recommendations based on findings
   * @param {Array} findings - Array of vulnerability findings
   */
  generateRecommendations(findings) {
    const uniqueRecs = new Set();

    findings.forEach(finding => {
      const rec = recommendations[finding.type];
      if (rec) {
        uniqueRecs.add(JSON.stringify({
          type: finding.type,
          recommendation: typeof rec.recommendation === 'string' ? rec.recommendation : 'Review and fix the identified issue',
          references: rec.references || [],
          cwe: rec.cwe || finding.cwe
        }));
      }
    });

    return Array.from(uniqueRecs).map(rec => JSON.parse(rec));
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
    if (!scanner.config.octokit) {
      throw new Error('GitHub token is required');
    }

    // Test token validity
    try {
      await scanner.config.octokit.rest.users.getAuthenticated();
    } catch (error) {
      if (error.status === 401) {
        authManager.clearToken(); // Clear invalid token
        throw new Error('Invalid GitHub token. Please provide a new token.');
      }
      throw error;
    }

    const { files, fromCache } = await scanner.fetchRepositoryFiles(url, scanner.config.octokit);

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
