// scanner.js

import _ from 'lodash';
import { patterns, patternCategories, recommendations } from './patterns';
import { getScannerForFile, PACKAGE_FILE_PATTERNS } from './scanners';
import { repoCache } from './cache';
import { Octokit } from '@octokit/core';
import { authManager } from './githubAuth';
import fetch from 'node-fetch';
import semver from 'semver';
import path from 'path';
function parseGitHubUrl(url) {
  const githubRegex = /github\.com\/([^/]+)\/([^/]+)(?:\/tree\/([^/]+))?\/?(.*)/;
  const match = url.match(githubRegex);
  if (!match) throw new Error('Invalid GitHub URL format');
  const [, owner, repo, branch = 'main', path = ''] = match;
  return { owner, repo, branch, path };
}

class VulnerabilityScanner {
  constructor(config = {}) {
    this.config = {
      enablePackageScanners: true,
      maxRetries: 3,
      retryDelay: 1000,
      octokit: null,
      onProgress: null,
      maxFileSize: 1024 * 1024,
      patternTimeout: 30000,
      totalScanTimeout: 300000,
      excludePatterns: /\.(test|spec)\.js$|\.config\.js$|\.env$/,
      ...config
    };

    this.vulnerabilityPatterns = { ...patterns };

    console.log('Initializing scanner with patterns:', {
      totalPatterns: Object.keys(this.vulnerabilityPatterns).length
    });

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

  async getRateLimitInfo() {
    if (!this.config.octokit) return null;
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

  async fetchRepositoryFiles(url, octokit = null) {
    if (octokit) this.config.octokit = octokit;
    const { owner, repo, branch, path } = parseGitHubUrl(url);

    const cacheKey = `${owner}/${repo}/${branch}/${path}`;
    const cachedData = repoCache.get(cacheKey);
    if (cachedData) {
      if (this.config.onProgress) {
        this.config.onProgress.setTotal(1);
        this.config.onProgress.increment();
        this.config.onProgress.complete();
      }
      return {
        files: cachedData.files,
        rateLimit: cachedData.rateLimit,
        fromCache: true
      };
    }

    try {
      const rateLimitInfo = await this.getRateLimitInfo();
      let fileList = [];

      const fetchContents = async (currentPath = '') => {
        try {
          const response = await this.config.octokit.rest.repos.getContent({
            owner,
            repo,
            ref: branch,
            path: currentPath,
          });

          if (Array.isArray(response.data)) {
            for (const item of response.data) {
              if (item.type === 'file' && !this.config.excludePatterns.test(item.path)) {
                fileList.push({ path: item.path, url: item.download_url });
              } else if (item.type === 'dir') {
                await fetchContents(item.path);
              }
            }
          }
        } catch (error) {
          console.error(`Error fetching contents for path ${currentPath}:`, error);
          throw error;
        }
      };

      await fetchContents(path);

      const filesWithContent = [];
      let totalFiles = fileList.length;
      let processedFiles = 0;

      if (this.config.onProgress) this.config.onProgress.setTotal(totalFiles);

      for (const fileInfo of fileList) {
        try {
          const response = await fetch(fileInfo.url);
          if (!response.ok) {
            console.error(`Failed to fetch ${fileInfo.path}: ${response.status} ${response.statusText}`);
            continue;
          }
          const content = await response.text();
          filesWithContent.push({ path: fileInfo.path, content });
        } catch (error) {
          console.error(`Error fetching content for ${fileInfo.path}:`, error);
        } finally {
          processedFiles++;
          if (this.config.onProgress) this.config.onProgress.increment();
        }
      }

      if (this.config.onProgress) this.config.onProgress.complete();

      const result = { files: filesWithContent, rateLimit: rateLimitInfo, fromCache: false };
      repoCache.set(cacheKey, result);
      return result;
    } catch (error) {
      console.error('Error fetching repository files:', error);
      throw error;
    }
  }

  // Main scanning function for a single file
  async scanFile(fileContent, filePath) {
    console.log(`Scanning file: ${filePath}`);

    if (!fileContent || typeof fileContent !== 'string') {
      console.error('Invalid file content provided to scanner');
      return [];
    }

    if (fileContent.length > this.config.maxFileSize) {
      console.warn(`File ${filePath} exceeds size limit of ${this.config.maxFileSize} bytes`);
      return [];
    }

    const findings = [];

    if (!this.vulnerabilityPatterns || Object.keys(this.vulnerabilityPatterns).length === 0) {
      console.error('No vulnerability patterns loaded');
      return findings;
    }

    console.log(`Active patterns: ${Object.keys(this.vulnerabilityPatterns).length}`);

    try {
      if (this.config.enablePackageScanners) {
        for (const [pattern, type] of Object.entries(PACKAGE_FILE_PATTERNS)) {
          if (filePath.toLowerCase().endsWith(pattern.toLowerCase())) {
            console.log(`Found package file match: ${pattern} -> ${type}`);
            const scanner = getScannerForFile(type);
            if (scanner) {
              const packageFindings = await scanner.scan(filePath, fileContent);
              console.log(`Package scanner found ${packageFindings.length} issues`);
              findings.push(...packageFindings);
            }
            break;
          }
        }
      }

      if (filePath.endsWith('package.json')) {
        try {
          const packageJson = JSON.parse(fileContent);
          const dependencies = packageJson.dependencies || {};
          const devDependencies = packageJson.devDependencies || {};

          const allDeps = { ...dependencies, ...devDependencies };
          const depNames = Object.keys(allDeps);

          for (const dep of depNames) {
            const installedVersion = allDeps[dep].replace(/^[^\d]*/, '');
            const vulnData = await this.fetchVulnerabilityData(dep, installedVersion);
            if (vulnData.isVulnerable) {
              findings.push({
                type: 'vulnerableDependency',
                description: `Dependency "${dep}" has known vulnerabilities`,
                severity: 'HIGH',
                category: patternCategories.DEPENDENCY_MANAGEMENT,
                subcategory: '925',
                cwe: '925',
                file: filePath,
                occurrences: 1,
                lineNumbers: this.findLineNumbers(fileContent, patterns.vulnerableDependency.pattern),
                recommendation: recommendations.vulnerableDependency?.recommendation || 'Update the dependency to a secure version',
                references: recommendations.vulnerableDependency?.references || [],
                cwe: patterns.vulnerableDependency.cwe,
                scannerType: 'dependency'
              });
            }
            if (vulnData.isOutdated) {
              findings.push({
                type: 'outdatedDependency',
                description: `Dependency "${dep}" is outdated`,
                severity: 'MEDIUM',
                category: patternCategories.DEPENDENCY_MANAGEMENT,
                subcategory: '926',
                cwe: '926',
                file: filePath,
                occurrences: 1,
                lineNumbers: this.findLineNumbers(fileContent, patterns.outdatedDependency.pattern),
                recommendation: recommendations.outdatedDependency?.recommendation || 'Update the dependency to the latest version',
                references: recommendations.outdatedDependency?.references || [],
                cwe: patterns.outdatedDependency.cwe,
                scannerType: 'dependency'
              });
            }
          }
        } catch (error) {
          console.error(`Error parsing package.json in ${filePath}:`, error);
        }
      }

      const chunkSize = 100000;
      const totalChunks = Math.ceil(fileContent.length / chunkSize);
      let processedChunks = 0;

      if (this.config.onProgress) this.config.onProgress.setTotal(totalChunks * Object.keys(this.vulnerabilityPatterns).length);

      for (const [vulnType, vulnInfo] of Object.entries(this.vulnerabilityPatterns)) {
        try {
          const regex = new RegExp(vulnInfo.pattern, 'g');
          let matches = [];

          if (fileContent.length > chunkSize) {
            for (let i = 0; i < fileContent.length; i += chunkSize) {
              const chunk = fileContent.slice(i, i + chunkSize);
              const chunkMatches = chunk.match(regex) || [];
              matches.push(...chunkMatches);

              processedChunks++;
              if (this.config.onProgress) this.config.onProgress.increment();
            }
          } else {
            matches = fileContent.match(regex) || [];
            processedChunks++;
            if (this.config.onProgress) this.config.onProgress.increment();
          }

          if (patternCategories.API_SECURITY === vulnInfo.category) {
            if (vulnType === 'jwtInURL' || vulnType === 'tokenInURL') {
              const urlRegex = /https?:\/\/[^/\s]+\?[^#\s]+/g;
              const urls = fileContent.match(urlRegex) || [];
              urls.forEach(url => {
                if (vulnInfo.pattern.test(url)) {
                  matches.push(url);
                }
              });
            }
          }

          if (vulnType === 'insecureMiddleware') {
            const lines = fileContent.split('\n');
            lines.forEach((line, index) => {
              if (vulnInfo.pattern.test(line)) {
                const nextLine = lines[index + 1] || '';
                if (!/authenticate|authorize/i.test(nextLine)) {
                  matches.push(line);
                }
              }
            });
          }

          if (matches.length > 0) {
            console.log(`Found ${matches.length} matches for pattern: ${vulnType}`);
            findings.push({
              ...vulnInfo,
              type: vulnType,
              file: filePath,
              occurrences: matches.length,
              lineNumbers: this.findLineNumbers(fileContent, vulnInfo.pattern),
              recommendation: recommendations[vulnType]?.recommendation || 'Review and fix the identified issue',
              references: recommendations[vulnType]?.references || [],
              cwe: vulnInfo.cwe,
              scannerType: 'pattern'
            });
          }
        } catch (error) {
          console.error(`Error analyzing pattern ${vulnType}:`, error);
        }
      }

      if (this.config.onProgress) this.config.onProgress.complete();

      return findings;
      } catch (error) {
      console.error('Error during file scanning:', error);
      return [];
      }
    }

  async fetchVulnerabilityData(dependency, installedVersion) {
      try {
      const advisoriesResponse = await this.config.octokit.rest.security_advisories.listForRepo({
        owner: 'npm',
        repo: dependency,
        per_page: 100
      });

      const advisories = advisoriesResponse.data;

      const relevantAdvisories = advisories.filter(advisory =>
        advisory.affected.some(affected =>
          affected.package.name.toLowerCase() === dependency.toLowerCase()
        )
      );

      const isVulnerable = relevantAdvisories.length > 0;
      const isOutdated = await this.isDependencyOutdated(dependency, installedVersion);

      return { isVulnerable, isOutdated };
      } catch (error) {
      console.error(`Error fetching vulnerability data for ${dependency}:`, error);
      return { isVulnerable: false, isOutdated: false };
      }
    }

  async isDependencyOutdated(dependency, installedVersion) {
  try {
      const response = await fetch(`https://registry.npmjs.org/${dependency}`);
      if (!response.ok) {
        console.error(`Failed to fetch data for ${dependency} from npm registry.`);
        return false;
      }

      const data = await response.json();
      const latestVersion = data['dist-tags']?.latest;

      if (!latestVersion) {
        console.error(`Latest version not found for ${dependency}.`);
        return false;
      }

      if (semver.valid(installedVersion) && semver.valid(latestVersion)) {
        if (semver.gt(latestVersion, installedVersion)) {
          return true;
        }
      } else {
        console.warn(`Invalid semver for ${dependency}: installed=${installedVersion}, latest=${latestVersion}`);
      }

      return false;
    } catch (error) {
      console.error(`Error checking if dependency ${dependency} is outdated:`, error);
      return false;
      }
    }

  findLineNumbers(content, pattern) {
    const lines = content.split('\n');
    const regex = new RegExp(pattern);
    return lines.reduce((numbers, line, index) => {
      if (regex.test(line)) {
        numbers.push(index + 1);
      }
      return numbers;
    }, []);
  }

  findingsByCategory(findings) {
    const categorized = {};

    findings.forEach(finding => {
      const category = finding.category || 'UNCATEGORIZED';
      const subcategory = finding.subcategory || 'UNKNOWN';

      if (!categorized[category]) categorized[category] = {};
      if (!categorized[category][subcategory]) categorized[category][subcategory] = [];

      categorized[category][subcategory].push(finding);
    });

    return categorized;
  }

  generateReport(findings) {
    const groupedFindings = findings.reduce((acc, finding) => {
      if (!acc[finding.type]) {
        acc[finding.type] = {
          severity: finding.severity,
          description: finding.description,
          category: finding.category,
          subcategory: finding.subcategory,
          allLineNumbers: {},
        };
      }
      if (finding.file && finding.lineNumbers) {
        acc[finding.type].allLineNumbers[finding.file] = finding.lineNumbers;
      }
      return acc;
    }, {});

    const summary = {
      totalIssues: findings.length,
      criticalIssues: findings.filter(f => f.severity === 'CRITICAL').length,
      highIssues: findings.filter(f => f.severity === 'HIGH').length,
      mediumIssues: findings.filter(f => f.severity === 'MEDIUM').length,
      lowIssues: findings.filter(f => f.severity === 'LOW').length
    };

    return {
      summary,
      findings: groupedFindings,
      rateLimit: this.rateLimitInfo
    };
  }
}

export async function scanRepositoryLocally(url) {
  const scanner = new VulnerabilityScanner();
      try {
    const token = authManager.getToken();
    if (!token) throw new Error('GitHub token is required');

    const octokit = new Octokit({ auth: token });

    try {
      await octokit.rest.users.getAuthenticated();
      } catch (error) {
      if (error.status === 401) {
        authManager.clearToken();
        throw new Error('Invalid GitHub token. Please provide a new token.');
      }
    throw error;
  }

    scanner.config.octokit = octokit;

    const { files, rateLimit, fromCache } = await scanner.fetchRepositoryFiles(url, octokit);

    const findings = [];
    const totalFiles = files.length;
    let processedFiles = 0;

    if (scanner.config.onProgress) {
      scanner.config.onProgress.setTotal(totalFiles);
}

    for (const file of files) {
      try {
        const fileFindings = await scanner.scanFile(file.content, file.path);
        findings.push(...fileFindings);
      } catch (error) {
        console.error(`Error scanning file ${file.path}:`, error);
      } finally {
        processedFiles++;
        if (scanner.config.onProgress) scanner.config.onProgress.increment();
      }
    }

    const report = scanner.generateReport(findings);
    report.rateLimit = rateLimit;
    report.fromCache = fromCache;

    return report;
  } catch (error) {
    console.error('Local scan error:', error);
    throw error;
  }
}

export default VulnerabilityScanner;
