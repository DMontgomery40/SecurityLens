import _ from 'lodash';
import { patterns, recommendations } from './patterns/index';
import { repoCache } from './cache';
import { Octokit } from '@octokit/core';
import { authManager } from './githubAuth';

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

        // Debug logging
        console.log('Initializing scanner with patterns:', {
            Patterns: !!patterns,
          
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

    async fetchRepositoryFiles(url, octokit = null) {
        if (octokit) {
            this.config.octokit = octokit;
        }

        const githubRegex = /github\.com\/([^/]+)\/([^/]+)(?:\/tree\/([^/]+))?\/?(.*)/;
        const match = url.match(githubRegex);

        if (!match) {
            throw new Error('Invalid GitHub URL format');
        }

        const [, owner, repo, branch = 'main', path = ''] = match;

        // Check cache first
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
            
            async function fetchContents(currentPath = '') {
                try {
                    const response = await this.config.octokit.rest.repos.getContent({
                        owner,
                        repo,
                        ref: branch,
                        path: currentPath,
                    });

                    if (Array.isArray(response.data)) {
                        for (const item of response.data) {
                            if (item.type === 'file') {
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
            }

            await fetchContents(path);

            const filesWithContent = [];
            let totalFiles = fileList.length;
            let processedFiles = 0;

            if (this.config.onProgress) {
                this.config.onProgress.setTotal(totalFiles);
            }

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
                    if (this.config.onProgress) {
                        this.config.onProgress.increment();
                    }
                }
            }

            if (this.config.onProgress) {
                this.config.onProgress.complete();
            }

            const result = { files: filesWithContent, rateLimit: rateLimitInfo, fromCache: false };
            repoCache.set(cacheKey, result);
            return result;
        } catch (error) {
            console.error('Error fetching repository files:', error);
            throw error;
        }
    }

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
            // Pattern scanning with chunking for large files
            const chunkSize = 100000; // 100KB chunks
            const totalChunks = Math.ceil(fileContent.length / chunkSize);
            let processedChunks = 0;

            if (this.config.onProgress) {
                this.config.onProgress.setTotal(totalChunks);
            }

            for (const [vulnType, vulnInfo] of Object.entries(this.vulnerabilityPatterns)) {
                try {
                    const regex = new RegExp(vulnInfo.pattern, 'g');
                    let matches = [];
                    
                    // Process large files in chunks
                    if (fileContent.length > chunkSize) {
                        for (let i = 0; i < fileContent.length; i += chunkSize) {
                            const chunk = fileContent.slice(i, i + chunkSize);
                            const chunkMatches = chunk.match(regex) || [];
                            matches.push(...chunkMatches);
                            
                            // Increment and update progress
                            processedChunks++;
                            if (this.config.onProgress) {
                                this.config.onProgress.increment();
                            }
                        }
                    } else {
                        matches = fileContent.match(regex) || [];
                        // Single chunk for small files
                        processedChunks++;
                        if (this.config.onProgress) {
                            this.config.onProgress.increment();
                        }
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
                            cwe: recommendations[vulnType]?.cwe,
                            scannerType: 'pattern'
                        });
                    }
                } catch (error) {
                    console.error(`Error analyzing pattern ${vulnType}:`, error);
                }
            }

            if (this.config.onProgress) {
                this.config.onProgress.complete();
            }
        } catch (error) {
            if (error.message === 'Pattern matching timeout') {
                console.warn(`Pattern matching timeout for ${filePath} after ${this.config.patternTimeout}ms`);
                return findings;
            }
            console.error(`Error scanning file ${filePath}:`, error);
        }

        return findings;
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
            
            if (!categorized[category]) {
                categorized[category] = {};
            }
            if (!categorized[category][subcategory]) {
                categorized[category][subcategory] = [];
            }
            
            categorized[category][subcategory].push(finding);
        });
        
        return categorized;
    }

    generateReport(findings) {
        // Group findings by type
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
            // Aggregate line numbers by file
            if (finding.file && finding.lineNumbers) {
                acc[finding.type].allLineNumbers[finding.file] = finding.lineNumbers;
            }
            return acc;
        }, {});

        return {
            summary: {
                totalIssues: findings.length,
                criticalIssues: findings.filter(f => f.severity === 'CRITICAL').length,
                highIssues: findings.filter(f => f.severity === 'HIGH').length,
                mediumIssues: findings.filter(f => f.severity === 'MEDIUM').length,
                lowIssues: findings.filter(f => f.severity === 'LOW').length
            },
            findings: groupedFindings,
            recommendedFixes: this.generateRecommendations(findings),
            rateLimit: this.rateLimitInfo
        };
    }

    generateRecommendations(findings) {
        const findingsArray = Array.isArray(findings) ? findings : [];

        return Array.from(new Set(findingsArray.map(finding => {
            const rec = recommendations[finding.type];
            return {
                type: finding.type,
                recommendation: typeof rec === 'string' ? rec :
                              (rec?.recommendation || finding.recommendation || 'Review and fix the identified issue'),
                references: rec?.references || [],
                cwe: rec?.cwe || finding.cwe
            };
        })));
    }
}

export async function scanRepositoryLocally(url) {
    const scanner = new VulnerabilityScanner();
    
    try {
        const token = authManager.getToken();
        if (!token) {
            throw new Error('GitHub token is required');
        }

        const octokit = new Octokit({
            auth: token
        });

        // Test token validity
        try {
            await octokit.rest.users.getAuthenticated();
        } catch (error) {
            if (error.status === 401) {
                authManager.clearToken(); // Clear invalid token
                throw new Error('Invalid GitHub token. Please provide a new token.');
            }
            throw error;
        }

        const { owner, repo, path = '' } = parseGitHubUrl(url);
        
        // Get repository contents
        const { data: contents } = await octokit.repos.getContent({
            owner,
            repo,
            path
        });

        // Process files in chunks to avoid timeout
        const files = Array.isArray(contents) ? contents : [contents];
        const findings = [];
        
        for (const file of files) {
            if (file.type === 'file') {
                const { data: content } = await octokit.repos.getContent({
                    owner,
                    repo,
                    path: file.path,
                    mediaType: { format: 'raw' }
                });
                
                const fileFindings = await scanner.scanFile(content, file.path);
                findings.push(...fileFindings);
            }
        }

        return scanner.generateReport(findings);
    } catch (error) {
        console.error('Local scan error:', error);
        throw error;
    }
}

export default VulnerabilityScanner;
