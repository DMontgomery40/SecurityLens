import _ from 'lodash';
import { corePatterns, enhancedPatterns, recommendations } from './patterns';
import { getScannerForFile, PACKAGE_FILE_PATTERNS } from './scanners';
import { repoCache } from './cache';

class VulnerabilityScanner {
    constructor(config = {}) {
        this.config = {
            enableNewPatterns: true,
            enablePackageScanners: true,
            maxRetries: 3,
            retryDelay: 1000,
            octokit: null,
            onProgress: null,
            ...config
        };

        this.vulnerabilityPatterns = {
            ...corePatterns,
            ...(this.config.enableNewPatterns ? enhancedPatterns : {})
        };

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
                rateLimit: await this.getRateLimitInfo(),
                fromCache: true
            };
        }

        try {
            const files = await this.fetchDirectoryContent(owner, repo, path, branch);
            
            repoCache.set(cacheKey, { files });
            
            if (this.config.onProgress) {
                this.config.onProgress.complete();
            }
            
            return {
                files,
                rateLimit: await this.getRateLimitInfo(),
                fromCache: false
            };
        } catch (error) {
            if (error.status === 403) {
                throw new Error('Rate limit exceeded or access denied. Please check your token.');
            }
            if (error.status === 404) {
                throw new Error('Repository or path not found. Please check the URL.');
            }
            throw error;
        }
    }

    async fetchDirectoryContent(owner, repo, path, branch, accumulator = []) {
        if (!this.config.octokit) {
            throw new Error('GitHub client not initialized');
        }

        try {
            const response = await this.config.octokit.repos.getContent({
                owner,
                repo,
                path: path || '',
                ref: branch
            });

            const items = Array.isArray(response.data) ? response.data : [response.data];

            // Update total count for progress
            if (this.config.onProgress) {
                const totalFiles = items.filter(item => 
                    item.type === 'file' && 
                    (PACKAGE_FILE_PATTERNS[item.name] || 
                    ['.js', '.jsx', '.ts', '.tsx', '.py', '.yml', '.yaml', '.json']
                        .includes('.' + item.name.split('.').pop()?.toLowerCase()))
                ).length;
                
                this.config.onProgress.setTotal(
                    (this.config.onProgress.total || 0) + totalFiles
                );
            }

            for (const item of items) {
                const rateLimit = await this.getRateLimitInfo();
                if (rateLimit?.remaining < 10) {
                    console.warn(`Warning: Rate limit running low (${rateLimit.remaining} remaining)`);
                }

                if (item.type === 'file') {
                    const ext = item.name.split('.').pop()?.toLowerCase();
                    const isSupported = PACKAGE_FILE_PATTERNS[item.name] || 
                                      ['.js', '.jsx', '.ts', '.tsx', '.py', '.yml', '.yaml', '.json'].includes('.' + ext);

                    if (isSupported) {
                        try {
                            const contentResponse = await this.config.octokit.repos.getContent({
                                owner,
                                repo,
                                path: item.path,
                                ref: branch,
                                mediaType: {
                                    format: 'raw'
                                }
                            });

                            const content = Buffer.from(contentResponse.data, 'base64').toString('utf8');
                            
                            accumulator.push({
                                path: item.path,
                                content: content
                            });

                            // Increment progress
                            if (this.config.onProgress) {
                                this.config.onProgress.increment();
                            }
                        } catch (error) {
                            console.error(`Error fetching content for ${item.path}:`, error.message);
                        }
                    }
                } else if (item.type === 'dir') {
                    await this.fetchDirectoryContent(owner, repo, item.path, branch, accumulator);
                }
            }

            return accumulator;
        } catch (error) {
            throw new Error(`Failed to fetch directory content: ${error.message}`);
        }
    }

    async scanFile(fileContent, filePath) {
        if (!fileContent || typeof fileContent !== 'string') {
            throw new Error('Invalid file content provided');
        }

        const findings = [];
        
        const packageScanner = this.config.enablePackageScanners ? getScannerForFile(filePath) : null;
        
        if (packageScanner) {
            try {
                const packageFindings = await packageScanner.scan(filePath, fileContent);
                findings.push(...packageFindings.map(finding => ({
                    ...finding,
                    scannerType: 'package',
                    file: filePath
                })));
            } catch (error) {
                console.error(`Package scanner error for ${filePath}:`, error);
            }
        }

        for (const [vulnType, vulnInfo] of Object.entries(this.vulnerabilityPatterns)) {
            try {
                const matches = fileContent.match(new RegExp(vulnInfo.pattern, 'g')) || [];
                if (matches.length > 0) {
                    findings.push({
                        type: vulnType,
                        severity: vulnInfo.severity,
                        description: vulnInfo.description,
                        file: filePath,
                        occurrences: matches.length,
                        lineNumbers: this.findLineNumbers(fileContent, vulnInfo.pattern),
                        recommendation: recommendations[vulnType] || 'Review and fix the identified issue',
                        scannerType: 'general'
                    });
                }
            } catch (error) {
                console.error(`Error analyzing pattern ${vulnType}:`, error);
            }
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

    generateReport(findings) {
        const groupedBySeverity = _.groupBy(findings, 'severity');
        
        const findingsWithArrays = {};
        Object.entries(groupedBySeverity).forEach(([severity, items]) => {
            findingsWithArrays[severity] = Array.isArray(items) ? items : [];
        });

        return {
            summary: {
                totalIssues: findings.length,
                criticalIssues: (findingsWithArrays.CRITICAL || []).length,
                highIssues: (findingsWithArrays.HIGH || []).length,
                mediumIssues: (findingsWithArrays.MEDIUM || []).length,
                lowIssues: (findingsWithArrays.LOW || []).length
            },
            findings: findingsWithArrays,
            recommendedFixes: this.generateRecommendations(findings),
            rateLimit: this.rateLimitInfo
        };
    }

    generateRecommendations(findings) {
        const findingsArray = Array.isArray(findings) ? findings : [];
        
        return Array.from(new Set(findingsArray.map(finding => ({
            type: finding.type,
            recommendation: recommendations[finding.type] || finding.recommendation || 'Review and fix the identified issue',
            scannerType: finding.scannerType
        }))));
    }
}

export default VulnerabilityScanner;