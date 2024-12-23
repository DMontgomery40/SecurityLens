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

        this.vulnerabilityPatterns = {};
        
        if (corePatterns && typeof corePatterns === 'object') {
            this.vulnerabilityPatterns = { ...corePatterns };
        }

        if (this.config.enableNewPatterns && enhancedPatterns && typeof enhancedPatterns === 'object') {
            this.vulnerabilityPatterns = {
                ...this.vulnerabilityPatterns,
                ...enhancedPatterns
            };
        }

        Object.entries(this.vulnerabilityPatterns).forEach(([key, pattern]) => {
            if (!pattern.pattern || !pattern.severity || !pattern.description) {
                console.error(`Invalid pattern configuration for ${key}`);
                delete this.vulnerabilityPatterns[key];
            }
        });

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
        if (!fileContent || typeof fileContent !== 'string') {
            console.error('Invalid file content provided to scanner');
            return [];
        }

        const findings = [];
        
        if (!this.vulnerabilityPatterns || Object.keys(this.vulnerabilityPatterns).length === 0) {
            console.error('No vulnerability patterns loaded');
            return findings;
        }

        try {
            if (this.config.enablePackageScanners) {
                for (const [pattern, type] of Object.entries(PACKAGE_FILE_PATTERNS)) {
                    if (filePath.toLowerCase().endsWith(pattern.toLowerCase())) {
                        const scanner = getScannerForFile(type);
                        if (scanner) {
                            const packageFindings = await scanner.scan(filePath, fileContent);
                            findings.push(...packageFindings);
                        }
                        break;
                    }
                }
            }

            for (const [vulnType, vulnInfo] of Object.entries(this.vulnerabilityPatterns)) {
                try {
                    const regex = new RegExp(vulnInfo.pattern, 'g');
                    const matches = fileContent.match(regex);
                    
                    if (matches && matches.length > 0) {
                        findings.push({
                            type: vulnType,
                            severity: vulnInfo.severity,
                            description: vulnInfo.description,
                            file: filePath,
                            occurrences: matches.length,
                            lineNumbers: this.findLineNumbers(fileContent, vulnInfo.pattern),
                            recommendation: recommendations[vulnType] || 'Review and fix the identified issue',
                            scannerType: 'pattern'
                        });
                    }
                } catch (error) {
                    console.error(`Error analyzing pattern ${vulnType}:`, error);
                }
            }
        } catch (error) {
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

export default VulnerabilityScanner;