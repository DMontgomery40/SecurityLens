import _ from 'lodash';
import { corePatterns, enhancedPatterns, recommendations } from './patterns';
import { getScannerForFile, PACKAGE_FILE_PATTERNS } from './scanners';
import { repoCache } from './cache';

class VulnerabilityScanner {
    constructor(config = {}) {
        this.config = {
            enableNewPatterns: true,
            enablePackageScanners: true,
            ...config
        };

        this.vulnerabilityPatterns = {
            ...corePatterns,
            ...(this.config.enableNewPatterns ? enhancedPatterns : {})
        };

        this.rateLimitInfo = null;
    }

    async fetchWithAuth(url, token) {
        const headers = {
            'Accept': 'application/vnd.github.v3+json',
            'X-GitHub-Api-Version': '2022-11-28'
        };

        if (token) {
            headers.Authorization = `Bearer ${token}`;
        }

        try {
            const response = await fetch(url, { 
                headers,
                mode: 'cors'
            });

            this.rateLimitInfo = {
                limit: parseInt(response.headers.get('x-ratelimit-limit') || '60'),
                remaining: parseInt(response.headers.get('x-ratelimit-remaining') || '0'),
                reset: parseInt(response.headers.get('x-ratelimit-reset') || '0')
            };

            if (!response.ok) {
                if (response.status === 403 && this.rateLimitInfo.remaining === 0) {
                    const resetDate = new Date(this.rateLimitInfo.reset * 1000);
                    throw new Error(`GitHub API rate limit exceeded. Resets at ${resetDate.toLocaleString()}`);
                }
                if (response.status === 404) {
                    throw new Error('Repository or file not found. Check the URL and ensure you have access.');
                }
                if (response.status === 401) {
                    throw new Error('Authentication failed. Please check your GitHub token.');
                }
                throw new Error(`GitHub API error: ${response.statusText}`);
            }

            return response;
        } catch (error) {
            if (error.name === 'TypeError') {
                throw new Error('Network error occurred. Please check your connection and try again.');
            }
            throw error;
        }
    }

    async fetchRepositoryFiles(url, token = null) {
        const githubRegex = /github\.com\/([^/]+)\/([^/]+)(?:\/tree\/[^/]+)?\/?(.*)/;
        const match = url.match(githubRegex);
        
        if (!match) {
            throw new Error('Invalid GitHub URL format');
        }

        const cachedData = repoCache.get(url, token);
        if (cachedData) {
            return {
                files: cachedData.files,
                rateLimit: this.rateLimitInfo,
                fromCache: true
            };
        }

        const [, owner, repo, path] = match;
        const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${path}`.replace(/\/+$/, '');

        try {
            const response = await this.fetchWithAuth(apiUrl, token);
            const data = await response.json();
            const files = [];

            await this.fetchFiles(files, data, owner, repo, token);
            
            repoCache.set(url, token, { files });
            
            return {
                files,
                rateLimit: this.rateLimitInfo,
                fromCache: false
            };
        } catch (error) {
            throw error;
        }
    }

    async fetchFiles(files, items, owner, repo, token) {
        // Ensure items is always an array
        const itemsArray = Array.isArray(items) ? items : [items];
        
        for (const item of itemsArray) {
            if (this.rateLimitInfo && this.rateLimitInfo.remaining < 5) {
                const resetDate = new Date(this.rateLimitInfo.reset * 1000);
                console.warn(`Warning: Rate limit running low. Resets at ${resetDate.toLocaleString()}`);
            }

            const supportedExtensions = Object.keys(PACKAGE_FILE_PATTERNS)
                .concat(['.json', '.py', '.css', '.html', '.config', '.conf', '.sh', '.patch', 
                        '.yaml', '.yml', 'Dockerfile', '.ini', '.js', '.jsx', '.ts', '.tsx']);
            
            try {
                if (item.type === 'file') {
                    const isSupported = supportedExtensions.some(ext => 
                        item.name.toLowerCase().endsWith(ext.toLowerCase()) ||
                        item.name.toLowerCase() === ext.toLowerCase()
                    );

                    if (isSupported) {
                        // Get raw content using base64 content from API
                        if (item.content) {
                            const content = atob(item.content.replace(/\\n/g, ''));
                            files.push({
                                path: item.path,
                                content: content
                            });
                        } else {
                            // Fallback to raw URL if content not included
                            const contentUrl = item.download_url;
                            const response = await this.fetchWithAuth(contentUrl, token);
                            const content = await response.text();
                            files.push({
                                path: item.path,
                                content: content
                            });
                        }
                    }
                } else if (item.type === 'dir') {
                    const dirUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${item.path}`;
                    const response = await this.fetchWithAuth(dirUrl, token);
                    const data = await response.json();
                    await this.fetchFiles(files, data, owner, repo, token);
                }
            } catch (error) {
                console.error(`Error processing ${item.path || 'unknown file'}:`, error.message);
            }
        }
    }

    generateReport(findings) {
        const groupedBySeverity = _.groupBy(findings, 'severity');
        
        // Convert findings object to arrays inside severity groups
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

    generateRecommendations(findings) {
        // Make sure findings is an array
        const findingsArray = Array.isArray(findings) ? findings : [];
        
        return Array.from(new Set(findingsArray.map(finding => ({
            type: finding.type,
            recommendation: recommendations[finding.type] || finding.recommendation || 'Review and fix the identified issue',
            scannerType: finding.scannerType
        }))));
    }
}

export default VulnerabilityScanner;