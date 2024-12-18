import _ from 'lodash';
<<<<<<< HEAD
import { VULNERABILITY_PATTERNS as patterns } from './patterns/index.js';
import { getScannerForFile, PACKAGE_FILE_PATTERNS } from './scanners/index.js';
import { repoCache } from './cache.js';

// Define recommendations based on vulnerability types
const recommendations = {
    bufferOverflow: 'Use safe buffer allocation methods and validate buffer sizes',
    memoryLeak: 'Ensure proper cleanup of timers and event listeners',
    pathTraversal: 'Validate and sanitize all file paths before use',
    unsafeFileOps: 'Use asynchronous file operations and proper error handling',
    eval: 'Avoid using eval() and other dynamic code execution methods',
    commandInjection: 'Use parameterized commands and input validation',
    sqlInjection: 'Use parameterized queries or an ORM',
    xss: 'Use proper content encoding and CSP headers',
    hardcodedSecrets: 'Move secrets to environment variables or secure storage',
    insecureCrypto: 'Use strong cryptographic algorithms and proper key management',
    dynamicRequire: 'Use static imports and proper dependency management',
    unsafeDeserialization: 'Validate and sanitize data before deserialization'
};
=======
import { corePatterns, enhancedPatterns, recommendations } from './patterns';
import { getScannerForFile, PACKAGE_FILE_PATTERNS } from './scanners';
import { repoCache } from './cache';
>>>>>>> 81342ac2800f95e58c70d0204d4e1fd9b4d976ed

class VulnerabilityScanner {
    constructor(config = {}) {
        // Default configuration
        this.config = {
            enableNewPatterns: true,  // Toggle new patterns
            enablePackageScanners: true, // Toggle specialized package scanners
            ...config
        };

<<<<<<< HEAD
        // Use all patterns
        this.vulnerabilityPatterns = patterns;
=======
        // Combine patterns based on configuration
        this.vulnerabilityPatterns = {
            ...corePatterns,
            ...(this.config.enableNewPatterns ? enhancedPatterns : {})
        };
>>>>>>> 81342ac2800f95e58c70d0204d4e1fd9b4d976ed

        // Track rate limit information
        this.rateLimitInfo = null;
    }

    async fetchWithAuth(url, token) {
        const headers = {
            'Accept': 'application/vnd.github.v3+json'
        };

        if (token) {
            headers.Authorization = `token ${token}`;
<<<<<<< HEAD
        }

        const response = await fetch(url, { headers });
        
        // Extract rate limit information from headers
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
            throw new Error(`GitHub API error: ${response.statusText}`);
        }

        return response;
    }

    async fetchRepositoryFiles(url, token = null) {
        const githubRegex = /github\.com\/([^/]+)\/([^/]+)(?:\/tree\/[^/]+)?\/?(.*)/;
        const match = url.match(githubRegex);
        if (!match) {
            throw new Error('Invalid GitHub URL format');
        }

        // Check cache first
        const cachedData = repoCache.get(url, token);
        if (cachedData) {
            return {
                files: cachedData.files,
                rateLimit: this.rateLimitInfo,
                fromCache: true
            };
        }

        const [, owner, repo, path] = match;
        const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${path}`;

        try {
            const response = await this.fetchWithAuth(apiUrl, token);
            const data = await response.json();
            const files = [];

            await this.fetchFiles(files, data, owner, repo, token);
            
            // Cache the results
            repoCache.set(url, token, { files });
            
            return {
                files,
                rateLimit: this.rateLimitInfo,
                fromCache: false
            };
        } catch (error) {
            throw new Error(error.message);
        }
    }

    async fetchFiles(files, items, owner, repo, token) {
        for (const item of items) {
            // Check if we're running low on rate limit
            if (this.rateLimitInfo && this.rateLimitInfo.remaining < 5) {
                const resetDate = new Date(this.rateLimitInfo.reset * 1000);
                console.warn(`Warning: Rate limit running low. Resets at ${resetDate.toLocaleString()}`);
            }

            const supportedExtensions = Object.keys(PACKAGE_FILE_PATTERNS)
                .concat(['.json', '.py', '.css', '.html', '.config', '.conf', '.sh', '.patch', 
                        '.yaml', '.yml', 'Dockerfile', '.ini', '.js', '.jsx', '.ts', '.tsx']);
            
            if (item.type === 'file' && 
                (supportedExtensions.some(ext => item.name.toLowerCase().endsWith(ext.toLowerCase())) ||
                 supportedExtensions.some(ext => item.name.toLowerCase() === ext.toLowerCase()))) {
                try {
                    const response = await this.fetchWithAuth(item.download_url, token);
                    const content = await response.text();
                    files.push({
                        path: item.path,
                        content: content
                    });
                } catch (error) {
                    console.error(`Error fetching ${item.path}:`, error.message);
                }
            } else if (item.type === 'dir') {
                try {
                    const response = await this.fetchWithAuth(item._links.self, token);
                    const data = await response.json();
                    await this.fetchFiles(files, data, owner, repo, token);
                } catch (error) {
                    console.error(`Error fetching directory ${item.path}:`, error.message);
                }
=======
        }

        const response = await fetch(url, { headers });
        
        // Extract rate limit information from headers
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
>>>>>>> 81342ac2800f95e58c70d0204d4e1fd9b4d976ed
            }
            throw new Error(`GitHub API error: ${response.statusText}`);
        }

        return response;
    }

    async scanFile(fileContent, filePath) {
        if (!fileContent || typeof fileContent !== 'string') {
            throw new Error('Invalid file content provided');
        }

        const findings = [];
        
        // Check if we have a specialized scanner for this file type
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

        // Always run the general vulnerability scanner
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

    async fetchRepositoryFiles(url, token = null) {
        const githubRegex = /github\.com\/([^/]+)\/([^/]+)(?:\/tree\/[^/]+)?\/?(.*)/;
        const match = url.match(githubRegex);
        if (!match) {
            throw new Error('Invalid GitHub URL format');
        }

        // Check cache first
        const cachedData = repoCache.get(url, token);
        if (cachedData) {
            return {
                files: cachedData.files,
                rateLimit: this.rateLimitInfo,
                fromCache: true
            };
        }

        const [, owner, repo, path] = match;
        const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${path}`;

        try {
            const response = await this.fetchWithAuth(apiUrl, token);
            const data = await response.json();
            const files = [];

            await this.fetchFiles(files, data, owner, repo, token);
            
            // Cache the results
            repoCache.set(url, token, { files });
            
            return {
                files,
                rateLimit: this.rateLimitInfo,
                fromCache: false
            };
        } catch (error) {
            throw new Error(error.message);
        }
    }

    async fetchFiles(files, items, owner, repo, token) {
        for (const item of items) {
            // Check if we're running low on rate limit
            if (this.rateLimitInfo && this.rateLimitInfo.remaining < 5) {
                const resetDate = new Date(this.rateLimitInfo.reset * 1000);
                console.warn(`Warning: Rate limit running low. Resets at ${resetDate.toLocaleString()}`);
            }

            const supportedExtensions = Object.keys(PACKAGE_FILE_PATTERNS)
                .concat(['.json', '.py', '.css', '.html', '.config', '.conf', '.sh', '.patch', 
                        '.yaml', '.yml', 'Dockerfile', '.ini', '.js', '.jsx', '.ts', '.tsx']);
            
            if (item.type === 'file' && 
                (supportedExtensions.some(ext => item.name.toLowerCase().endsWith(ext.toLowerCase())) ||
                 supportedExtensions.some(ext => item.name.toLowerCase() === ext.toLowerCase()))) {
                try {
                    const response = await this.fetchWithAuth(item.download_url, token);
                    const content = await response.text();
                    files.push({
                        path: item.path,
                        content: content
                    });
                } catch (error) {
                    console.error(`Error fetching ${item.path}:`, error.message);
                }
            } else if (item.type === 'dir') {
                try {
                    const response = await this.fetchWithAuth(item._links.self, token);
                    const data = await response.json();
                    await this.fetchFiles(files, data, owner, repo, token);
                } catch (error) {
                    console.error(`Error fetching directory ${item.path}:`, error.message);
                }
            }
        }
    }

    generateReport(findings) {
        // Separate findings by scanner type
        const generalFindings = findings.filter(f => f.scannerType === 'general');
        const packageFindings = findings.filter(f => f.scannerType === 'package');

        return {
            summary: {
                totalIssues: findings.length,
                generalIssues: generalFindings.length,
                packageIssues: packageFindings.length,
                criticalIssues: findings.filter(f => f.severity === 'CRITICAL').length,
                highIssues: findings.filter(f => f.severity === 'HIGH').length,
                mediumIssues: findings.filter(f => f.severity === 'MEDIUM').length,
                lowIssues: findings.filter(f => f.severity === 'LOW').length
            },
            findings: {
                ..._.groupBy(findings, 'severity'),
                byType: {
                    general: _.groupBy(generalFindings, 'severity'),
                    package: _.groupBy(packageFindings, 'severity')
                }
            },
            recommendedFixes: this.generateRecommendations(findings),
            rateLimit: this.rateLimitInfo
        };
    }

    generateRecommendations(findings) {
        return Array.from(new Set(findings.map(finding => ({
            type: finding.type,
            recommendation: recommendations[finding.type] || finding.recommendation || 'Review and fix the identified issue',
            scannerType: finding.scannerType
        }))));
    }
}

export default VulnerabilityScanner;