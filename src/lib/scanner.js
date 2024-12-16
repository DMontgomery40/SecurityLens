import _ from 'lodash';
import { corePatterns, enhancedPatterns, recommendations } from './patterns';

class VulnerabilityScanner {
    constructor(config = {}) {
        // Default configuration
        this.config = {
            enableNewPatterns: true,  // Toggle new patterns
            ...config
        };

        // Combine patterns based on configuration
        this.vulnerabilityPatterns = {
            ...corePatterns,
            ...(this.config.enableNewPatterns ? enhancedPatterns : {})
        };
    }

    async fetchRepositoryFiles(url) {
        const githubRegex = /github\.com\/([^/]+)\/([^/]+)(?:\/tree\/[^/]+)?\/?(.*)/;
        const match = url.match(githubRegex);
        if (!match) {
            throw new Error('Invalid GitHub URL format');
        }

        const [, owner, repo, path] = match;
        const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${path}`;

        try {
            const response = await fetch(apiUrl);
            if (!response.ok) {
                throw new Error('Failed to fetch repository contents');
            }

            const data = await response.json();
            const files = [];

            await this.fetchFiles(files, data, owner, repo);
            return files;
        } catch (error) {
            const message = error.message.includes('rate limit') ?
                'GitHub API rate limit exceeded. Please try again later.' :
                `Failed to fetch repository: ${error.message}`;
            throw new Error(message);
        }
    }

    async fetchFiles(files, items, owner, repo) {
        for (const item of items) {
            if (item.type === 'file' && /\.(json|py|css|html|config|conf|sh|patch|yaml|yml|Dockerfile|ini|js|jsx|ts|tsx)$/.test(item.name)) {
                try {
                    const response = await fetch(item.download_url);
                    if (!response.ok) throw new Error(`Failed to fetch ${item.path}`);
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
                    const response = await fetch(item._links.self);
                    if (!response.ok) throw new Error(`Failed to fetch directory ${item.path}`);
                    const data = await response.json();
                    await this.fetchFiles(files, data, owner, repo);
                } catch (error) {
                    console.error(`Error fetching directory ${item.path}:`, error.message);
                }
            }
        }
    }

    async scanFile(fileContent, filePath) {
        if (!fileContent || typeof fileContent !== 'string') {
            throw new Error('Invalid file content provided');
        }

        const findings = [];
        
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
                        recommendation: recommendations[vulnType] || 'Review and fix the identified issue'
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
        return lines.reduce((numbers, line, index) => {
            if (pattern.test(line)) {
                numbers.push(index + 1);
            }
            return numbers;
        }, []);
    }

    generateReport(findings) {
        return {
            summary: {
                totalIssues: findings.length,
                criticalIssues: findings.filter(f => f.severity === 'CRITICAL').length,
                highIssues: findings.filter(f => f.severity === 'HIGH').length,
                mediumIssues: findings.filter(f => f.severity === 'MEDIUM').length,
                lowIssues: findings.filter(f => f.severity === 'LOW').length
            },
            findings: _.groupBy(findings, 'severity'),
            recommendedFixes: this.generateRecommendations(findings)
        };
    }

    generateRecommendations(findings) {
        return Array.from(new Set(findings.map(finding => ({
            type: finding.type,
            recommendation: recommendations[finding.type] || 'Review and fix the identified issue'
        }))));
    }
}

export default VulnerabilityScanner;
