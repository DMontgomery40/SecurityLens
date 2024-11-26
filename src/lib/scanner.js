import _ from 'lodash';

class VulnerabilityScanner {
    constructor() {
        this.vulnerabilityPatterns = {
            bufferOverflow: {
                pattern: /Buffer\.allocUnsafe\s*\(/,
                severity: 'HIGH',
                description: 'Use of Buffer.allocUnsafe() can lead to memory leaks and potential information disclosure'
            },
            memoryLeak: {
                pattern: /(setInterval|setTimeout)\s*\([^,]+,\s*\d+\s*\)/,
                severity: 'MEDIUM',
                description: 'Potential memory leak in timer that might not be properly cleared'
            },
            pathTraversal: {
                pattern: /\.\.\//, 
                severity: 'CRITICAL',
                description: 'Potential path traversal vulnerability detected'
            },
            unsafeFileOps: {
                pattern: /fs\.([rw]rite|append)FileSync/,
                severity: 'HIGH',
                description: 'Synchronous file operations can lead to DOS vulnerabilities'
            },
            dynamicImports: {
                pattern: /import\s*\(\s*[^'"`][^)]*\)/,
                severity: 'CRITICAL',
                description: 'Dynamic imports without validation can lead to code execution vulnerabilities'
            },
            unsafeJsonParse: {
                pattern: /JSON\.parse\s*\([^)]+\)\s*(?!catch)/,
                severity: 'MEDIUM',
                description: 'Unhandled JSON.parse can throw on invalid input'
            }
        };
    }

    async scanFile(fileContent, filePath) {
        const findings = [];
        
        // Analyze each pattern
        for (const [vulnType, vulnInfo] of Object.entries(this.vulnerabilityPatterns)) {
            const matches = fileContent.match(new RegExp(vulnInfo.pattern, 'g'));
            if (matches) {
                findings.push({
                    type: vulnType,
                    severity: vulnInfo.severity,
                    description: vulnInfo.description,
                    file: filePath,
                    occurrences: matches.length,
                    lineNumbers: this.findLineNumbers(fileContent, vulnInfo.pattern)
                });
            }
        }

        await this.analyzeMemoryIssues(fileContent, filePath, findings);
        await this.analyzeFileSystemIssues(fileContent, filePath, findings);
        await this.analyzePluginArchitecture(fileContent, filePath, findings);

        return findings;
    }

    findLineNumbers(content, pattern) {
        const lines = content.split('\n');
        const lineNumbers = [];
        
        lines.forEach((line, index) => {
            if (pattern instanceof RegExp && line.match(pattern)) {
                lineNumbers.push(index + 1);
            }
        });
        
        return lineNumbers;
    }

    async analyzeMemoryIssues(content, filePath, findings) {
        const eventListenerPattern = /\.addEventListener\s*\(\s*(['"`][^'"`]+['"`])/g;
        const matches = Array.from(content.matchAll(eventListenerPattern));
        
        for (const match of matches) {
            // Safely escape the match for use in RegExp
            const escapedMatch = _.escapeRegExp(match[1]);
            const removePattern = new RegExp(`\.removeEventListener\s*\(\s*${escapedMatch}`);
            if (!content.match(removePattern)) {
                findings.push({
                    type: 'eventListenerLeak',
                    severity: 'MEDIUM',
                    description: 'Event listener without corresponding removal',
                    file: filePath,
                    lineNumbers: this.findLineNumbers(content, match[0])
                });
            }
        }
    }

    async analyzeFileSystemIssues(content, filePath, findings) {
        const unsafeFileOps = /fs\.([rw]rite|append)File(?!Sync)/g;
        const matches = Array.from(content.matchAll(unsafeFileOps));
        
        for (const match of matches) {
            // Safely escape the match for use in RegExp
            const escapedMatch = _.escapeRegExp(match[0]);
            const errorHandlingPattern = new RegExp(`${escapedMatch}[^;]*\.catch`);
            if (!content.match(errorHandlingPattern)) {
                findings.push({
                    type: 'unhandledFileError',
                    severity: 'HIGH',
                    description: 'File operation without proper error handling',
                    file: filePath,
                    lineNumbers: this.findLineNumbers(content, match[0])
                });
            }
        }
    }

    async analyzePluginArchitecture(content, filePath, findings) {
        const dynamicImportPattern = /import\s*\(\s*[^'"`][^)]*\)/g;
        const matches = Array.from(content.matchAll(dynamicImportPattern));
        
        for (const match of matches) {
            // Use a whitelist approach instead of blacklist
            const allowedImportPattern = /^(?:\.\/)(?:[a-zA-Z0-9-_]+\/)*[a-zA-Z0-9-_]+\.[jt]sx?$/;
            const importPath = match[0].match(/import\s*\(\s*([^)]+)\)/)?.[1];
            
            if (importPath && !allowedImportPattern.test(importPath)) {
                findings.push({
                    type: 'unsafePluginImport',
                    severity: 'CRITICAL',
                    description: 'Dynamic import without proper path validation',
                    file: filePath,
                    lineNumbers: this.findLineNumbers(content, match[0])
                });
            }
        }
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
        const recommendationMap = {
            bufferOverflow: 'Replace Buffer.allocUnsafe() with Buffer.alloc() for safer memory allocation',
            memoryLeak: 'Store timer IDs and clear them in component cleanup',
            pathTraversal: 'Use path.normalize() and validate paths against allowed directories',
            unsafeFileOps: 'Use async file operations with proper error handling',
            dynamicImports: 'Implement strict path validation for dynamic imports',
            unsafeJsonParse: 'Add try/catch blocks around JSON.parse calls'
        };

        const recommendations = new Set();
        findings.forEach(finding => {
            if (recommendationMap[finding.type]) {
                recommendations.add({
                    type: finding.type,
                    recommendation: recommendationMap[finding.type]
                });
            }
        });

        return Array.from(recommendations);
    }
}

export default VulnerabilityScanner;