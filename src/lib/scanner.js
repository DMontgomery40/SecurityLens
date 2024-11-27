import _ from 'lodash';

class VulnerabilityScanner {
    constructor(config = {}) {
        // Default configuration
        this.config = {
            enableNewPatterns: true,  // Toggle new patterns
            ...config
        };

        // Core patterns (existing ones)
        this.corePatterns = {
            evalUsage: {
                pattern: /(?<!\/\/\s*)eval\s*\(/,
                severity: 'CRITICAL',
                description: 'Use of eval() is dangerous and can lead to code injection'
            },
            dynamicImports: {
                pattern: /(?<!\/\/\s*)import\s*\(\s*(?!['\"`][^'\"`]+['\"`])[^)]*\)/,
                severity: 'HIGH',
                description: 'Dynamic imports without validation can lead to code execution vulnerabilities'
            },
            bufferOverflow: {
                pattern: /(?<!\/\/\s*)Buffer\.allocUnsafe\s*\(/,
                severity: 'MEDIUM',
                description: 'Use of Buffer.allocUnsafe() should be replaced with Buffer.alloc()'
            },
            consoleUsage: {
                pattern: /console\.(log|debug|info)\s*\(/,
                severity: 'LOW',
                description: 'Console statements should be removed in production'
            },
            hardcodedSecrets: {
                pattern: /(password|secret|key|token|api[_-]?key)\s*=\s*['\"`][^'\"`]{8,}['\"`]/i,
                severity: 'HIGH',
                description: 'Potential hardcoded secret detected'
            },
            unsafeRegex: {
                pattern: /new RegExp\([^)]+\)/,
                severity: 'MEDIUM',
                description: 'Dynamic RegExp construction could lead to ReDoS attacks'
            },
            unsafeJsonParse: {
                pattern: /JSON\.parse\s*\([^)]+\)(?!\s*\.(catch|then)|\s*catch\s*{)/,
                severity: 'LOW',
                description: 'Unhandled JSON.parse can throw on invalid input'
            },
            debuggerStatement: {
                pattern: /debugger;/,
                severity: 'LOW',
                description: 'Debugger statement should be removed in production'
            }
        };

        // Enhanced patterns (new ones)
        this.enhancedPatterns = {
            sqlInjection: {
                pattern: /(?<!\/\/\s*)(executeQuery|query)\s*\(\s*[`'"]*.*?\$\{.*?\}.*?[`'"]*\s*\)/,
                severity: 'CRITICAL',
                description: 'Potential SQL injection vulnerability detected through template literal usage in queries'
            },
            xss: {
                pattern: /(?<!\/\/\s*)(innerHTML|outerHTML)\s*=|document\.write\(|(?<!\.escape\().*?\$\{.*?\}.*?(?=\`)/,
                severity: 'CRITICAL',
                description: 'Potential XSS vulnerability through unsafe DOM manipulation or unescaped template literals'
            },
            insecurePasswords: {
                pattern: /(crypto\.createHash\(['\"]md5[\'"]\)|crypto\.createHash\(['\"]sha1[\'"]\))/,
                severity: 'HIGH',
                description: 'Use of weak hashing algorithms (MD5/SHA1) for passwords'
            },
            sensitiveDataExposure: {
                pattern: /(?<!\/\/\s*)(console\.(log|debug|info|warn|error)|alert)\s*\([^)]*(?:password|secret|key|token|credentials)[^)]*\)/i,
                severity: 'HIGH',
                description: 'Potential exposure of sensitive data through logging or alerts'
            },
            insecureRandomness: {
                pattern: /Math\.random\(\)/,
                severity: 'MEDIUM',
                description: 'Use of Math.random() for security-sensitive operations. Use crypto.getRandomValues() instead'
            },
            noAuthenticationCheck: {
                pattern: /(?<!\/\/\s*)(?:delete|update|remove|drop)\s*(?:user|account|data|record).*?(?<!check.*?)(?<!verify.*?)(?<!authenticate.*?)(?<!authorize.*?)\(/i,
                severity: 'HIGH',
                description: 'Critical operation without apparent authentication check'
            },
            pathTraversal: {
                pattern: /(?<!\/\/\s*)(fs\.read|fs\.write|fs\.append).*?\+\s*(?:req\.params|req\.query|req\.body)/,
                severity: 'CRITICAL',
                description: 'Potential path traversal vulnerability through unvalidated user input'
            },
            insecureDirectObjectRef: {
                pattern: /(?<!\/\/\s*)(?:findById|getById|selectById).*?(?:req\.params|req\.query|req\.body)/,
                severity: 'HIGH',
                description: 'Potential Insecure Direct Object Reference (IDOR) through unvalidated user input'
            }
        };

        // Combine patterns based on configuration
        this.vulnerabilityPatterns = {
            ...this.corePatterns,
            ...(this.config.enableNewPatterns ? this.enhancedPatterns : {})
        };

        // Extended recommendations
        this.extendedRecommendations = {
            sqlInjection: 'Use parameterized queries or an ORM to prevent SQL injection',
            xss: 'Use dedicated HTML sanitization libraries and avoid direct DOM manipulation with user input',
            insecurePasswords: 'Use strong hashing algorithms like bcrypt, Argon2, or PBKDF2',
            sensitiveDataExposure: 'Remove debug logging of sensitive data and implement proper logging policies',
            insecureRandomness: 'Replace Math.random() with crypto.getRandomValues() for security operations',
            noAuthenticationCheck: 'Implement proper authentication checks before critical operations',
            pathTraversal: 'Implement strict input validation and use path normalization',
            insecureDirectObjectRef: 'Implement proper authorization checks and use indirect references'
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
            throw new Error(`Failed to fetch repository: ${error.message}`);
        }
    }

    async fetchFiles(files, items, owner, repo) {
        for (const item of items) {
            if (item.type === 'file' && /\.(js|jsx|ts|tsx)$/.test(item.name)) {
                const response = await fetch(item.download_url);
                const content = await response.text();
                files.push({
                    path: item.path,
                    content: content
                });
            } else if (item.type === 'dir') {
                const response = await fetch(item._links.self);
                const data = await response.json();
                await this.fetchFiles(files, data, owner, repo);
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
                        lineNumbers: this.findLineNumbers(fileContent, vulnInfo.pattern)
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
        const recommendationMap = {
            ...{
                evalUsage: 'Replace eval() with safer alternatives like JSON.parse() or Function()',
                dynamicImports: 'Implement strict path validation for dynamic imports',
                bufferOverflow: 'Use Buffer.alloc() instead of Buffer.allocUnsafe()',
                consoleUsage: 'Remove console statements or use a logging library',
                hardcodedSecrets: 'Move secrets to environment variables or secure secret management',
                unsafeRegex: 'Use static regular expressions or validate dynamic patterns',
                unsafeJsonParse: 'Add try/catch blocks around JSON.parse calls',
                debuggerStatement: 'Remove debugger statements before deploying to production'
            },
            ...(this.config.enableNewPatterns ? this.extendedRecommendations : {})
        };

        return Array.from(new Set(findings.map(finding => ({
            type: finding.type,
            recommendation: recommendationMap[finding.type] || 'Review and fix the identified issue'
        }))));
    }
}

export default VulnerabilityScanner;