#!/usr/bin/env node

import { program } from 'commander';
import chalk from 'chalk';
import _ from 'lodash';
import { readFile } from 'fs/promises';
import { join } from 'path';

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
            unsafePluginLoad: {
                pattern: /require\s*\(\s*[^'"`][^)]*\)/,
                severity: 'CRITICAL',
                description: 'Dynamic require() calls can lead to remote code execution'
            },
            unsafeEval: {
                pattern: /eval\s*\(/,
                severity: 'CRITICAL',
                description: 'Use of eval() can lead to code injection vulnerabilities'
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

        // Additional analysis
        await this.analyzeMemoryIssues(fileContent, filePath, findings);
        await this.analyzeFileSystemIssues(fileContent, filePath, findings);
        await this.analyzePluginArchitecture(fileContent, filePath, findings);

        return findings;
    }

    findLineNumbers(content, pattern) {
        const lines = content.split('\n');
        const lineNumbers = [];
        
        lines.forEach((line, index) => {
            if (line.match(pattern)) {
                lineNumbers.push(index + 1);
            }
        });
        
        return lineNumbers;
    }

    async analyzeMemoryIssues(content, filePath, findings) {
        const eventListenerPattern = /\.addEventListener\s*\(\s*(['"`][^'"`]+['"`])/g;
        const matches = Array.from(content.matchAll(eventListenerPattern));
        
        for (const match of matches) {
            const removePattern = new RegExp(`\.removeEventListener\s*\(\s*${match[1]}`);
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
            const errorHandlingPattern = new RegExp(`${match[0]}[^;]*\.catch`);
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
            const sanitizationPattern = new RegExp(`validate|sanitize|check.*${match[0]}`);
            if (!content.match(sanitizationPattern)) {
                findings.push({
                    type: 'unsafePluginImport',
                    severity: 'CRITICAL',
                    description: 'Dynamic import without proper validation',
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
        const recommendations = new Map();
        
        findings.forEach(finding => {
            switch(finding.type) {
                case 'bufferOverflow':
                    recommendations.set(finding.type, 'Replace Buffer.allocUnsafe() with Buffer.alloc()');
                    break;
                case 'memoryLeak':
                    recommendations.set(finding.type, 'Store timer IDs and clear them in component cleanup');
                    break;
                case 'pathTraversal':
                    recommendations.set(finding.type, 'Use path.normalize() and validate paths against allowed directories');
                    break;
                case 'unsafeFileOps':
                    recommendations.set(finding.type, 'Use async file operations with proper error handling');
                    break;
                case 'unsafePluginLoad':
                    recommendations.set(finding.type, 'Implement a whitelist of allowed plugins and validate paths');
                    break;
                case 'unsafeEval':
                    recommendations.set(finding.type, 'Replace eval() with safer alternatives like JSON.parse()');
                    break;
            }
        });
        
        return Array.from(recommendations.entries()).map(([type, recommendation]) => ({
            type,
            recommendation
        }));
    }
}

const printReport = (report) => {
    console.log(chalk.bold('\nVulnerability Scan Report'));
    console.log(chalk.bold('========================'));
    
    // Print summary
    console.log(chalk.bold('\nSummary:'));
    console.log(chalk.red(`Critical Issues: ${report.summary.criticalIssues}`));
    console.log(chalk.yellow(`High Issues: ${report.summary.highIssues}`));
    console.log(chalk.blue(`Medium Issues: ${report.summary.mediumIssues}`));
    console.log(chalk.green(`Low Issues: ${report.summary.lowIssues}`));
    console.log(chalk.white(`Total Issues: ${report.summary.totalIssues}`));

    // Print findings by severity
    Object.entries(report.findings).forEach(([severity, findings]) => {
        console.log(chalk.bold(`\n${severity} Findings:`));
        findings.forEach(finding => {
            console.log(chalk.bold(`\n  ${finding.type}`));
            console.log(`  Description: ${finding.description}`);
            console.log(`  File: ${finding.file}`);
            console.log(`  Line(s): ${finding.lineNumbers.join(', ')}`);
        });
    });

    // Print recommendations
    console.log(chalk.bold('\nRecommendations:'));
    report.recommendedFixes.forEach(fix => {
        console.log(`\n  ${chalk.bold(fix.type)}:`);
        console.log(`  ${fix.recommendation}`);
    });
};

program
    .name('plugin-vulnerability-scanner')
    .description('A security vulnerability scanner for plugin architectures')
    .version('1.0.0');

program
    .command('scan')
    .description('Scan a file or directory for vulnerabilities')
    .argument('<path>', 'Path to file or directory to scan')
    .option('-o, --output <type>', 'Output format (text/json)', 'text')
    .action(async (path, options) => {
        try {
            const scanner = new VulnerabilityScanner();
            const content = await readFile(path, 'utf8');
            const findings = await scanner.scanFile(content, path);
            const report = scanner.generateReport(findings);

            if (options.output === 'json') {
                console.log(JSON.stringify(report, null, 2));
            } else {
                printReport(report);
            }
        } catch (error) {
            console.error(chalk.red('Error scanning file:'), error.message);
            process.exit(1);
        }
    });

program.parse();