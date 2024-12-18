#!/usr/bin/env node

import { program } from 'commander';
import chalk from 'chalk';
import { readFile, readdir, stat } from 'fs/promises';
import { join, relative } from 'path';
import VulnerabilityScanner from '../lib/scanner.js';

const printReport = (report) => {
    console.log(chalk.bold('\nVulnerability Scan Report'));
    console.log(chalk.bold('========================'));
    
    console.log(chalk.bold('\nSummary:'));
    console.log(chalk.red(`Critical Issues: ${report.summary.criticalIssues}`));
    console.log(chalk.yellow(`High Issues: ${report.summary.highIssues}`));
    console.log(chalk.blue(`Medium Issues: ${report.summary.mediumIssues}`));
    console.log(chalk.green(`Low Issues: ${report.summary.lowIssues}`));
    console.log(chalk.white(`Total Issues: ${report.summary.totalIssues}`));

    if (report.findings.byType) {
        // Print findings by scanner type
        Object.entries(report.findings.byType).forEach(([scannerType, severityFindings]) => {
            console.log(chalk.bold(`\n${scannerType.toUpperCase()} Scanner Findings:`));
            Object.entries(severityFindings).forEach(([severity, findings]) => {
                if (findings.length > 0) {
                    console.log(chalk.bold(`\n  ${severity} Severity:`));
                    findings.forEach(finding => {
                        console.log(chalk.bold(`\n    ${finding.type}`));
                        console.log(`    Description: ${finding.description}`);
                        console.log(`    File: ${finding.file}`);
                        if (finding.lineNumbers) {
                            console.log(`    Line(s): ${finding.lineNumbers.join(', ')}`);
                        }
                        if (finding.package) {
                            console.log(`    Package: ${finding.package}`);
                            console.log(`    Version: ${finding.version || 'unknown'}`);
                        }
                    });
                }
            });
        });
    } else {
        // Legacy report format
        Object.entries(report.findings).forEach(([severity, findings]) => {
            if (findings.length > 0) {
                console.log(chalk.bold(`\n${severity} Findings:`));
                findings.forEach(finding => {
                    console.log(chalk.bold(`\n  ${finding.type}`));
                    console.log(`  Description: ${finding.description}`);
                    console.log(`  File: ${finding.file}`);
                    if (finding.lineNumbers) {
                        console.log(`  Line(s): ${finding.lineNumbers.join(', ')}`);
                    }
                });
            }
        });
    }

    console.log(chalk.bold('\nRecommendations:'));
    report.recommendedFixes.forEach(fix => {
        console.log(`\n  ${chalk.bold(fix.type)}:`);
        console.log(`  ${fix.recommendation}`);
    });
};

async function* walkDirectory(dir) {
    const files = await readdir(dir);
    for (const file of files) {
        const path = join(dir, file);
        const stats = await stat(path);
        if (stats.isDirectory() && !path.includes('node_modules') && !path.includes('.git')) {
            yield* walkDirectory(path);
        } else {
            // Only yield files with supported extensions
            if (/\.(js|jsx|ts|tsx|py|json|yml|yaml|xml|config|ini)$/i.test(file)) {
                yield path;
            }
        }
    }
}

async function scanPath(path, scanner) {
    const stats = await stat(path);
    const findings = [];

    if (stats.isDirectory()) {
        console.log(chalk.blue(`Scanning directory: ${path}`));
        let fileCount = 0;
        for await (const file of walkDirectory(path)) {
            try {
                const content = await readFile(file, 'utf8');
                const relPath = relative(process.cwd(), file);
                fileCount++;
                process.stdout.write(`\r${chalk.gray(`Scanning files... (${fileCount} processed)`)}`);
                const fileFindings = await scanner.scanFile(content, relPath);
                if (fileFindings.length > 0) {
                    process.stdout.write(`\n${chalk.yellow(`Found ${fileFindings.length} issues in ${relPath}`)}\n`);
                }
                findings.push(...fileFindings);
            } catch (error) {
                console.error(chalk.yellow(`\nWarning: Failed to scan ${file}: ${error.message}`));
            }
        }
        process.stdout.write('\n');
        console.log(chalk.green(`Completed scanning ${fileCount} files`));
    } else {
        try {
            const content = await readFile(path, 'utf8');
            const fileFindings = await scanner.scanFile(content, path);
            findings.push(...fileFindings);
        } catch (error) {
            throw new Error(`Failed to scan ${path}: ${error.message}`);
        }
    }

    return findings;
}

program
    .name('plugin-vulnerability-scanner')
    .description('A security vulnerability scanner for plugin architectures')
    .version('1.0.0');

program
    .command('scan')
    .description('Scan a file or directory for vulnerabilities')
    .argument('<path>', 'Path to file or directory to scan')
    .option('-o, --output <type>', 'Output format (text/json)', 'text')
    .option('--no-package-scanners', 'Disable package-specific scanners')
    .option('--no-patterns', 'Disable general vulnerability patterns')
    .option('--exclude <pattern>', 'Exclude files matching pattern (can be used multiple times)', [])
    .action(async (path, options) => {
        try {
            const scanner = new VulnerabilityScanner({
                enableNewPatterns: options.patterns !== false,
                enablePackageScanners: options.packageScanners !== false
            });

            console.log(chalk.blue('Starting vulnerability scan...'));
            const findings = await scanPath(path, scanner);
            const report = scanner.generateReport(findings);

            if (options.output === 'json') {
                console.log(JSON.stringify(report, null, 2));
            } else {
                printReport(report);
            }

            // Exit with error code if critical or high vulnerabilities found
            if (report.summary.criticalIssues > 0 || report.summary.highIssues > 0) {
                process.exit(1);
            }
        } catch (error) {
            console.error(chalk.red('Error:'), error.message);
            process.exit(1);
        }
    });

program.parse();