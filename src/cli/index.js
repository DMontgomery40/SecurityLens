#!/usr/bin/env node

import { program } from 'commander';
import chalk from 'chalk';
import { readFile, readdir, stat } from 'fs/promises';
import { join, relative } from 'path';
import VulnerabilityScanner from '../lib/scanner.js';

function printReport(report) {
    console.log(chalk.bold('\nVulnerability Scan Report'));
    console.log(chalk.bold('========================'));
    
    // Print rate limit info if available
    if (report.rateLimit) {
        console.log(chalk.cyan('\nGitHub API Rate Limit:'));
        console.log(chalk.cyan(`  Remaining: ${report.rateLimit.remaining}/${report.rateLimit.limit}`));
        const resetTime = new Date(report.rateLimit.reset * 1000).toLocaleTimeString();
        console.log(chalk.cyan(`  Resets at: ${resetTime}`));
    }
    
    if (!report || !report.findings) {
        console.log(chalk.yellow('\nNo findings to report.'));
        return;
    }

    // Calculate summary
    const summary = {
        criticalIssues: 0,
        highIssues: 0,
        mediumIssues: 0,
        lowIssues: 0,
        criticalInstances: 0,
        highInstances: 0,
        mediumInstances: 0,
        lowInstances: 0,
        totalIssues: 0
    };

    // Count issues by severity
    report.findings.forEach(finding => {
        switch (finding.severity) {
            case 'CRITICAL':
                summary.criticalIssues++;
                summary.criticalInstances += finding.instances || 1;
                break;
            case 'HIGH':
                summary.highIssues++;
                summary.highInstances += finding.instances || 1;
                break;
            case 'MEDIUM':
                summary.mediumIssues++;
                summary.mediumInstances += finding.instances || 1;
                break;
            case 'LOW':
                summary.lowIssues++;
                summary.lowInstances += finding.instances || 1;
                break;
        }
        summary.totalIssues++;
    });

    // Add summary to report for front-end compatibility
    report.summary = summary;

    // Print summary
    console.log(chalk.bold('\nSummary:'));
    console.log(chalk.red(`Critical Issues: ${summary.criticalIssues} (${summary.criticalInstances} instances)`));
    console.log(chalk.yellow(`High Issues: ${summary.highIssues} (${summary.highInstances} instances)`));
    console.log(chalk.blue(`Medium Issues: ${summary.mediumIssues} (${summary.mediumInstances} instances)`));
    console.log(chalk.green(`Low Issues: ${summary.lowIssues} (${summary.lowInstances} instances)`));
    console.log(chalk.white(`Total Unique Issues: ${summary.totalIssues}`));

    // Print detailed findings
    if (report.findings.length > 0) {
        console.log(chalk.bold('\nDetailed Findings:'));
        report.findings.forEach(finding => {
            console.log(chalk.bold(`\n${finding.type} (${finding.severity})`));
            console.log(`Description: ${finding.description}`);
            console.log(`File: ${finding.file}`);
            if (finding.lineNumbers) {
                console.log(`Line(s): ${finding.lineNumbers.join(', ')}`);
            }
            if (finding.instances > 1) {
                console.log(`Instances: ${finding.instances}`);
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
                if (fileFindings && fileFindings.length > 0) {
                    process.stdout.write(`\n${chalk.yellow(`Found ${fileFindings.length} issues in ${relPath}`)}\n`);
                    findings.push(...fileFindings);
                }
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
            if (fileFindings && fileFindings.length > 0) {
                findings.push(...fileFindings);
            }
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

program
    .command('scan-repo')
    .description('Scan a GitHub repository for vulnerabilities')
    .argument('<url>', 'GitHub repository URL')
    .option('-t, --token <token>', 'GitHub personal access token')
    .option('-b, --branch <branch>', 'Branch to scan (defaults to main/master)')
    .option('-p, --path <path>', 'Subpath within repository to scan')
    .option('-o, --output <type>', 'Output format (text/json)', 'text')
    .option('--no-cache', 'Disable cache usage')
    .option('--no-package-scanners', 'Disable package-specific scanners')
    .option('--no-patterns', 'Disable general vulnerability patterns')
    .option('-v, --verbose', 'Enable verbose output')
    .action(async (url, options) => {
        try {
            const scanner = new VulnerabilityScanner({
                enableNewPatterns: options.patterns !== false,
                enablePackageScanners: options.packageScanners !== false
            });

            // Load token from environment if not provided
            const token = options.token || process.env.GITHUB_TOKEN;

            console.log(chalk.blue('Starting repository scan...'));
            if (options.verbose) {
                console.log(chalk.gray(`URL: ${url}`));
                console.log(chalk.gray(`Branch: ${options.branch || 'default'}`));
                console.log(chalk.gray(`Path: ${options.path || 'root'}`));
                console.log(chalk.gray(`Cache: ${options.cache ? 'enabled' : 'disabled'}`));
            }

            let repoUrl = url;
            if (options.branch) {
                repoUrl = repoUrl.replace(/\/tree\/[^/]+/, '') + `/tree/${options.branch}`;
            }
            if (options.path) {
                repoUrl = repoUrl.replace(/\/?$/, '/') + options.path.replace(/^\//, '');
            }

            const { files, rateLimit, fromCache } = await scanner.fetchRepositoryFiles(repoUrl, token);
            
            if (options.verbose && fromCache) {
                console.log(chalk.gray('Using cached repository data'));
            }

            let findings = [];
            console.log(chalk.blue(`Processing ${files.length} files...`));
            
            for (let i = 0; i < files.length; i++) {
                const file = files[i];
                if (options.verbose) {
                    process.stdout.write(`\r${chalk.gray(`Scanning file ${i + 1}/${files.length}: ${file.path}`)}`);
                }
                const fileFindings = await scanner.scanFile(file.content, file.path);
                if (fileFindings && fileFindings.length > 0 && options.verbose) {
                    process.stdout.write(`\n${chalk.yellow(`Found ${fileFindings.length} issues in ${file.path}`)}\n`);
                }
                if (fileFindings && fileFindings.length > 0) {
                    findings.push(...fileFindings);
                }
            }
            
            if (options.verbose) {
                process.stdout.write('\n');
            }

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