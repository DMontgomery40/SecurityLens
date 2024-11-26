#!/usr/bin/env node

import { program } from 'commander';
import chalk from 'chalk';
import { readFile } from 'fs/promises';
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

    Object.entries(report.findings).forEach(([severity, findings]) => {
        console.log(chalk.bold(`\n${severity} Findings:`));
        findings.forEach(finding => {
            console.log(chalk.bold(`\n  ${finding.type}`));
            console.log(`  Description: ${finding.description}`);
            console.log(`  File: ${finding.file}`);
            console.log(`  Line(s): ${finding.lineNumbers.join(', ')}`);
        });
    });

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