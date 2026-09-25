#!/usr/bin/env node
/* eslint-env node */

import { program } from 'commander';
import chalk from 'chalk';
import { readFile, readdir, stat } from 'fs/promises';
import { join, relative } from 'path';
import { RepositoryCrawler } from '../lib/RepositoryCrawler.js';
import { FileScanner } from '../lib/FileScanner.js';
import { ReportBuilder } from '../lib/ReportBuilder.js';
import { getErrorMetadata, normalizeError, SecurityLensError } from '../lib/errors.js';
import { createLogger, createRequestId, withLogContext } from '../lib/logger.js';
import { registerIspCommands } from './ispCommands.js';

const cliLogger = createLogger({
  component: 'cli'
});

function writeLine(text = '') {
  process.stdout.write(`${text}\n`);
}

function ensureSummary(report) {
  if (report?.summary) {
    return report.summary;
  }

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

  (report?.findings || []).forEach((finding) => {
    const instanceCount = Object.values(finding.allLineNumbers || {}).reduce(
      (sum, lines) => sum + lines.length,
      finding.instances || 1
    );

    switch (finding.severity) {
      case 'CRITICAL':
        summary.criticalIssues += 1;
        summary.criticalInstances += instanceCount;
        break;
      case 'HIGH':
        summary.highIssues += 1;
        summary.highInstances += instanceCount;
        break;
      case 'MEDIUM':
        summary.mediumIssues += 1;
        summary.mediumInstances += instanceCount;
        break;
      case 'LOW':
        summary.lowIssues += 1;
        summary.lowInstances += instanceCount;
        break;
      default:
        break;
    }

    summary.totalIssues += 1;
  });

  report.summary = summary;
  return summary;
}

function printReport(report) {
  const summary = ensureSummary(report);

  writeLine(chalk.bold('\nVulnerability Scan Report'));
  writeLine(chalk.bold('========================'));
  
  if (report.rateLimit) {
    writeLine(chalk.cyan('\nGitHub API Rate Limit:'));
    writeLine(chalk.cyan(`  Remaining: ${report.rateLimit.remaining}/${report.rateLimit.limit}`));
    const resetTime = new Date(report.rateLimit.reset * 1000).toLocaleTimeString();
    writeLine(chalk.cyan(`  Resets at: ${resetTime}`));
  }
  
  if (!report || !report.findings) {
    writeLine(chalk.yellow('\nNo findings to report.'));
    return;
  }

  writeLine(chalk.bold('\nSummary:'));
  writeLine(chalk.red(`Critical Issues: ${summary.criticalIssues} (${summary.criticalInstances} instances)`));
  writeLine(chalk.yellow(`High Issues: ${summary.highIssues} (${summary.highInstances} instances)`));
  writeLine(chalk.blue(`Medium Issues: ${summary.mediumIssues} (${summary.mediumInstances} instances)`));
  writeLine(chalk.green(`Low Issues: ${summary.lowIssues} (${summary.lowInstances} instances)`));
  writeLine(chalk.white(`Total Unique Issues: ${summary.totalIssues}`));

  if (report.findings.length > 0) {
    writeLine(chalk.bold('\nDetailed Findings:'));
    report.findings.forEach((finding) => {
      writeLine(chalk.bold(`\n${finding.type} (${finding.severity})`));
      writeLine(`Description: ${finding.description}`);
      
      if (finding.files && finding.files.length > 0) {
        finding.files.forEach((file) => {
          writeLine(`File: ${file}`);
          if (finding.allLineNumbers && finding.allLineNumbers[file]) {
            writeLine(`Line(s): ${finding.allLineNumbers[file].join(', ')}`);
          }
        });
        const totalInstances = Object.values(finding.allLineNumbers || {})
          .reduce((sum, lines) => sum + lines.length, 0);
        if (totalInstances > 1) {
          writeLine(`Total Instances: ${totalInstances}`);
        }
      } else if (finding.file) {
        writeLine(`File: ${finding.file}`);
        if (finding.lineNumbers) {
          writeLine(`Line(s): ${finding.lineNumbers.join(', ')}`);
        }
      }
    });
  }

  writeLine(chalk.bold('\nRecommendations:'));
  (report.recommendedFixes || []).forEach((fix) => {
    writeLine(`\n  ${chalk.bold(fix.type)}:`);
    writeLine(`  ${fix.recommendation}`);
  });
}

async function* walkDirectory(dir) {
  const files = await readdir(dir);
  for (const file of files) {
    const path = join(dir, file);
    const stats = await stat(path);
    if (stats.isDirectory() && !path.includes('node_modules') && !path.includes('.git')) {
      yield* walkDirectory(path);
    } else if (/\.(js|jsx|ts|tsx|py|json|yml|yaml|xml|config|ini)$/i.test(file)) {
      yield path;
    }
  }
}

async function scanPath(targetPath, scanner, logger) {
  const stats = await stat(targetPath);
  const findings = [];

  if (stats.isDirectory()) {
    logger.info(
      {
        targetPath
      },
      'Scanning local directory'
    );

    let fileCount = 0;
    for await (const file of walkDirectory(targetPath)) {
      try {
        const content = await readFile(file, 'utf8');
        const relativePath = relative(process.cwd(), file);
        fileCount += 1;
        process.stdout.write(`\r${chalk.gray(`Scanning files... (${fileCount} processed)`)}`);
        const fileFindings = await scanner.scanFile(content, relativePath);
        if (fileFindings.length > 0) {
          process.stdout.write(`\n${chalk.yellow(`Found ${fileFindings.length} issues in ${relativePath}`)}\n`);
          findings.push(...fileFindings);
        }
      } catch (error) {
        logger.warn(
          getErrorMetadata(
            normalizeError(error, {
              code: 'CLI_FILE_SCAN_FAILED',
              status: 500,
              message: `Failed to scan ${file}`,
              details: {
                filePath: file
              },
              expose: false
            })
          ),
          'Continuing after local file scan failure'
        );
        process.stderr.write(`${chalk.yellow(`\nWarning: Failed to scan ${file}: ${error.message}\n`)}`);
      }
    }

    process.stdout.write('\n');
    logger.info(
      {
        targetPath,
        filesScanned: fileCount,
        findings: findings.length
      },
      'Completed local directory scan'
    );
  } else {
    try {
      const content = await readFile(targetPath, 'utf8');
      findings.push(...await scanner.scanFile(content, targetPath));
      logger.info(
        {
          targetPath,
          findings: findings.length
        },
        'Completed local file scan'
      );
    } catch (error) {
      throw normalizeError(error, {
        code: 'CLI_TARGET_SCAN_FAILED',
        status: 500,
        message: `Failed to scan ${targetPath}`,
        details: {
          targetPath
        }
      });
    }
  }

  return findings;
}

function exitCodeForReport(report) {
  const summary = ensureSummary(report);
  return summary.criticalIssues > 0 || summary.highIssues > 0 ? 1 : 0;
}

function reportCommandError(logger, error, fallbackMessage) {
  const normalized = normalizeError(error, {
    code: 'CLI_COMMAND_FAILED',
    status: error?.status || 500,
    message: fallbackMessage,
    userMessage: error?.userMessage || error?.message || fallbackMessage
  });

  logger.error(getErrorMetadata(normalized), fallbackMessage);
  process.stderr.write(`${chalk.red('Error:')} ${normalized.userMessage || normalized.message}\n`);
  if (normalized.requestId) {
    process.stderr.write(`${chalk.gray(`Reference ID: ${normalized.requestId}`)}\n`);
  }

  return 1;
}

program
  .name('plugin-vulnerability-scanner')
  .description('A security vulnerability scanner for plugin architectures')
  .version('1.0.0');

const commonOptions = {
  enableNewPatterns: (options) => options.patterns !== false,
  enablePackageScanners: (options) => options.packageScanners !== false,
  createFileScanner: (options, logger) => new FileScanner({
    enableNewPatterns: commonOptions.enableNewPatterns(options),
    enablePackageScanners: commonOptions.enablePackageScanners(options),
    logger
  }),
  createReportBuilder: () => new ReportBuilder()
};

program
  .command('scan')
  .description('Scan a file or directory for vulnerabilities')
  .argument('<path>', 'Path to file or directory to scan')
  .option('-o, --output <type>', 'Output format (text/json)', 'text')
  .option('--no-package-scanners', 'Disable package-specific scanners')
  .option('--no-patterns', 'Disable general vulnerability patterns')
  .option('--exclude <pattern>', 'Exclude files matching pattern (can be used multiple times)', [])
  .action(async (targetPath, options) => {
    const logger = withLogContext(cliLogger, {
      command: 'scan',
      runId: createRequestId('cli')
    });

    try {
      const fileScanner = commonOptions.createFileScanner(options, logger);
      const reportBuilder = commonOptions.createReportBuilder();

      logger.info(
        {
          targetPath,
          output: options.output
        },
        'Starting CLI vulnerability scan'
      );

      const findings = await scanPath(targetPath, fileScanner, logger);
      const report = reportBuilder.generateReport(findings);
      report.recommendedFixes = reportBuilder.generateRecommendations(findings);

      if (options.output === 'json') {
        writeLine(JSON.stringify(report, null, 2));
      } else {
        printReport(report);
      }

      process.exitCode = exitCodeForReport(report);
    } catch (error) {
      process.exitCode = reportCommandError(logger, error, 'Local scan failed');
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
  .option('-c, --concurrency <n>', 'Number of concurrent GitHub file downloads (default: 10, max: 50)', '10')
  .action(async (url, options) => {
    const logger = withLogContext(cliLogger, {
      command: 'scan-repo',
      runId: createRequestId('cli')
    });

    try {
      const concurrency = Math.min(Math.max(Number.parseInt(options.concurrency, 10) || 10, 1), 50);
      const token = options.token || process.env.GITHUB_TOKEN;

      if (!token) {
        throw new SecurityLensError('GitHub token is required. Pass --token or set GITHUB_TOKEN.', {
          code: 'MISSING_TOKEN',
          status: 401,
          userMessage: 'GitHub token is required. Pass --token or set GITHUB_TOKEN.'
        });
      }

      const repositoryCrawler = new RepositoryCrawler({
        concurrency,
        useCache: options.cache !== false,
        logger
      });
      const fileScanner = commonOptions.createFileScanner(options, logger);
      const reportBuilder = commonOptions.createReportBuilder();
      const parsedUrl = repositoryCrawler.parseGitHubUrl(url);
      const branch = options.branch || parsedUrl.branch;
      const repoPath = options.path || parsedUrl.path;

      logger.info(
        {
          repository: `${parsedUrl.owner}/${parsedUrl.repo}`,
          branch,
          path: repoPath || '/',
          concurrency,
          useCache: options.cache !== false
        },
        'Starting CLI repository scan'
      );

      const { files, fromCache, partial, scanStats, errors } = await repositoryCrawler.getFiles(
        token,
        parsedUrl.owner,
        parsedUrl.repo,
        branch,
        repoPath,
        (progress) => {
          if (
            options.verbose &&
            (progress.current === 0 ||
              progress.current === progress.total ||
              progress.current % 50 === 0)
          ) {
            process.stdout.write(
              `\r${chalk.gray(`${progress.phase} ${progress.current}/${progress.total}`)}`
            );
          }
        }
      );

      if (options.verbose) {
        process.stdout.write('\n');
      }

      const findings = [];
      for (let index = 0; index < files.length; index += 1) {
        const file = files[index];

        try {
          if (options.verbose) {
            process.stdout.write(
              `\r${chalk.gray(`Scanning file ${index + 1}/${files.length}: ${file.path}`)}`
            );
          }

          const fileFindings = await fileScanner.scanFile(file.content, file.path);
          if (fileFindings.length > 0) {
            findings.push(...fileFindings);
            if (options.verbose) {
              process.stdout.write(`\n${chalk.yellow(`Found ${fileFindings.length} issues in ${file.path}`)}\n`);
            }
          }
        } catch (error) {
          logger.warn(
            getErrorMetadata(
              normalizeError(error, {
                code: 'CLI_REPOSITORY_FILE_SCAN_FAILED',
                status: 500,
                message: `Failed to scan ${file.path}`,
                details: {
                  filePath: file.path
                },
                expose: false
              })
            ),
            'Continuing after repository file scan failure'
          );
        }
      }

      if (options.verbose) {
        process.stdout.write('\n');
      }

      const report = reportBuilder.generateReport(findings, {
        rateLimit: repositoryCrawler.rateLimitInfo,
        fromCache
      });
      report.recommendedFixes = reportBuilder.generateRecommendations(findings);
      report.partial = partial || false;
      report.scanStats = scanStats || null;
      report.fetchErrors = errors || [];

      if (options.output === 'json') {
        writeLine(JSON.stringify(report, null, 2));
      } else {
        printReport(report);
      }

      logger.info(
        {
          findings: report.summary.totalIssues,
          filesProcessed: files.length,
          fromCache,
          partial: report.partial
        },
        'CLI repository scan completed'
      );

      process.exitCode = exitCodeForReport(report);
    } catch (error) {
      process.exitCode = reportCommandError(logger, error, 'Repository scan failed');
    }
  });

registerIspCommands(program);

program.parseAsync().catch((error) => {
  process.exitCode = reportCommandError(cliLogger, error, 'CLI execution failed');
});
